# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the declarative policy language, evaluator, and bridge."""

import tempfile
from pathlib import Path

import pytest

from agent_os.integrations.base import GovernancePolicy, PatternType
from agent_os.policies import (
    PolicyAction,
    PolicyCondition,
    PolicyDecision,
    PolicyDefaults,
    PolicyDocument,
    PolicyEvaluator,
    PolicyOperator,
    PolicyRule,
    document_to_governance,
    governance_to_document,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples" / "policies"


def _make_simple_doc() -> PolicyDocument:
    return PolicyDocument(
        version="1.0",
        name="test-policy",
        description="A test policy",
        rules=[
            PolicyRule(
                name="deny_large_tokens",
                condition=PolicyCondition(
                    field="token_count", operator=PolicyOperator.GT, value=1000
                ),
                action=PolicyAction.DENY,
                priority=100,
                message="Too many tokens",
            ),
            PolicyRule(
                name="block_dangerous_tool",
                condition=PolicyCondition(
                    field="tool_name", operator=PolicyOperator.EQ, value="rm_rf"
                ),
                action=PolicyAction.BLOCK,
                priority=90,
                message="Dangerous tool blocked",
            ),
        ],
        defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    )


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


class TestPolicySchema:
    def test_create_policy_document(self):
        doc = _make_simple_doc()
        assert doc.name == "test-policy"
        assert len(doc.rules) == 2
        assert doc.defaults.action == PolicyAction.ALLOW

    def test_rule_priority_default(self):
        rule = PolicyRule(
            name="r",
            condition=PolicyCondition(
                field="x", operator=PolicyOperator.EQ, value=1
            ),
            action=PolicyAction.ALLOW,
        )
        assert rule.priority == 0


# ---------------------------------------------------------------------------
# YAML roundtrip
# ---------------------------------------------------------------------------


class TestYamlRoundtrip:
    def test_roundtrip(self, tmp_path):
        doc = _make_simple_doc()
        yaml_path = tmp_path / "policy.yaml"
        doc.to_yaml(yaml_path)

        loaded = PolicyDocument.from_yaml(yaml_path)
        assert loaded.name == doc.name
        assert loaded.version == doc.version
        assert len(loaded.rules) == len(doc.rules)
        assert loaded.rules[0].name == doc.rules[0].name
        assert loaded.rules[0].condition.operator == doc.rules[0].condition.operator
        assert loaded.defaults.action == doc.defaults.action

    def test_json_roundtrip(self, tmp_path):
        doc = _make_simple_doc()
        json_path = tmp_path / "policy.json"
        doc.to_json(json_path)

        loaded = PolicyDocument.from_json(json_path)
        assert loaded.name == doc.name
        assert len(loaded.rules) == len(doc.rules)


# ---------------------------------------------------------------------------
# Evaluator tests
# ---------------------------------------------------------------------------


class TestEvaluator:
    def test_deny_on_high_tokens(self):
        evaluator = PolicyEvaluator(policies=[_make_simple_doc()])
        decision = evaluator.evaluate({"token_count": 2000})
        assert not decision.allowed
        assert decision.matched_rule == "deny_large_tokens"
        assert decision.action == "deny"

    def test_block_dangerous_tool(self):
        evaluator = PolicyEvaluator(policies=[_make_simple_doc()])
        decision = evaluator.evaluate({"tool_name": "rm_rf"})
        assert not decision.allowed
        assert decision.matched_rule == "block_dangerous_tool"
        assert decision.action == "block"

    def test_allow_when_no_rule_matches(self):
        evaluator = PolicyEvaluator(policies=[_make_simple_doc()])
        decision = evaluator.evaluate({"token_count": 500, "tool_name": "read_file"})
        assert decision.allowed
        assert decision.action == "allow"

    def test_priority_ordering(self):
        """Higher priority rules should match first."""
        doc = PolicyDocument(
            name="priority-test",
            rules=[
                PolicyRule(
                    name="low_priority",
                    condition=PolicyCondition(
                        field="tool_name", operator=PolicyOperator.EQ, value="test"
                    ),
                    action=PolicyAction.ALLOW,
                    priority=1,
                ),
                PolicyRule(
                    name="high_priority",
                    condition=PolicyCondition(
                        field="tool_name", operator=PolicyOperator.EQ, value="test"
                    ),
                    action=PolicyAction.DENY,
                    priority=10,
                ),
            ],
        )
        evaluator = PolicyEvaluator(policies=[doc])
        decision = evaluator.evaluate({"tool_name": "test"})
        assert decision.matched_rule == "high_priority"
        assert decision.action == "deny"

    def test_audit_entry_populated(self):
        evaluator = PolicyEvaluator(policies=[_make_simple_doc()])
        decision = evaluator.evaluate({"token_count": 5000})
        assert "timestamp" in decision.audit_entry
        assert decision.audit_entry["rule"] == "deny_large_tokens"

    def test_operators(self):
        """Verify all comparison operators work correctly."""
        cases = [
            (PolicyOperator.EQ, "x", "x", True),
            (PolicyOperator.EQ, "x", "y", False),
            (PolicyOperator.NE, "x", "y", True),
            (PolicyOperator.GT, 10, 5, True),
            (PolicyOperator.GT, 5, 10, False),
            (PolicyOperator.LT, 5, 10, True),
            (PolicyOperator.GTE, 10, 10, True),
            (PolicyOperator.LTE, 10, 10, True),
            (PolicyOperator.IN, "a", ["a", "b"], True),
            (PolicyOperator.IN, "c", ["a", "b"], False),
            (PolicyOperator.CONTAINS, "hello world", "world", True),
            (PolicyOperator.MATCHES, "abc123", r"\d+", True),
            (PolicyOperator.MATCHES, "abc", r"\d+", False),
        ]
        for op, ctx_val, rule_val, expected in cases:
            doc = PolicyDocument(
                name="op-test",
                rules=[
                    PolicyRule(
                        name="r",
                        condition=PolicyCondition(
                            field="f", operator=op, value=rule_val
                        ),
                        action=PolicyAction.DENY,
                    ),
                ],
            )
            evaluator = PolicyEvaluator(policies=[doc])
            decision = evaluator.evaluate({"f": ctx_val})
            assert (decision.action == "deny") == expected, (
                f"Operator {op} with ctx={ctx_val}, val={rule_val}: "
                f"expected match={expected}, got action={decision.action}"
            )

    def test_missing_field_no_match(self):
        evaluator = PolicyEvaluator(policies=[_make_simple_doc()])
        decision = evaluator.evaluate({})
        assert decision.allowed

    def test_load_policies_from_directory(self, tmp_path):
        doc = _make_simple_doc()
        doc.to_yaml(tmp_path / "p1.yaml")
        doc.to_yaml(tmp_path / "p2.yml")

        evaluator = PolicyEvaluator()
        evaluator.load_policies(tmp_path)
        assert len(evaluator.policies) == 2


# ---------------------------------------------------------------------------
# Bridge tests
# ---------------------------------------------------------------------------


class TestBridge:
    def test_governance_to_document(self):
        gp = GovernancePolicy(
            name="bridge-test",
            max_tokens=2048,
            max_tool_calls=5,
            allowed_tools=["read_file", "write_file"],
            blocked_patterns=["secret", ("api_key.*", PatternType.REGEX)],
            confidence_threshold=0.9,
        )
        doc = governance_to_document(gp)
        assert doc.name == "bridge-test"
        assert any(r.name == "max_tokens" for r in doc.rules)
        assert any(r.name == "allowed_tools" for r in doc.rules)
        assert any(r.name.startswith("blocked_pattern_") for r in doc.rules)

    def test_document_to_governance(self):
        doc = PolicyDocument(
            version="1.0",
            name="roundtrip",
            rules=[
                PolicyRule(
                    name="max_tokens",
                    condition=PolicyCondition(
                        field="token_count", operator=PolicyOperator.GT, value=2048
                    ),
                    action=PolicyAction.DENY,
                    priority=100,
                ),
                PolicyRule(
                    name="max_tool_calls",
                    condition=PolicyCondition(
                        field="tool_call_count", operator=PolicyOperator.GT, value=5
                    ),
                    action=PolicyAction.DENY,
                    priority=99,
                ),
                PolicyRule(
                    name="confidence_threshold",
                    condition=PolicyCondition(
                        field="confidence", operator=PolicyOperator.LT, value=0.9
                    ),
                    action=PolicyAction.DENY,
                    priority=90,
                ),
            ],
            defaults=PolicyDefaults(
                max_tokens=2048,
                max_tool_calls=5,
                confidence_threshold=0.9,
            ),
        )
        gp = document_to_governance(doc)
        assert gp.name == "roundtrip"
        assert gp.max_tokens == 2048
        assert gp.max_tool_calls == 5
        assert gp.confidence_threshold == 0.9

    def test_roundtrip_preserves_values(self):
        original = GovernancePolicy(
            name="rt",
            max_tokens=1024,
            max_tool_calls=3,
            allowed_tools=["search"],
            confidence_threshold=0.7,
        )
        doc = governance_to_document(original)
        restored = document_to_governance(doc)
        assert restored.max_tokens == original.max_tokens
        assert restored.max_tool_calls == original.max_tool_calls
        assert restored.confidence_threshold == original.confidence_threshold
        assert restored.allowed_tools == original.allowed_tools


# ---------------------------------------------------------------------------
# Example policies load and validate
# ---------------------------------------------------------------------------


class TestExamplePolicies:
    @pytest.mark.parametrize("filename", ["default.yaml", "strict.yaml", "development.yaml"])
    def test_example_loads(self, filename):
        path = EXAMPLES_DIR / filename
        if not path.exists():
            pytest.skip(f"{path} not found")
        doc = PolicyDocument.from_yaml(path)
        assert doc.name
        assert doc.version
        assert len(doc.rules) > 0

    @pytest.mark.parametrize("filename", ["default.yaml", "strict.yaml", "development.yaml"])
    def test_example_evaluates(self, filename):
        path = EXAMPLES_DIR / filename
        if not path.exists():
            pytest.skip(f"{path} not found")
        doc = PolicyDocument.from_yaml(path)
        evaluator = PolicyEvaluator(policies=[doc])
        decision = evaluator.evaluate({"token_count": 100, "tool_name": "read_file"})
        assert isinstance(decision, PolicyDecision)
