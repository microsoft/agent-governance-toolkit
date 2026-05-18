# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the declarative policy language, evaluator, and bridge."""

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

    def test_not_in_operator_loads_from_yaml(self, tmp_path):
        yaml_path = tmp_path / "not-in-policy.yaml"
        yaml_path.write_text(
            """
version: "1.0"
name: not-in-yaml
rules:
  - name: deny-non-allowlisted-tool
    condition:
      field: tool_name
      operator: not_in
      value: [read_file, search]
    action: deny
""".strip(),
            encoding="utf-8",
        )

        loaded = PolicyDocument.from_yaml(yaml_path)
        assert loaded.rules[0].condition.operator == PolicyOperator.NOT_IN


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
            (PolicyOperator.NOT_IN, "c", ["a", "b"], True),
            (PolicyOperator.NOT_IN, "a", ["a", "b"], False),
            # String target: Python's `in` uses substring semantics, so
            # `"a" not in "admin"` is False because "a" is a substring of
            # "admin".  NOT_IN mirrors IN intentionally — pre-existing behaviour.
            (PolicyOperator.NOT_IN, "a", "admin", False),
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

    def test_not_in_inside_allowlist_does_not_match(self):
        doc = PolicyDocument(
            name="not-in-semantics",
            rules=[
                PolicyRule(
                    name="deny-unapproved-tool",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NOT_IN,
                        value=["read_file", "search"],
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )
        decision = PolicyEvaluator(policies=[doc]).evaluate({"tool_name": "read_file"})
        assert decision.allowed

    def test_not_in_outside_allowlist_matches(self):
        doc = PolicyDocument(
            name="not-in-semantics",
            rules=[
                PolicyRule(
                    name="deny-unapproved-tool",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NOT_IN,
                        value=["read_file", "search"],
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )
        decision = PolicyEvaluator(policies=[doc]).evaluate({"tool_name": "delete_file"})
        assert not decision.allowed
        assert decision.matched_rule == "deny-unapproved-tool"

    def test_not_in_differs_from_ne(self):
        value = "read_file"
        not_in_doc = PolicyDocument(
            name="not-in-vs-ne",
            rules=[
                PolicyRule(
                    name="not-in-rule",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NOT_IN,
                        value=["read_file", "search"],
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )
        ne_doc = PolicyDocument(
            name="not-in-vs-ne",
            rules=[
                PolicyRule(
                    name="ne-rule",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NE,
                        value=["read_file", "search"],
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )

        not_in_decision = PolicyEvaluator(policies=[not_in_doc]).evaluate({"tool_name": value})
        ne_decision = PolicyEvaluator(policies=[ne_doc]).evaluate({"tool_name": value})

        assert not_in_decision.allowed
        assert not ne_decision.allowed

    def test_not_in_missing_field_no_match(self):
        doc = PolicyDocument(
            name="not-in-missing-field",
            rules=[
                PolicyRule(
                    name="deny-unapproved-tool",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NOT_IN,
                        value=["read_file", "search"],
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )
        decision = PolicyEvaluator(policies=[doc]).evaluate({})
        assert decision.allowed

    def test_not_in_malformed_target_fails_closed(self):
        doc = PolicyDocument(
            name="not-in-malformed",
            rules=[
                PolicyRule(
                    name="deny-on-bad-policy",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NOT_IN,
                        value=5,
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )
        decision = PolicyEvaluator(policies=[doc]).evaluate({"tool_name": "read_file"})
        assert not decision.allowed
        assert decision.reason == "Policy evaluation error — access denied (fail closed)"

    def test_not_in_empty_allowlist_matches_everything(self):
        # When value=[] the deny rule fires for *any* present ctx_value:
        # `x not in []` is always True in Python.  This is intentional
        # membership semantics — an empty approved-list approves nothing.
        # The same reasoning applies to `IN, value=[]` which never matches.
        doc = PolicyDocument(
            name="not-in-empty-allowlist",
            rules=[
                PolicyRule(
                    name="deny-all-tools",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.NOT_IN,
                        value=[],
                    ),
                    action=PolicyAction.DENY,
                ),
            ],
        )
        evaluator = PolicyEvaluator(policies=[doc])

        for tool in ("read_file", "search", "delete_file", "anything"):
            decision = evaluator.evaluate({"tool_name": tool})
            assert not decision.allowed, (
                f"Expected deny for tool='{tool}' with empty allowlist, got allowed"
            )
            assert decision.matched_rule == "deny-all-tools"

    def test_not_in_end_to_end_from_yaml(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text(
            """
version: "1.0"
name: end-to-end-not-in
rules:
  - name: deny-unapproved-tool
    condition:
      field: tool_name
      operator: not_in
      value:
        - read_file
        - search
    action: deny
defaults:
  action: allow
""".strip(),
            encoding="utf-8",
        )

        doc = PolicyDocument.from_yaml(path)
        evaluator = PolicyEvaluator(policies=[doc])

        approved = evaluator.evaluate({"tool_name": "search"})
        unapproved = evaluator.evaluate({"tool_name": "delete_file"})

        assert approved.allowed
        assert not unapproved.allowed
        assert unapproved.matched_rule == "deny-unapproved-tool"

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
