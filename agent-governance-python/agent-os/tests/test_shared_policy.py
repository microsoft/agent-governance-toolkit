# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the cross-project shared policy language."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agent_os.policies.shared import (
    Condition,
    SharedPolicyDecision,
    SharedPolicyEvaluator,
    SharedPolicyRule,
    SharedPolicySchema,
    policy_document_to_shared,
    shared_to_policy_document,
)


# ---------------------------------------------------------------------------
# Condition validation
# ---------------------------------------------------------------------------


class TestCondition:
    def test_valid_operator(self):
        c = Condition(field="tool_name", operator="eq", value="search")
        assert c.operator == "eq"

    def test_invalid_operator_raises(self):
        with pytest.raises(ValueError, match="Invalid operator"):
            Condition(field="x", operator="bad_op", value=1)


# ---------------------------------------------------------------------------
# SharedPolicyRule validation
# ---------------------------------------------------------------------------


class TestSharedPolicyRule:
    def test_valid_action(self):
        rule = SharedPolicyRule(id="r1", action="deny")
        assert rule.action == "deny"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            SharedPolicyRule(id="r1", action="explode")


# ---------------------------------------------------------------------------
# SharedPolicySchema
# ---------------------------------------------------------------------------


class TestSharedPolicySchema:
    def test_minimal_schema(self):
        schema = SharedPolicySchema(name="test", scope="agent")
        assert schema.version == "1.0"
        assert schema.rules == []

    def test_invalid_scope_raises(self):
        with pytest.raises(ValueError, match="Invalid scope"):
            SharedPolicySchema(name="bad", scope="universe")

    def test_parsed_rules(self):
        schema = SharedPolicySchema(
            name="p1",
            scope="tool",
            rules=[
                {
                    "id": "r1",
                    "action": "deny",
                    "priority": 10,
                    "conditions": [
                        {"field": "tool_name", "operator": "eq", "value": "exec"},
                    ],
                }
            ],
        )
        parsed = schema.parsed_rules()
        assert len(parsed) == 1
        assert parsed[0].id == "r1"
        assert parsed[0].conditions[0].field == "tool_name"

    def test_yaml_round_trip(self, tmp_path: Path):
        schema = SharedPolicySchema(
            name="round-trip",
            scope="mesh",
            description="test",
            rules=[
                {
                    "id": "r1",
                    "action": "allow",
                    "conditions": [
                        {"field": "trust_score", "operator": "gt", "value": 0.8},
                    ],
                }
            ],
            metadata={"author": "test"},
        )
        yaml_path = tmp_path / "test.yaml"
        schema.to_yaml(yaml_path)

        loaded = SharedPolicySchema.from_yaml(yaml_path)
        assert loaded.name == "round-trip"
        assert loaded.scope == "mesh"
        assert len(loaded.rules) == 1
        assert loaded.metadata["author"] == "test"


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class TestSharedPolicyEvaluator:
    def _make_rules(self) -> list[SharedPolicyRule]:
        return [
            SharedPolicyRule(
                id="deny-high-tokens",
                action="deny",
                priority=10,
                conditions=[Condition(field="token_count", operator="gt", value=4000)],
            ),
            SharedPolicyRule(
                id="allow-search",
                action="allow",
                priority=5,
                conditions=[Condition(field="tool_name", operator="eq", value="search")],
            ),
        ]

    def test_deny_matches(self):
        ev = SharedPolicyEvaluator()
        decision = ev.evaluate({"token_count": 5000}, self._make_rules())
        assert not decision.allowed
        assert decision.action == "deny"
        assert decision.matched_rule_id == "deny-high-tokens"

    def test_allow_matches(self):
        ev = SharedPolicyEvaluator()
        decision = ev.evaluate(
            {"tool_name": "search", "token_count": 100}, self._make_rules()
        )
        assert decision.allowed
        assert decision.matched_rule_id == "allow-search"

    def test_no_match_defaults_allow(self):
        ev = SharedPolicyEvaluator()
        decision = ev.evaluate({"tool_name": "unknown", "token_count": 10}, self._make_rules())
        assert decision.allowed
        assert decision.matched_rule_id is None

    def test_priority_ordering(self):
        """Higher-priority rule wins even if a lower one also matches."""
        rules = [
            SharedPolicyRule(
                id="low",
                action="allow",
                priority=1,
                conditions=[Condition(field="x", operator="eq", value=1)],
            ),
            SharedPolicyRule(
                id="high",
                action="deny",
                priority=100,
                conditions=[Condition(field="x", operator="eq", value=1)],
            ),
        ]
        decision = SharedPolicyEvaluator().evaluate({"x": 1}, rules)
        assert decision.matched_rule_id == "high"
        assert decision.action == "deny"

    def test_multiple_conditions_all_must_match(self):
        rule = SharedPolicyRule(
            id="multi",
            action="deny",
            priority=1,
            conditions=[
                Condition(field="a", operator="eq", value=1),
                Condition(field="b", operator="eq", value=2),
            ],
        )
        ev = SharedPolicyEvaluator()
        assert not ev.evaluate({"a": 1, "b": 999}, [rule]).allowed is False
        assert not ev.evaluate({"a": 1, "b": 2}, [rule]).allowed

    def test_regex_matches(self):
        rule = SharedPolicyRule(
            id="pii",
            action="deny",
            priority=1,
            conditions=[
                Condition(
                    field="content",
                    operator="matches",
                    value=r"\b\d{3}-\d{2}-\d{4}\b",
                )
            ],
        )
        ev = SharedPolicyEvaluator()
        assert not ev.evaluate({"content": "SSN is 123-45-6789"}, [rule]).allowed
        assert ev.evaluate({"content": "no pii here"}, [rule]).allowed

    def test_not_in_operator(self):
        rule = SharedPolicyRule(
            id="not-admin",
            action="deny",
            priority=1,
            conditions=[
                Condition(
                    field="role",
                    operator="not_in",
                    value=["admin", "superuser"],
                )
            ],
        )
        ev = SharedPolicyEvaluator()
        assert not ev.evaluate({"role": "guest"}, [rule]).allowed
        assert ev.evaluate({"role": "admin"}, [rule]).allowed


# ---------------------------------------------------------------------------
# Bridge tests
# ---------------------------------------------------------------------------


class TestBridge:
    def test_shared_to_policy_document(self):
        schema = SharedPolicySchema(
            name="bridge-test",
            scope="agent",
            rules=[
                {
                    "id": "block-exec",
                    "action": "deny",
                    "priority": 50,
                    "conditions": [
                        {"field": "tool_name", "operator": "eq", "value": "exec"},
                    ],
                }
            ],
        )
        doc = shared_to_policy_document(schema)
        assert doc.name == "bridge-test"
        assert len(doc.rules) == 1
        assert doc.rules[0].name == "block-exec"
        assert doc.rules[0].action.value == "deny"

    def test_policy_document_to_shared(self):
        schema = SharedPolicySchema(
            name="roundtrip",
            scope="tool",
            rules=[
                {
                    "id": "r1",
                    "action": "allow",
                    "priority": 10,
                    "conditions": [
                        {"field": "tool_name", "operator": "eq", "value": "search"},
                    ],
                }
            ],
        )
        doc = shared_to_policy_document(schema)
        back = policy_document_to_shared(doc, scope="tool")
        assert back.name == "roundtrip"
        assert back.scope == "tool"
        assert len(back.rules) == 1
        assert back.rules[0]["id"] == "r1"


# ---------------------------------------------------------------------------
# Example YAML loading
# ---------------------------------------------------------------------------


class TestExamplePolicies:
    EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples" / "shared-policies"

    @pytest.mark.parametrize(
        "filename",
        ["no-pii.yaml", "rate-limited-tools.yaml", "trust-handoff.yaml"],
    )
    def test_example_loads(self, filename: str):
        path = self.EXAMPLES_DIR / filename
        if not path.exists():
            pytest.skip(f"{path} not found")
        schema = SharedPolicySchema.from_yaml(path)
        assert schema.name
        assert schema.scope in ("agent", "tool", "flow", "mesh")
        assert len(schema.parsed_rules()) >= 1
