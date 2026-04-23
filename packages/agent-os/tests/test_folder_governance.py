# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for folder-level governance policy discovery and merge."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from agent_os.policies.discovery import discover_policies, filter_by_scope
from agent_os.policies.evaluator import PolicyDecision, PolicyEvaluator
from agent_os.policies.merge import merge_policies
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


def _write_policy(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(data, f)


def _make_policy(name: str, rules: list[dict], **kwargs) -> dict:
    return {
        "name": name,
        "version": "1.0",
        "rules": rules,
        "defaults": {"action": "allow"},
        **kwargs,
    }


def _make_rule(name: str, tool: str, action: str = "deny", priority: int = 100, **kwargs) -> dict:
    return {
        "name": name,
        "condition": {"field": "tool_name", "operator": "eq", "value": tool},
        "action": action,
        "priority": priority,
        **kwargs,
    }


# =============================================================================
# Discovery tests
# =============================================================================


class TestDiscoverPolicies:
    def test_single_root_policy(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()

        result = discover_policies(action, tmp_path)
        assert len(result) == 1
        assert result[0].name == "governance.yaml"

    def test_nested_policies_root_first(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        _write_policy(tmp_path / "services" / "billing" / "governance.yaml", _make_policy("billing", []))
        action = tmp_path / "services" / "billing" / "agent.py"
        action.touch()

        result = discover_policies(action, tmp_path)
        assert len(result) == 2
        assert "governance.yaml" in str(result[0])
        assert "billing" in str(result[1])

    def test_no_policies_found(self, tmp_path):
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()

        result = discover_policies(action, tmp_path)
        assert result == []

    def test_inherit_false_stops_chain(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        _write_policy(
            tmp_path / "services" / "governance.yaml",
            _make_policy("services", [], inherit=False),
        )
        _write_policy(
            tmp_path / "services" / "billing" / "governance.yaml",
            _make_policy("billing", []),
        )
        action = tmp_path / "services" / "billing" / "agent.py"
        action.touch()

        result = discover_policies(action, tmp_path)
        # Should NOT include root — services has inherit: false
        assert len(result) == 2
        names = [str(p) for p in result]
        assert not any("governance.yaml" == Path(n).name and Path(n).parent == tmp_path for n in names[:1])

    def test_yml_extension(self, tmp_path):
        _write_policy(tmp_path / "governance.yml", _make_policy("root", []))
        action = tmp_path / "agent.py"
        action.touch()

        result = discover_policies(action, tmp_path)
        assert len(result) == 1

    def test_directory_as_action_path(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action_dir = tmp_path / "src"
        action_dir.mkdir()

        result = discover_policies(action_dir, tmp_path)
        assert len(result) == 1


# =============================================================================
# Merge tests
# =============================================================================


class TestMergePolicies:
    def test_single_policy(self):
        doc = PolicyDocument(
            name="root",
            rules=[
                PolicyRule(name="r1", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=100),
            ],
        )
        result = merge_policies([doc])
        assert len(result) == 1
        assert result[0].name == "r1"

    def test_additive_rules(self):
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="r1", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=100),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="r2", condition=PolicyCondition(field="y", operator=PolicyOperator.EQ, value=2), action=PolicyAction.DENY, priority=200),
        ])
        result = merge_policies([root, child])
        assert len(result) == 2
        assert result[0].name == "r2"  # Higher priority first
        assert result[1].name == "r1"

    def test_override_replaces_parent(self):
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="audit-rule", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.AUDIT, priority=50),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="audit-rule", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=50, override=True, message="Stricter in child"),
        ])
        result = merge_policies([root, child])
        assert len(result) == 1
        assert result[0].action == PolicyAction.DENY
        assert result[0].message == "Stricter in child"

    def test_deny_cannot_be_overridden(self):
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="block-shell", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=1000),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="block-shell", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.ALLOW, priority=1000, override=True),
        ])
        result = merge_policies([root, child])
        # Both rules present — parent deny kept, child allow also added
        assert len(result) == 2
        deny_rules = [r for r in result if r.action == PolicyAction.DENY]
        assert len(deny_rules) == 1  # Parent deny preserved

    def test_empty_chain(self):
        assert merge_policies([]) == []


# =============================================================================
# Scope filter tests
# =============================================================================


class TestFilterByScope:
    def test_no_scope_always_matches(self, tmp_path):
        assert filter_by_scope(tmp_path / "governance.yaml", None, tmp_path / "src" / "x.py", tmp_path)

    def test_matching_scope(self, tmp_path):
        action = tmp_path / "services" / "billing" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()
        assert filter_by_scope(tmp_path / "governance.yaml", "services/billing/**", action, tmp_path)

    def test_non_matching_scope(self, tmp_path):
        action = tmp_path / "services" / "docs" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()
        assert not filter_by_scope(tmp_path / "governance.yaml", "services/billing/**", action, tmp_path)


# =============================================================================
# End-to-end evaluator tests
# =============================================================================


class TestFolderScopedEvaluator:
    def test_scoped_evaluation(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", [
            _make_rule("block-shell", "shell_exec", priority=1000),
        ]))
        _write_policy(tmp_path / "services" / "billing" / "governance.yaml", _make_policy("billing", [
            _make_rule("block-pii", "export_pii", priority=900),
        ]))

        action = tmp_path / "services" / "billing" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)

        # Parent deny still works
        result = evaluator.evaluate({"tool_name": "shell_exec", "path": str(action)})
        assert not result.allowed
        assert result.matched_rule == "block-shell"

        # Child rule works
        result = evaluator.evaluate({"tool_name": "export_pii", "path": str(action)})
        assert not result.allowed
        assert result.matched_rule == "block-pii"

        # Allowed tool
        result = evaluator.evaluate({"tool_name": "web_search", "path": str(action)})
        assert result.allowed

    def test_flat_fallback_without_root_dir(self):
        doc = PolicyDocument(name="flat", rules=[
            PolicyRule(name="r1", condition=PolicyCondition(field="tool_name", operator=PolicyOperator.EQ, value="x"), action=PolicyAction.DENY, priority=100),
        ])
        evaluator = PolicyEvaluator(policies=[doc])
        result = evaluator.evaluate({"tool_name": "x"})
        assert not result.allowed

    def test_flat_fallback_without_path_in_context(self, tmp_path):
        doc = PolicyDocument(name="flat", rules=[
            PolicyRule(name="r1", condition=PolicyCondition(field="tool_name", operator=PolicyOperator.EQ, value="x"), action=PolicyAction.DENY, priority=100),
        ])
        evaluator = PolicyEvaluator(policies=[doc], root_dir=tmp_path)
        # No 'path' in context — falls back to flat
        result = evaluator.evaluate({"tool_name": "x"})
        assert not result.allowed
