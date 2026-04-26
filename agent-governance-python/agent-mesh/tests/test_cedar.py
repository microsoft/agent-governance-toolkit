# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Cedar policy adapter in AgentMesh governance."""

from __future__ import annotations

import pytest

from agentmesh.governance.cedar import (
    CedarDecision,
    CedarEvaluator,
    _parse_cedar_statements,
    load_cedar_into_engine,
)
from agentmesh.governance.policy import PolicyEngine


class TestCedarEvaluator:
    """Tests for the CedarEvaluator builtin mode."""

    SIMPLE_POLICY = """
permit(
    principal,
    action == Action::"ReadData",
    resource
);

permit(
    principal,
    action == Action::"ListFiles",
    resource
);

forbid(
    principal,
    action == Action::"DeleteFile",
    resource
);
"""

    PERMIT_ALL = """
permit(
    principal,
    action,
    resource
);
"""

    FORBID_ALL = """
forbid(
    principal,
    action,
    resource
);
"""

    def test_permit_matching_action(self):
        evaluator = CedarEvaluator(policy_content=self.SIMPLE_POLICY)
        decision = evaluator.evaluate('Action::"ReadData"', {"agent_did": "did:example:1"})
        assert decision.allowed is True
        assert decision.source == "builtin"
        assert decision.error is None

    def test_forbid_matching_action(self):
        evaluator = CedarEvaluator(policy_content=self.SIMPLE_POLICY)
        decision = evaluator.evaluate('Action::"DeleteFile"', {"agent_did": "did:example:1"})
        assert decision.allowed is False

    def test_default_deny_no_match(self):
        evaluator = CedarEvaluator(policy_content=self.SIMPLE_POLICY)
        decision = evaluator.evaluate('Action::"ExecuteCode"', {"agent_did": "did:example:1"})
        assert decision.allowed is False

    def test_permit_all_catchall(self):
        evaluator = CedarEvaluator(policy_content=self.PERMIT_ALL)
        decision = evaluator.evaluate('Action::"Anything"', {})
        assert decision.allowed is True

    def test_forbid_all_catchall(self):
        evaluator = CedarEvaluator(policy_content=self.FORBID_ALL)
        decision = evaluator.evaluate('Action::"Anything"', {})
        assert decision.allowed is False

    def test_evaluation_ms_tracked(self):
        evaluator = CedarEvaluator(policy_content=self.SIMPLE_POLICY)
        decision = evaluator.evaluate('Action::"ReadData"', {})
        assert decision.evaluation_ms >= 0

    def test_no_content_returns_error(self):
        evaluator = CedarEvaluator()
        decision = evaluator.evaluate('Action::"Test"', {})
        assert decision.allowed is False
        assert decision.error is not None

    def test_action_without_namespace_prefix(self):
        """Action strings without '::' get auto-wrapped."""
        evaluator = CedarEvaluator(policy_content=self.SIMPLE_POLICY)
        decision = evaluator.evaluate("ReadData", {})
        assert decision.allowed is True

    def test_multiple_permits(self):
        evaluator = CedarEvaluator(policy_content=self.SIMPLE_POLICY)
        assert evaluator.evaluate('Action::"ReadData"', {}).allowed is True
        assert evaluator.evaluate('Action::"ListFiles"', {}).allowed is True

    def test_forbid_overrides_permit_for_same_action(self):
        """Cedar semantics: forbid overrides permit when both match."""
        policy = """
permit(principal, action == Action::"Export", resource);
forbid(principal, action == Action::"Export", resource);
"""
        evaluator = CedarEvaluator(policy_content=policy)
        decision = evaluator.evaluate('Action::"Export"', {})
        assert decision.allowed is False

    def test_build_request_normalizes_entities(self):
        evaluator = CedarEvaluator(policy_content=self.PERMIT_ALL)
        request = evaluator._build_request('Action::"Test"', {
            "agent_did": "did:example:agent1",
            "resource": "dataset-A",
        })
        assert '::' in request["principal"]
        assert '::' in request["resource"]
        assert '::' in request["action"]


class TestCedarParseStatements:
    """Tests for the Cedar statement parser."""

    def test_parse_simple_permit(self):
        stmts = _parse_cedar_statements(
            'permit(principal, action == Action::"ReadData", resource);'
        )
        assert len(stmts) == 1
        assert stmts[0]["effect"] == "permit"
        assert stmts[0]["action_constraint"] == 'Action::"ReadData"'

    def test_parse_forbid(self):
        stmts = _parse_cedar_statements(
            'forbid(principal, action == Action::"Delete", resource);'
        )
        assert len(stmts) == 1
        assert stmts[0]["effect"] == "forbid"

    def test_parse_catchall_no_constraint(self):
        stmts = _parse_cedar_statements(
            'permit(principal, action, resource);'
        )
        assert len(stmts) == 1
        assert stmts[0]["action_constraint"] is None

    def test_parse_multiline(self):
        stmts = _parse_cedar_statements("""
permit(
    principal,
    action == Action::"ReadData",
    resource
);
""")
        assert len(stmts) == 1
        assert stmts[0]["effect"] == "permit"

    def test_parse_multiple_statements(self):
        stmts = _parse_cedar_statements("""
permit(principal, action == Action::"Read", resource);
forbid(principal, action == Action::"Write", resource);
permit(principal, action, resource);
""")
        assert len(stmts) == 3


class TestPolicyEngineWithCedar:
    """Tests for AgentMesh PolicyEngine Cedar integration."""

    def test_load_cedar_registers_evaluator(self):
        engine = PolicyEngine()
        evaluator = engine.load_cedar(cedar_content="""
permit(principal, action == Action::"ReadData", resource);
""")
        assert isinstance(evaluator, CedarEvaluator)
        assert len(engine._cedar_evaluators) == 1

    def test_cedar_evaluated_after_yaml(self):
        """Cedar policies are checked when no YAML rule matches."""
        engine = PolicyEngine()
        engine.load_yaml("""
apiVersion: governance.toolkit/v1
name: test-yaml
rules:
  - name: deny-export
    condition: "action.type == 'export'"
    action: deny
    priority: 100
""")
        engine.load_cedar(cedar_content="""
permit(principal, action == Action::"read_data", resource);
""")
        # YAML matches → deny
        decision = engine.evaluate("did:example:1", {"action": {"type": "export"}})
        assert decision.allowed is False

        # YAML doesn't match → falls through to Cedar
        decision = engine.evaluate("did:example:1", {"tool_name": "read_data"})
        assert decision.allowed is True

    def test_cedar_evaluated_after_rego(self):
        """Cedar policies are checked after Rego when Rego has errors."""
        engine = PolicyEngine()
        # Load Cedar (no Rego)
        engine.load_cedar(cedar_content="""
permit(principal, action == Action::"analyze", resource);
""")
        decision = engine.evaluate("did:example:1", {"tool_name": "analyze"})
        assert decision.allowed is True

    def test_multiple_cedar_evaluators(self):
        engine = PolicyEngine()
        engine.load_cedar(cedar_content='forbid(principal, action == Action::"dangerous", resource);')
        engine.load_cedar(cedar_content='permit(principal, action, resource);')

        # First Cedar evaluator forbids
        decision = engine.evaluate("did:example:1", {"tool_name": "dangerous"})
        assert decision.allowed is False

    def test_load_cedar_into_engine_helper(self):
        """Test the standalone helper function."""
        engine = PolicyEngine()
        evaluator = load_cedar_into_engine(engine, "nonexistent.cedar")
        assert isinstance(evaluator, CedarEvaluator)
