# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OPA/Rego policy adapter and PolicyEngine integration."""

import pytest
from agentmesh.governance.opa import OPAEvaluator, OPADecision
from agentmesh.governance.policy import PolicyEngine


# ── Sample Rego policies ──────────────────────────────────────

BASIC_REGO = """
package agentmesh

default allow = false

allow {
    input.agent.role == "admin"
}

allow {
    input.agent.role == "analyst"
    input.action == "read"
}
"""

PII_REGO = """
package agentmesh

default allow = false

allow {
    not input.data.contains_pii
}

allow {
    input.data.contains_pii
    input.agent.pii_access
}
"""

DENY_REGO = """
package agentmesh

default allow = true

allow {
    input.action != "delete"
}
"""

MULTI_CONDITION_REGO = """
package governance

default allow = false

allow {
    input.agent.role == "operator"
    input.action == "deploy"
    input.env == "staging"
}
"""


# ── OPAEvaluator: built-in evaluator tests ───────────────────

class TestBuiltinEvaluator:
    """Test the built-in Rego parser (no OPA CLI needed)."""

    def test_admin_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.allowed is True
        assert result.error is None

    def test_analyst_read_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "agent": {"role": "analyst"},
            "action": "read",
        })
        assert result.allowed is True

    def test_analyst_write_denied(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "agent": {"role": "analyst"},
            "action": "write",
        })
        assert result.allowed is False

    def test_unknown_role_denied(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "agent": {"role": "intern"},
        })
        assert result.allowed is False

    def test_pii_access_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=PII_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "data": {"contains_pii": True},
            "agent": {"pii_access": True},
        })
        assert result.allowed is True

    def test_pii_no_access_denied(self):
        evaluator = OPAEvaluator(mode="local", rego_content=PII_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "data": {"contains_pii": True},
            "agent": {"pii_access": False},
        })
        # Without pii_access, the second rule doesn't match,
        # and contains_pii is truthy so first rule doesn't match either
        assert result.allowed is False

    def test_no_pii_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=PII_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "data": {"contains_pii": False},
            "agent": {},
        })
        assert result.allowed is True

    def test_not_equal_condition(self):
        evaluator = OPAEvaluator(mode="local", rego_content=DENY_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"action": "read"})
        assert result.allowed is True

    def test_multi_condition_match(self):
        evaluator = OPAEvaluator(mode="local", rego_content=MULTI_CONDITION_REGO)
        result = evaluator.evaluate("data.governance.allow", {
            "agent": {"role": "operator"},
            "action": "deploy",
            "env": "staging",
        })
        assert result.allowed is True

    def test_multi_condition_partial_miss(self):
        evaluator = OPAEvaluator(mode="local", rego_content=MULTI_CONDITION_REGO)
        result = evaluator.evaluate("data.governance.allow", {
            "agent": {"role": "operator"},
            "action": "deploy",
            "env": "production",  # not staging
        })
        assert result.allowed is False

    def test_evaluation_timing(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.evaluation_ms >= 0
        assert result.evaluation_ms < 100  # should be well under 100ms

    def test_source_is_local(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.source == "local"


# ── OPADecision model ────────────────────────────────────────

class TestOPADecision:
    def test_default_values(self):
        d = OPADecision(allowed=True)
        assert d.allowed is True
        assert d.error is None
        assert d.source == "local"
        assert d.evaluation_ms == 0.0

    def test_error_decision(self):
        d = OPADecision(allowed=False, error="timeout", source="remote")
        assert d.allowed is False
        assert d.error == "timeout"
        assert d.source == "remote"


# ── PolicyEngine + Rego integration ──────────────────────────

class TestPolicyEngineRegoIntegration:
    """Test that load_rego works alongside YAML policies."""

    def test_load_rego_returns_evaluator(self):
        engine = PolicyEngine()
        evaluator = engine.load_rego(rego_content=BASIC_REGO)
        assert isinstance(evaluator, OPAEvaluator)

    def test_rego_allows_admin(self):
        engine = PolicyEngine()
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        decision = engine.evaluate("did:mesh:any", {"agent": {"role": "admin"}})
        assert decision.allowed is True
        assert "OPA/Rego" in decision.reason

    def test_rego_denies_unknown(self):
        engine = PolicyEngine()
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        decision = engine.evaluate("did:mesh:any", {"agent": {"role": "intern"}})
        assert decision.allowed is False

    def test_yaml_takes_precedence_over_rego(self):
        """YAML rules are evaluated first; if they match, Rego is skipped."""
        engine = PolicyEngine()

        # Load a YAML policy that denies everything for agent "did:mesh:blocked"
        yaml_policy = """
version: "1.0"
name: block-policy
agents:
  - "did:mesh:blocked"
rules:
  - name: block-all
    condition: "action.type == 'read'"
    action: deny
"""
        engine.load_yaml(yaml_policy)

        # Load a Rego policy that would allow admin
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")

        # YAML deny should take precedence
        decision = engine.evaluate("did:mesh:blocked", {
            "action": {"type": "read"},
            "agent": {"role": "admin"},
        })
        assert decision.allowed is False
        assert decision.matched_rule == "block-all"

    def test_rego_consulted_when_yaml_no_match(self):
        """If no YAML rule matches, Rego is consulted."""
        engine = PolicyEngine()

        yaml_policy = """
version: "1.0"
name: narrow-policy
agents:
  - "did:mesh:specific"
rules:
  - name: specific-rule
    condition: "action.type == 'deploy'"
    action: deny
"""
        engine.load_yaml(yaml_policy)
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")

        # This agent is not targeted by YAML, so Rego is consulted
        decision = engine.evaluate("did:mesh:other", {"agent": {"role": "admin"}})
        assert decision.allowed is True
        assert "OPA/Rego" in decision.reason

    def test_multiple_rego_evaluators(self):
        engine = PolicyEngine()
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        engine.load_rego(rego_content=MULTI_CONDITION_REGO, package="governance")

        # First evaluator should match admin
        decision = engine.evaluate("did:mesh:any", {"agent": {"role": "admin"}})
        assert decision.allowed is True


# ── Edge cases ────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_rego_content(self):
        evaluator = OPAEvaluator(mode="local", rego_content="")
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False

    def test_no_rego_no_path(self):
        evaluator = OPAEvaluator(mode="local")
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False
        assert result.error is not None

    def test_nonexistent_rego_file(self):
        evaluator = OPAEvaluator(mode="local", rego_path="/nonexistent/policy.rego")
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False

    def test_invalid_query_target(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        # Querying a rule that doesn't exist returns default False
        result = evaluator.evaluate("data.agentmesh.nonexistent", {})
        assert result.allowed is False

    def test_empty_input(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False

    def test_remote_mode_unreachable(self):
        """Remote mode with no server should fail gracefully."""
        evaluator = OPAEvaluator(mode="remote", opa_url="http://localhost:99999")
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.allowed is False
        assert result.error is not None
