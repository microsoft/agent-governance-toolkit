# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the unified AgentMeshClient."""

import pytest

from agentmesh.client import AgentMeshClient, GovernanceResult


# ── Helpers ───────────────────────────────────────────────────

DENY_EXPORT_POLICY = """\
apiVersion: governance.toolkit/v1
name: deny-export
agents:
  - "*"
rules:
  - name: block-export
    condition: "action.type == 'export'"
    action: deny
    description: Data export is not allowed
default_action: allow
"""

ALLOW_ALL_POLICY = """\
apiVersion: governance.toolkit/v1
name: allow-all
agents:
  - "*"
rules: []
default_action: allow
"""


# ── Tests ─────────────────────────────────────────────────────


class TestDefaultClient:
    """A client with no policy YAML should allow every action."""

    def test_allows_action(self):
        client = AgentMeshClient("test-agent")
        result = client.execute_with_governance("read")

        assert isinstance(result, GovernanceResult)
        assert result.allowed is True
        assert result.decision == "allow"

    def test_returns_trust_score(self):
        client = AgentMeshClient("test-agent")
        result = client.execute_with_governance("read")

        # Default score is 500, +10 on success → 510
        assert result.trust_score == 510.0


class TestPolicyEnforcement:
    """A client loaded with a deny rule should block matching actions."""

    def test_blocks_denied_action(self):
        client = AgentMeshClient("test-agent", policy_yaml=DENY_EXPORT_POLICY)
        result = client.execute_with_governance("export")

        assert result.allowed is False
        assert result.decision == "deny"

    def test_allows_non_matching_action(self):
        client = AgentMeshClient(
            "test-agent", policy_yaml=ALLOW_ALL_POLICY
        )
        result = client.execute_with_governance("read")

        assert result.allowed is True

    def test_context_forwarded_to_policy(self):
        client = AgentMeshClient("test-agent", policy_yaml=DENY_EXPORT_POLICY)
        result = client.execute_with_governance(
            "export", context={"action": {"type": "export"}}
        )
        assert result.allowed is False


class TestTrustScoreUpdates:
    """Trust score should increase on allow and decrease on deny."""

    def test_score_increases_on_allow(self):
        client = AgentMeshClient("test-agent")
        initial = client.trust_score.total_score

        client.execute_with_governance("read")

        assert client.trust_score.total_score > initial

    def test_score_decreases_on_deny(self):
        client = AgentMeshClient("test-agent", policy_yaml=DENY_EXPORT_POLICY)
        initial = client.trust_score.total_score

        client.execute_with_governance("export")

        assert client.trust_score.total_score < initial

    def test_custom_trust_config(self):
        config = {"initial_score": 700, "success_delta": 5, "failure_delta": -50}
        client = AgentMeshClient(
            "test-agent", trust_config=config, policy_yaml=DENY_EXPORT_POLICY
        )

        assert client.trust_score.total_score == 700

        client.execute_with_governance("export")  # deny → -50
        assert client.trust_score.total_score == 650


class TestAuditChain:
    """Audit entries should be created and the chain verifiable."""

    def test_audit_entry_created(self):
        client = AgentMeshClient("test-agent")
        result = client.execute_with_governance("read")

        assert result.audit_entry is not None
        assert result.audit_entry.action == "read"
        assert result.audit_entry.agent_did == client.agent_did

    def test_chain_integrity_after_multiple_actions(self):
        client = AgentMeshClient("test-agent")

        for action in ("read", "write", "delete"):
            client.execute_with_governance(action)

        valid, error = client.audit_log.verify_integrity()
        assert valid is True, f"Audit chain integrity failed: {error}"

    def test_audit_entries_queryable_by_agent(self):
        client = AgentMeshClient("test-agent")
        client.execute_with_governance("read")
        client.execute_with_governance("write")

        entries = client.audit_log.get_entries_for_agent(client.agent_did)
        assert len(entries) == 2


class TestClientProperties:
    """Smoke-test that public properties are accessible."""

    def test_identity_has_did(self):
        client = AgentMeshClient("test-agent", capabilities=["read", "write"])
        assert str(client.identity.did).startswith("did:mesh:")

    def test_agent_did_matches_identity(self):
        client = AgentMeshClient("test-agent")
        assert client.agent_did == str(client.identity.did)

    def test_policy_engine_exposed(self):
        client = AgentMeshClient("test-agent", policy_yaml=ALLOW_ALL_POLICY)
        assert "allow-all" in client.policy_engine.list_policies()
