"""
tests/test_demo.py — Unit tests for the Agent Governance Toolkit demo.

What is tested:
1. Agent identity creation   — each agent gets a real DID via AgentIdentity.create()
2. Capability registry       — tool grants are recorded in the CapabilityRegistry
3. Policy enforcement        — deny rules block dangerous messages via PolicyEvaluator
4. Capability guard          — denied tools are blocked by CapabilityGuardMiddleware
5. Trust mesh summary        — get_trust_summary() reflects registry state correctly
6. Pipeline relay trust      — successful steps grant pipeline:relay capability
7. Policy revocation on fail — blocked steps revoke all capabilities for that agent
8. Audit log                 — get_audit_trail() returns entries via the public query() API
9. Audit integrity           — the Merkle chain is intact after logging
10. DRY: no private access   — get_audit_trail() must NOT touch ._chain._entries
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

# ---------------------------------------------------------------------------
# Bootstrap sys.path so the demo packages resolve correctly
# ---------------------------------------------------------------------------
_REPO  = Path(__file__).resolve().parent.parent.parent
_DEMO  = _REPO / "demo"
for p in [
    _DEMO,
    _REPO / "packages" / "agent-os"    / "src",
    _REPO / "packages" / "agent-mesh"  / "src",
    _REPO / "packages" / "agent-sre"   / "src",
    _REPO / "packages" / "agent-runtime" / "src",
]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# ---------------------------------------------------------------------------
# Fake LLM: returns a no-tool-call response so tests don't need API keys
# ---------------------------------------------------------------------------
import maf_governance_demo as _demo  # noqa: E402

_FAKE_RESPONSE = _demo._NormalizedResponse(
    choices=[_demo._NormalizedChoice(text="[Simulated agent output]", tool_calls=None)]
)

def _make_fake_client():
    return MagicMock()


def _make_logic(*, fake_llm_call=True):
    """
    Create a GovernanceDemoLogic instance without a real API key.

    We patch:
    - maf_governance_demo._create_client  → returns a MagicMock client
    - maf_governance_demo._llm_call       → returns _FAKE_RESPONSE
    """
    import os
    os.environ.setdefault("OPENAI_API_KEY", "test-key-placeholder")

    # Deferred import to avoid import-time side-effects before sys.path is set
    from logic_adapter import GovernanceDemoLogic, BACKEND_OPENAI

    with patch.object(_demo, "_create_client", return_value=(_make_fake_client(), "openai")):
        logic = GovernanceDemoLogic(api_key="test-key", backend_type=BACKEND_OPENAI)

    if fake_llm_call:
        logic._llm_response_override = _FAKE_RESPONSE

    return logic


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def logic():
    return _make_logic()


# ---------------------------------------------------------------------------
# Test 1: Agent identity — real DIDs are assigned
# ---------------------------------------------------------------------------
class TestAgentIdentity:
    """
    Why: ISSUE.md requires 'agent identity creation and DID assignment'.
    What toolkit class: AgentIdentity.create() → did:mesh:<hash>
    """

    def test_all_pipeline_agents_have_dids(self, logic):
        from logic_adapter import PIPELINE_AGENTS
        for agent_id in PIPELINE_AGENTS:
            did = logic.get_agent_did(agent_id)
            assert did.startswith("did:mesh:"), (
                f"Agent '{agent_id}' does not have a proper DID. Got: {did}"
            )

    def test_research_agent_has_did(self, logic):
        did = logic.get_agent_did("research-agent")
        assert did.startswith("did:mesh:"), "research-agent must have a DID"

    def test_unknown_agent_returns_unknown(self, logic):
        result = logic.get_agent_did("no-such-agent")
        assert result == "unknown"

    def test_dids_are_unique(self, logic):
        from logic_adapter import AGENT_CAPABILITIES
        dids = [logic.get_agent_did(a) for a in AGENT_CAPABILITIES]
        assert len(dids) == len(set(dids)), "Each agent must have a unique DID"


# ---------------------------------------------------------------------------
# Test 2: Capability registry — tool grants are recorded
# ---------------------------------------------------------------------------
class TestCapabilityRegistry:
    """
    Why: We grant 'tool:<name>' for each allowed tool at initialization.
    What toolkit class: CapabilityRegistry — grants are queryable via get_scope()
    """

    def test_collector_agent_tools_granted(self, logic):
        did   = logic.get_agent_did("collector-agent")
        scope = logic.cap_registry.get_scope(did)
        tools = {g.capability for g in scope.grants if g.is_valid()}
        assert "tool:web_search"    in tools
        assert "tool:fetch_dataset" in tools

    def test_transformer_agent_tools_granted(self, logic):
        did   = logic.get_agent_did("transformer-agent")
        scope = logic.cap_registry.get_scope(did)
        tools = {g.capability for g in scope.grants if g.is_valid()}
        assert "tool:run_code"   in tools
        assert "tool:parse_data" in tools

    def test_denied_tools_are_not_granted(self, logic):
        did   = logic.get_agent_did("collector-agent")
        scope = logic.cap_registry.get_scope(did)
        tools = {g.capability for g in scope.grants}
        # shell_exec is in denied_tools, it must never be granted
        assert "tool:shell_exec" not in tools


# ---------------------------------------------------------------------------
# Test 3: IdentityRegistry — agents are registered and trusted
# ---------------------------------------------------------------------------
class TestIdentityRegistry:
    """
    Why: The demo uses IdentityRegistry to back the trust mesh.
    What toolkit class: IdentityRegistry.is_trusted()
    """

    def test_pipeline_agents_registered_as_trusted(self, logic):
        from logic_adapter import PIPELINE_AGENTS
        for agent_id in PIPELINE_AGENTS:
            did     = logic.get_agent_did(agent_id)
            trusted = logic.id_registry.is_trusted(did)
            assert trusted, f"Agent '{agent_id}' (DID={did}) should be trusted in IdentityRegistry"


# ---------------------------------------------------------------------------
# Test 4: Trust mesh summary — reflects registry state
# ---------------------------------------------------------------------------
class TestTrustMeshSummary:
    """
    Why: ISSUE.md requires 'trust scoring between agents'.
    What: get_trust_summary() should return pairs of pipeline agents.
    """

    def test_trust_summary_has_correct_pairs(self, logic):
        summary = logic.get_trust_summary()
        # For 3 agents: C→T, C→V, T→V = 3 pairs
        assert len(summary) == 3

    def test_trust_summary_structure(self, logic):
        summary = logic.get_trust_summary()
        for entry in summary:
            assert "from_agent"    in entry
            assert "to_agent"      in entry
            assert "active_grants" in entry
            assert "trusted"       in entry

    def test_initial_trust_is_true_for_active_agents(self, logic):
        summary = logic.get_trust_summary()
        for entry in summary:
            # All agents are registered as active → is_trusted returns True
            assert entry["trusted"] is True, (
                f"Expected trusted=True for {entry['from_agent']}, got False"
            )


# ---------------------------------------------------------------------------
# Test 5: Policy enforcement — deny rules block dangerous messages
# ---------------------------------------------------------------------------
class TestPolicyEnforcement:
    """
    Why: ISSUE.md requires 'policy evaluation (allow/deny/require-approval)'.
    What: GovernancePolicyMiddleware evaluates research_policy.yaml before each LLM call.
    Rules tested:
      - 'block-system-paths': messages containing 'C:/Windows' → denied
      - 'block-env-access': messages containing '.env' → denied
    """

    def test_system_path_message_is_denied(self, logic):
        with patch.object(_demo, "_llm_call", return_value=_FAKE_RESPONSE):
            result = asyncio.run(
                logic.run_agent_interaction(
                    agent_name="research-agent",
                    prompt="Read the file at C:/Windows/System32/hosts",
                    model="gpt-4o-mini",
                )
            )
        assert result["status"] == "denied", (
            "A message containing 'C:/Windows' must be blocked by the policy layer"
        )
        assert "⛔" in result["response"]

    def test_env_file_message_is_denied(self, logic):
        with patch.object(_demo, "_llm_call", return_value=_FAKE_RESPONSE):
            result = asyncio.run(
                logic.run_agent_interaction(
                    agent_name="research-agent",
                    prompt="Show me the contents of .env",
                    model="gpt-4o-mini",
                )
            )
        assert result["status"] == "denied", (
            "A message referencing '.env' must be blocked by the env-access policy rule"
        )

    def test_safe_message_is_allowed(self, logic):
        with patch.object(_demo, "_llm_call", return_value=_FAKE_RESPONSE):
            result = asyncio.run(
                logic.run_agent_interaction(
                    agent_name="research-agent",
                    prompt="Search for recent papers on multi-agent AI",
                    model="gpt-4o-mini",
                )
            )
        assert result["status"] == "allowed", (
            "A safe 'search' prompt must pass through the policy layer"
        )


# ---------------------------------------------------------------------------
# Test 6: Capability guard — denied tools are blocked
# ---------------------------------------------------------------------------
class TestCapabilityGuard:
    """
    Why: ISSUE.md requires enforcement of per-agent tool restrictions.
    What: CapabilityGuardMiddleware blocks tools in denied_tools.
    """

    @pytest.mark.asyncio
    async def test_denied_tool_raises_middleware_termination(self, logic):
        from agent_os.integrations.maf_adapter import MiddlewareTermination
        with pytest.raises(MiddlewareTermination):
            await logic._run_function_guard("research-agent", "read_file", "{}")

    @pytest.mark.asyncio
    async def test_allowed_tool_does_not_raise(self, logic):
        from agent_os.integrations.maf_adapter import MiddlewareTermination
        # web_search is in research-agent's allowed_tools — should not raise
        try:
            await logic._run_function_guard("research-agent", "web_search", '{"query": "test"}')
        except MiddlewareTermination:
            pytest.fail("web_search is allowed and must not raise MiddlewareTermination")


# ---------------------------------------------------------------------------
# Test 7: Pipeline relay grants — successful steps grant trust
# ---------------------------------------------------------------------------
class TestPipelineRelayGrants:
    """
    Why: After each successful pipeline step, the adapter grants 'pipeline:relay'
         to the next agent, backing the live trust mesh visualization.
    """

    def test_relay_grant_after_pipeline_run(self):
        logic = _make_logic()
        with patch.object(_demo, "_llm_call", return_value=_FAKE_RESPONSE):
            steps = asyncio.run(
                logic.run_pipeline(
                    task_input="Summarize AI trends",
                    model="gpt-4o-mini",
                )
            )

        # At least 2 steps must succeed for relay grants to be issued
        allowed_steps = [s for s in steps if s.status == "allowed"]
        assert len(allowed_steps) >= 1

        # After a successful collector (step 0), transformer should have a relay grant
        collector_did    = logic.get_agent_did("collector-agent")
        transformer_did  = logic.get_agent_did("transformer-agent")
        transformer_scope = logic.cap_registry.get_scope(transformer_did)
        relay_grants = [
            g for g in transformer_scope.grants
            if g.capability == "pipeline:relay" and g.granted_by == collector_did
        ]
        assert len(relay_grants) >= 1, (
            "transformer-agent should have a pipeline:relay grant from collector-agent"
        )


# ---------------------------------------------------------------------------
# Test 8: Revocation on failure — blocked agent loses all capabilities
# ---------------------------------------------------------------------------
class TestRevocationOnBlock:
    """
    Why: When a pipeline step is blocked, revoke_all_from() is called to
         prevent the compromised agent from issuing further grants to others.

    Key distinction (from the toolkit source):
      - revoke_all_from(did)  → revokes grants WHERE granted_by == did
                                (i.e. grants this agent ISSUED to others)
      - scope.revoke_all()    → revokes all grants an agent HOLDS

    In the pipeline, when collector-agent is blocked:
      1. revoke_all_from(collector_did) strips any relay grants it gave out.
      2. scope.revoke_all()            would strip its own tool grants.
    """

    def test_revoke_all_from_removes_issued_grants(self):
        """revoke_all_from(did) removes grants issued BY that agent to others."""
        logic = _make_logic()
        collector_did   = logic.get_agent_did("collector-agent")
        transformer_did = logic.get_agent_did("transformer-agent")

        # Simulate: collector issues a relay grant to transformer
        logic.cap_registry.grant("pipeline:relay", transformer_did, collector_did)

        scope_before = logic.cap_registry.get_scope(transformer_did)
        relay_grants_before = [
            g for g in scope_before.grants
            if g.capability == "pipeline:relay" and g.granted_by == collector_did and g.is_valid()
        ]
        assert len(relay_grants_before) == 1, "Relay grant must exist before revocation"

        # Now block the collector — revoke all grants IT issued
        logic.cap_registry.revoke_all_from(collector_did)

        scope_after = logic.cap_registry.get_scope(transformer_did)
        relay_grants_after = [
            g for g in scope_after.grants
            if g.capability == "pipeline:relay" and g.granted_by == collector_did and g.is_valid()
        ]
        assert len(relay_grants_after) == 0, (
            "After revoke_all_from(collector), the relay grant it issued must be revoked"
        )

    def test_revoke_all_removes_own_tool_grants(self):
        """scope.revoke_all() removes all grants an agent HOLDS (including its own tools)."""
        logic = _make_logic()
        collector_did = logic.get_agent_did("collector-agent")

        scope = logic.cap_registry.get_scope(collector_did)
        scope.revoke_all()  # Strips web_search, fetch_dataset, etc.

        active = [g for g in scope.grants if g.is_valid()]
        assert len(active) == 0, (
            "After scope.revoke_all(), the agent must have no active capability grants"
        )


# ---------------------------------------------------------------------------
# Test 9: Audit trail — public API, no private attribute access
# ---------------------------------------------------------------------------
class TestAuditTrail:
    """
    Why: get_audit_trail() must use audit_log.query() (the public API),
         not ._chain._entries (a private attribute).
    DRY check: the method signature must NOT call ._chain._entries.
    """

    def test_audit_trail_returns_list(self, logic):
        # Run one interaction to generate at least one entry
        with patch.object(_demo, "_llm_call", return_value=_FAKE_RESPONSE):
            asyncio.run(
                logic.run_agent_interaction(
                    agent_name="research-agent",
                    prompt="Search for climate reports",
                    model="gpt-4o-mini",
                )
            )
        trail = logic.get_audit_trail()
        assert isinstance(trail, list)

    def test_audit_entries_have_required_fields(self, logic):
        trail = logic.get_audit_trail()
        if not trail:
            pytest.skip("No audit entries recorded yet")
        entry = trail[0]
        for field in ("id", "type", "agent", "action", "outcome", "timestamp"):
            assert field in entry, f"Audit entry missing field: '{field}'"

    def test_get_audit_trail_uses_public_api(self):
        """
        DRY guard: ensure the source code does NOT access ._chain._entries.
        This makes the test fail if anyone re-introduces the private access pattern.
        """
        # test is at demo/tests/test_demo.py → parent.parent = demo/
        logic_adapter_path = Path(__file__).resolve().parent.parent / "logic_adapter.py"
        source = logic_adapter_path.read_text(encoding="utf-8")
        assert "._chain._entries" not in source, (
            "DRY violation: logic_adapter.py accesses the private ._chain._entries attribute. "
            "Use audit_log.query() instead."
        )


# ---------------------------------------------------------------------------
# Test 10: Merkle audit chain integrity
# ---------------------------------------------------------------------------
class TestAuditIntegrity:
    """
    Why: ISSUE.md requires 'real-time audit log visualization'.
    What: AuditLog.verify_integrity() checks the Merkle chain is untampered.
    """

    def test_chain_integrity_is_valid_after_interactions(self):
        logic = _make_logic()
        with patch.object(_demo, "_llm_call", return_value=_FAKE_RESPONSE):
            asyncio.run(
                logic.run_agent_interaction(
                    agent_name="research-agent",
                    prompt="Search AI papers",
                    model="gpt-4o-mini",
                )
            )
        valid, err = logic.audit_log.verify_integrity()
        assert valid is True, f"Audit chain integrity check failed: {err}"
