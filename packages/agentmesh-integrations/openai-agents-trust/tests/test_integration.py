"""Tests for OpenAI Agents SDK integration (guardrails, hooks, handoffs).

Uses the real openai-agents SDK types since it's installed as a dependency.
"""

import pytest
from openai_agents_trust.guardrails import (
    trust_input_guardrail,
    policy_input_guardrail,
    content_output_guardrail,
    TrustGuardrailConfig,
    PolicyGuardrailConfig,
)
from openai_agents_trust.hooks import GovernanceHooks
from openai_agents_trust.trust import TrustScorer
from openai_agents_trust.policy import GovernancePolicy
from openai_agents_trust.audit import AuditLog
from openai_agents_trust.identity import AgentIdentity

from agents import Agent, InputGuardrail, OutputGuardrail
from agents.guardrail import GuardrailFunctionOutput


def make_agent(name: str = "test-agent") -> Agent:
    return Agent(name=name, instructions="Test agent")


class TestTrustInputGuardrail:
    def test_creates_input_guardrail(self):
        config = TrustGuardrailConfig(scorer=TrustScorer())
        guardrail = trust_input_guardrail(config)
        assert isinstance(guardrail, InputGuardrail)
        assert guardrail.name == "agentmesh_trust_guardrail"

    def test_allows_trusted_agent(self):
        audit = AuditLog()
        config = TrustGuardrailConfig(scorer=TrustScorer(), min_score=0.5, audit_log=audit)
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent("trusted"), "test")
        assert isinstance(result, GuardrailFunctionOutput)
        assert result.tripwire_triggered is False
        assert result.output_info["passed"] is True
        assert len(audit) == 1

    def test_blocks_untrusted_agent(self):
        audit = AuditLog()
        config = TrustGuardrailConfig(scorer=TrustScorer(default_score=0.3), min_score=0.5, audit_log=audit)
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent("untrusted"), "test")
        assert result.tripwire_triggered is True
        assert result.output_info["passed"] is False
        assert len(audit.get_entries(decision="deny")) == 1

    def test_requires_identity_blocks_unregistered(self):
        config = TrustGuardrailConfig(scorer=TrustScorer(), require_identity=True, audit_log=AuditLog())
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent("no-id"), "test")
        assert result.tripwire_triggered is True

    def test_requires_identity_allows_registered(self):
        identity = AgentIdentity(agent_id="a1", name="Agent 1", secret_key="key")
        config = TrustGuardrailConfig(scorer=TrustScorer(), require_identity=True, identities={"a1": identity})
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent("a1"), "test")
        assert result.tripwire_triggered is False


class TestPolicyInputGuardrail:
    def test_creates_input_guardrail(self):
        config = PolicyGuardrailConfig(policy=GovernancePolicy())
        guardrail = policy_input_guardrail(config)
        assert isinstance(guardrail, InputGuardrail)

    def test_allows_clean_input(self):
        audit = AuditLog()
        config = PolicyGuardrailConfig(policy=GovernancePolicy(blocked_patterns=[r"DROP TABLE"]), audit_log=audit)
        guardrail = policy_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent(), "SELECT * FROM users")
        assert result.tripwire_triggered is False
        assert len(audit) == 1

    def test_blocks_dangerous_input(self):
        config = PolicyGuardrailConfig(policy=GovernancePolicy(blocked_patterns=[r"DROP TABLE"]), audit_log=AuditLog())
        guardrail = policy_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent(), "DROP TABLE users")
        assert result.tripwire_triggered is True
        assert "violation" in result.output_info

    def test_blocks_regex(self):
        config = PolicyGuardrailConfig(policy=GovernancePolicy(blocked_patterns=[r"eval\(.*\)"]))
        guardrail = policy_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent(), "Run eval('code')")
        assert result.tripwire_triggered is True


class TestContentOutputGuardrail:
    def test_creates_output_guardrail(self):
        guardrail = content_output_guardrail(GovernancePolicy())
        assert isinstance(guardrail, OutputGuardrail)

    def test_allows_clean_output(self):
        guardrail = content_output_guardrail(GovernancePolicy(blocked_patterns=[r"password"]))
        result = guardrail.guardrail_function(None, make_agent(), "Clean report")
        assert result.tripwire_triggered is False

    def test_blocks_sensitive_output(self):
        audit = AuditLog()
        guardrail = content_output_guardrail(GovernancePolicy(blocked_patterns=[r"password"]), audit_log=audit)
        result = guardrail.guardrail_function(None, make_agent(), "The password is abc")
        assert result.tripwire_triggered is True
        assert len(audit.get_entries(decision="deny")) == 1


class TestGovernanceHooks:
    @pytest.mark.asyncio
    async def test_on_agent_start(self):
        hooks = GovernanceHooks(policy=GovernancePolicy())
        await hooks.on_agent_start(None, make_agent("a1"))
        assert len(hooks.audit_log) == 1
        assert hooks.audit_log.get_entries()[0].action == "agent_start"

    @pytest.mark.asyncio
    async def test_on_agent_end_boosts_trust(self):
        scorer = TrustScorer(default_score=0.5)
        hooks = GovernanceHooks(policy=GovernancePolicy(), scorer=scorer)
        hooks._agent_start_times["a1"] = 0
        await hooks.on_agent_end(None, make_agent("a1"), "output")
        assert scorer.get_score("a1").reliability > 0.5

    @pytest.mark.asyncio
    async def test_tool_tracking(self):
        hooks = GovernanceHooks(policy=GovernancePolicy(max_tool_calls=100))

        class FakeTool:
            name = "search"

        await hooks.on_tool_start(None, make_agent("a1"), FakeTool())
        assert hooks.get_tool_call_count("a1") == 1

    @pytest.mark.asyncio
    async def test_tool_limit_warning(self):
        hooks = GovernanceHooks(policy=GovernancePolicy(max_tool_calls=2))

        class FakeTool:
            name = "search"

        for _ in range(3):
            await hooks.on_tool_start(None, make_agent("a1"), FakeTool())
        assert len(hooks.audit_log.get_entries(decision="warn")) == 1

    @pytest.mark.asyncio
    async def test_blocked_tool_warning(self):
        hooks = GovernanceHooks(policy=GovernancePolicy(allowed_tools=["search"]))

        class FakeTool:
            name = "execute_code"

        await hooks.on_tool_start(None, make_agent("a1"), FakeTool())
        assert len(hooks.audit_log.get_entries(decision="warn")) == 1

    @pytest.mark.asyncio
    async def test_tool_output_check(self):
        hooks = GovernanceHooks(policy=GovernancePolicy(blocked_patterns=[r"secret"]))

        class FakeTool:
            name = "search"

        await hooks.on_tool_end(None, make_agent("a1"), FakeTool(), "The secret is 42")
        assert len(hooks.audit_log.get_entries(decision="warn")) == 1

    @pytest.mark.asyncio
    async def test_handoff_recording(self):
        hooks = GovernanceHooks(policy=GovernancePolicy())
        await hooks.on_handoff(None, make_agent("triage"), make_agent("billing"))
        entries = hooks.audit_log.get_entries()
        assert any("handoff_to:billing" in e.action for e in entries)

    def test_summary(self):
        hooks = GovernanceHooks(policy=GovernancePolicy())
        hooks.audit_log.record("a1", "t1", "allow")
        hooks.audit_log.record("a1", "t2", "deny")
        hooks.audit_log.record("a1", "t3", "warn")
        summary = hooks.get_summary()
        assert summary["total_events"] == 3
        assert summary["denials"] == 1
        assert summary["warnings"] == 1
        assert summary["chain_valid"] is True
