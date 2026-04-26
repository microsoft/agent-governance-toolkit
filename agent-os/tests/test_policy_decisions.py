# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ESCALATE and DEFER policy decisions."""

import asyncio

import pytest

from agent_os.base_agent import (
    AgentConfig,
    BaseAgent,
    EscalationRequest,
    PolicyDecision,
)
from agent_os.stateless import ExecutionResult


# ---------------------------------------------------------------------------
# Concrete agent for testing
# ---------------------------------------------------------------------------

class _StubAgent(BaseAgent):
    """Minimal concrete agent used in tests."""

    async def run(self, *args, **kwargs) -> ExecutionResult:
        return await self._execute("noop", {})


# ---------------------------------------------------------------------------
# PolicyDecision enum tests
# ---------------------------------------------------------------------------

class TestPolicyDecisionEnum:
    """Verify ESCALATE and DEFER are present on the enum."""

    def test_escalate_member(self):
        assert PolicyDecision.ESCALATE.value == "escalate"

    def test_defer_member(self):
        assert PolicyDecision.DEFER.value == "defer"

    def test_all_members(self):
        names = {m.name for m in PolicyDecision}
        assert {"ALLOW", "DENY", "AUDIT", "ESCALATE", "DEFER"}.issubset(names)


# ---------------------------------------------------------------------------
# EscalationRequest tests
# ---------------------------------------------------------------------------

class TestEscalationRequest:
    """Verify EscalationRequest dataclass behaviour."""

    def test_default_status_is_pending(self):
        req = EscalationRequest(
            action="send_email", reason="risky", requested_by="agent-1"
        )
        assert req.status == "pending"

    def test_approve(self):
        req = EscalationRequest(
            action="delete_db", reason="destructive", requested_by="agent-1"
        )
        req.approve()
        assert req.status == "approved"

    def test_reject(self):
        req = EscalationRequest(
            action="delete_db", reason="destructive", requested_by="agent-1"
        )
        req.reject()
        assert req.status == "rejected"

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError, match="Invalid status"):
            EscalationRequest(
                action="x", reason="y", requested_by="z", status="unknown"
            )

    def test_to_dict(self):
        req = EscalationRequest(
            action="deploy", reason="needs approval", requested_by="agent-2"
        )
        d = req.to_dict()
        assert d["action"] == "deploy"
        assert d["status"] == "pending"
        assert "timestamp" in d


# ---------------------------------------------------------------------------
# _enforce_policy — ESCALATE path
# ---------------------------------------------------------------------------

class TestEnforcePolicyEscalate:
    """Test _enforce_policy with ESCALATE decision."""

    @pytest.fixture()
    def agent(self):
        return _StubAgent(AgentConfig(agent_id="test-agent"))

    @pytest.mark.asyncio
    async def test_escalate_returns_pending_result(self, agent):
        result = await agent._enforce_policy(
            PolicyDecision.ESCALATE, "send_email", {"to": "boss@co.com"}
        )
        assert result.success is False
        assert result.signal == "ESCALATE"
        assert result.data["status"] == "pending"

    @pytest.mark.asyncio
    async def test_escalate_queues_request(self, agent):
        await agent._enforce_policy(
            PolicyDecision.ESCALATE, "deploy", {}, reason="prod deploy"
        )
        queue = agent.get_escalation_queue()
        assert len(queue) == 1
        assert queue[0].action == "deploy"
        assert queue[0].reason == "prod deploy"

    @pytest.mark.asyncio
    async def test_escalate_audit_entry(self, agent):
        """Calling _enforce_policy directly doesn't create an audit entry,
        but calling _execute with a signal should."""
        result = await agent._enforce_policy(
            PolicyDecision.ESCALATE, "risky_action", {}
        )
        assert result.data["requested_by"] == "test-agent"


# ---------------------------------------------------------------------------
# _enforce_policy — DEFER path
# ---------------------------------------------------------------------------

class TestEnforcePolicyDefer:
    """Test _enforce_policy with DEFER decision."""

    @pytest.fixture()
    def agent(self):
        return _StubAgent(AgentConfig(agent_id="defer-agent"), defer_timeout=1.0)

    @pytest.mark.asyncio
    async def test_defer_no_callback_returns_error(self, agent):
        result = await agent._enforce_policy(PolicyDecision.DEFER, "scan", {})
        assert result.success is False
        assert "no callback registered" in result.error

    @pytest.mark.asyncio
    async def test_defer_callback_allows(self, agent):
        async def _allow(action, params):
            return PolicyDecision.ALLOW

        agent.set_defer_callback(_allow)
        result = await agent._enforce_policy(PolicyDecision.DEFER, "scan", {})
        assert result.success is True

    @pytest.mark.asyncio
    async def test_defer_callback_denies(self, agent):
        async def _deny(action, params):
            return PolicyDecision.DENY

        agent.set_defer_callback(_deny)
        result = await agent._enforce_policy(PolicyDecision.DEFER, "scan", {})
        assert result.success is False
        assert "deny" in result.error.lower()

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_defer_timeout(self, agent):
        async def _slow(action, params):
            await asyncio.sleep(10)
            return PolicyDecision.ALLOW

        agent.set_defer_callback(_slow)
        result = await agent._enforce_policy(PolicyDecision.DEFER, "scan", {})
        assert result.success is False
        assert result.signal == "DEFER_TIMEOUT"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_defer_custom_timeout(self):
        agent = _StubAgent(
            AgentConfig(agent_id="custom-timeout"), defer_timeout=0.1
        )

        async def _slow(action, params):
            await asyncio.sleep(5)
            return PolicyDecision.ALLOW

        agent.set_defer_callback(_slow)
        result = await agent._enforce_policy(PolicyDecision.DEFER, "x", {})
        assert result.signal == "DEFER_TIMEOUT"


# ---------------------------------------------------------------------------
# _enforce_policy — ALLOW / DENY passthrough
# ---------------------------------------------------------------------------

class TestEnforcePolicyPassthrough:
    """ALLOW and DENY still work through _enforce_policy."""

    @pytest.fixture()
    def agent(self):
        return _StubAgent(AgentConfig(agent_id="pt-agent"))

    @pytest.mark.asyncio
    async def test_allow(self, agent):
        result = await agent._enforce_policy(PolicyDecision.ALLOW, "read", {})
        assert result.success is True

    @pytest.mark.asyncio
    async def test_deny(self, agent):
        result = await agent._enforce_policy(
            PolicyDecision.DENY, "write", {}, reason="blocked"
        )
        assert result.success is False
        assert result.signal == "SIGKILL"
