# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ADK AgentMesh governance integration."""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path

import pytest

from adk_agentmesh.evaluator import ADKPolicyEvaluator, PolicyDecision, Verdict
from adk_agentmesh.governance import DelegationScope, GovernanceCallbacks
from adk_agentmesh.audit import AuditEvent, LoggingAuditHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture()
def evaluator():
    """A basic evaluator with common test settings."""
    return ADKPolicyEvaluator(
        blocked_tools=["execute_shell", "drop_table"],
        allowed_tools=[],
        max_tool_calls=3,
        require_approval_for=["send_email"],
    )


@pytest.fixture()
def sample_policy_path(tmp_path: Path) -> Path:
    """Write a minimal YAML policy to a temp file."""
    policy = textwrap.dedent("""\
        version: "1.0"
        name: test-policy
        adk_governance:
          blocked_tools:
            - dangerous_tool
            - nuke_everything
          max_tool_calls: 5
          require_approval_for:
            - publish_document
    """)
    p = tmp_path / "policy.yaml"
    p.write_text(policy, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# ADKPolicyEvaluator — tool call evaluation
# ---------------------------------------------------------------------------

class TestBlockedTools:
    """Blocked tools must be denied."""

    @pytest.mark.asyncio
    async def test_blocked_tool_is_denied(self, evaluator: ADKPolicyEvaluator):
        decision = await evaluator.evaluate_tool_call(
            tool_name="execute_shell",
            tool_args={"cmd": "rm -rf /"},
            agent_name="bad-agent",
        )
        assert decision.verdict == Verdict.DENY
        assert "blocked" in decision.reason.lower()
        assert decision.matched_rule == "blocked_tool"

    @pytest.mark.asyncio
    async def test_second_blocked_tool_is_also_denied(self, evaluator: ADKPolicyEvaluator):
        decision = await evaluator.evaluate_tool_call(
            tool_name="drop_table",
            tool_args={"table": "users"},
            agent_name="bad-agent",
        )
        assert decision.verdict == Verdict.DENY


class TestAllowedTools:
    """Unrestricted tools should pass when no allowlist is set."""

    @pytest.mark.asyncio
    async def test_allowed_tool_passes(self, evaluator: ADKPolicyEvaluator):
        decision = await evaluator.evaluate_tool_call(
            tool_name="search_web",
            tool_args={"q": "governance"},
            agent_name="good-agent",
        )
        assert decision.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_allowlist_restricts_tools(self):
        evaluator = ADKPolicyEvaluator(allowed_tools=["search_web", "read_file"])
        decision = await evaluator.evaluate_tool_call(
            tool_name="write_file",
            tool_args={"path": "/etc/passwd"},
            agent_name="agent",
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "allowed_tools"

    @pytest.mark.asyncio
    async def test_allowlist_permits_listed_tool(self):
        evaluator = ADKPolicyEvaluator(allowed_tools=["search_web", "read_file"])
        decision = await evaluator.evaluate_tool_call(
            tool_name="search_web",
            tool_args={"q": "hello"},
            agent_name="agent",
        )
        assert decision.verdict == Verdict.ALLOW


class TestRateLimit:
    """Rate limiting must kick in after max_tool_calls."""

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self, evaluator: ADKPolicyEvaluator):
        # evaluator has max_tool_calls=3
        for i in range(3):
            decision = await evaluator.evaluate_tool_call(
                tool_name="search_web",
                tool_args={"q": f"query-{i}"},
                agent_name="fast-agent",
            )
            assert decision.verdict == Verdict.ALLOW

        # 4th call should be denied
        decision = await evaluator.evaluate_tool_call(
            tool_name="search_web",
            tool_args={"q": "one-too-many"},
            agent_name="fast-agent",
        )
        assert decision.verdict == Verdict.DENY
        assert decision.matched_rule == "rate_limit"

    @pytest.mark.asyncio
    async def test_rate_limit_per_agent(self, evaluator: ADKPolicyEvaluator):
        """Different agents have independent counters."""
        for i in range(3):
            await evaluator.evaluate_tool_call(
                tool_name="search_web",
                tool_args={},
                agent_name="agent-a",
            )
        # agent-a is at the limit, agent-b should still work
        decision = await evaluator.evaluate_tool_call(
            tool_name="search_web",
            tool_args={},
            agent_name="agent-b",
        )
        assert decision.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_reset_counters(self, evaluator: ADKPolicyEvaluator):
        for i in range(3):
            await evaluator.evaluate_tool_call(
                tool_name="search_web",
                tool_args={},
                agent_name="agent",
            )
        evaluator.reset_counters()
        decision = await evaluator.evaluate_tool_call(
            tool_name="search_web",
            tool_args={},
            agent_name="agent",
        )
        assert decision.verdict == Verdict.ALLOW


class TestApprovalRequired:
    """Tools requiring approval should escalate."""

    @pytest.mark.asyncio
    async def test_approval_required_escalation(self, evaluator: ADKPolicyEvaluator):
        decision = await evaluator.evaluate_tool_call(
            tool_name="send_email",
            tool_args={"to": "boss@example.com"},
            agent_name="assistant",
        )
        assert decision.verdict == Verdict.ESCALATE
        assert "approval" in decision.reason.lower()
        assert decision.matched_rule == "require_approval"


class TestAuditLog:
    """Audit log must capture governance decisions."""

    @pytest.mark.asyncio
    async def test_audit_log_populated(self, evaluator: ADKPolicyEvaluator):
        await evaluator.evaluate_tool_call(
            tool_name="search_web", tool_args={}, agent_name="agent"
        )
        await evaluator.evaluate_tool_call(
            tool_name="execute_shell", tool_args={}, agent_name="agent"
        )
        log = evaluator.get_audit_log()
        assert len(log) >= 2
        events = [e["event"] for e in log]
        assert "tool_call_allowed" in events
        assert "tool_call_denied" in events

    @pytest.mark.asyncio
    async def test_audit_log_has_timestamps(self, evaluator: ADKPolicyEvaluator):
        await evaluator.evaluate_tool_call(
            tool_name="search_web", tool_args={}, agent_name="agent"
        )
        log = evaluator.get_audit_log()
        assert all("timestamp" in entry for entry in log)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestConfigLoading:
    """Policy loading from YAML."""

    def test_from_config(self, sample_policy_path: Path):
        evaluator = ADKPolicyEvaluator.from_config(sample_policy_path)
        assert "dangerous_tool" in evaluator._blocked_tools
        assert "nuke_everything" in evaluator._blocked_tools
        assert evaluator._max_tool_calls == 5
        assert "publish_document" in evaluator._require_approval

    def test_missing_config_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            ADKPolicyEvaluator.from_config(tmp_path / "nonexistent.yaml")

    @pytest.mark.asyncio
    async def test_loaded_policy_blocks_tool(self, sample_policy_path: Path):
        evaluator = ADKPolicyEvaluator.from_config(sample_policy_path)
        decision = await evaluator.evaluate_tool_call(
            tool_name="dangerous_tool",
            tool_args={},
            agent_name="agent",
        )
        assert decision.verdict == Verdict.DENY

    @pytest.mark.asyncio
    async def test_loaded_policy_escalates_approval(self, sample_policy_path: Path):
        evaluator = ADKPolicyEvaluator.from_config(sample_policy_path)
        decision = await evaluator.evaluate_tool_call(
            tool_name="publish_document",
            tool_args={},
            agent_name="agent",
        )
        assert decision.verdict == Verdict.ESCALATE


# ---------------------------------------------------------------------------
# DelegationScope
# ---------------------------------------------------------------------------

class TestDelegationScope:
    """Delegation scope narrowing must be monotonic."""

    def test_narrow_reduces_depth(self):
        parent = DelegationScope(max_depth=3)
        child = parent.narrow()
        assert child.max_depth == 2

    def test_narrow_cannot_increase_depth(self):
        parent = DelegationScope(max_depth=3)
        child = parent.narrow(max_depth=10)
        assert child.max_depth == 2  # min(10, 3-1) = 2

    def test_narrow_cannot_increase_tool_calls(self):
        parent = DelegationScope(max_tool_calls=50)
        child = parent.narrow(max_tool_calls=100)
        assert child.max_tool_calls == 50

    def test_narrow_can_decrease_tool_calls(self):
        parent = DelegationScope(max_tool_calls=50)
        child = parent.narrow(max_tool_calls=10)
        assert child.max_tool_calls == 10

    def test_narrow_tools_subset(self):
        parent = DelegationScope(allowed_tools=["read", "write", "delete"])
        child = parent.narrow(allowed_tools=["read", "write", "admin"])
        # "admin" should be filtered out — not in parent
        assert "read" in child.allowed_tools
        assert "write" in child.allowed_tools
        assert "admin" not in child.allowed_tools

    def test_narrow_read_only_is_sticky(self):
        parent = DelegationScope(read_only=True)
        child = parent.narrow(read_only=False)
        assert child.read_only is True  # once set, cannot unset

    def test_narrow_can_set_read_only(self):
        parent = DelegationScope(read_only=False)
        child = parent.narrow(read_only=True)
        assert child.read_only is True


# ---------------------------------------------------------------------------
# GovernanceCallbacks
# ---------------------------------------------------------------------------

class TestGovernanceCallbacks:
    """GovernanceCallbacks wiring into ADK lifecycle."""

    def test_read_only_blocks_write(self):
        evaluator = ADKPolicyEvaluator()
        scope = DelegationScope(read_only=True)
        callbacks = GovernanceCallbacks(evaluator, delegation_scope=scope)

        result = callbacks.before_tool("write_file", {"path": "/tmp/x"})
        assert result is not None
        assert "read-only" in result["error"].lower() or "Read-only" in result["error"]

    def test_read_only_allows_read(self):
        evaluator = ADKPolicyEvaluator()
        scope = DelegationScope(read_only=True)
        callbacks = GovernanceCallbacks(evaluator, delegation_scope=scope)

        result = callbacks.before_tool("read_file", {"path": "/tmp/x"})
        assert result is None  # allowed

    def test_scope_blocks_unlisted_tool(self):
        evaluator = ADKPolicyEvaluator()
        scope = DelegationScope(allowed_tools=["search_web"])
        callbacks = GovernanceCallbacks(evaluator, delegation_scope=scope)

        result = callbacks.before_tool("execute_shell", {"cmd": "ls"})
        assert result is not None
        assert "not in delegation scope" in result["error"]

    def test_max_depth_zero_blocks_delegation(self):
        evaluator = ADKPolicyEvaluator()
        scope = DelegationScope(max_depth=0)
        callbacks = GovernanceCallbacks(evaluator, delegation_scope=scope)

        result = callbacks.before_agent("sub-agent")
        assert result is not None
        assert "depth" in result["error"].lower()


# ---------------------------------------------------------------------------
# AuditEvent & LoggingAuditHandler
# ---------------------------------------------------------------------------

class TestAuditEvent:
    """Structured audit event serialization."""

    def test_to_dict(self):
        event = AuditEvent(
            event_type="tool_call_denied",
            agent_name="test-agent",
            tool_name="execute_shell",
            verdict="deny",
            reason="blocked by policy",
        )
        d = event.to_dict()
        assert d["event_type"] == "tool_call_denied"
        assert d["agent_name"] == "test-agent"
        assert "timestamp" in d

    def test_to_json(self):
        event = AuditEvent(
            event_type="tool_call_allowed",
            agent_name="agent",
        )
        j = event.to_json()
        assert '"event_type": "tool_call_allowed"' in j

    def test_logging_handler(self, caplog):
        handler = LoggingAuditHandler()
        event = AuditEvent(
            event_type="test_event",
            agent_name="agent",
            tool_name="tool",
            verdict="allow",
        )
        with caplog.at_level("INFO", logger="adk_agentmesh.audit"):
            handler.handle(event)
        assert "test_event" in caplog.text
        assert "agent" in caplog.text


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------

class TestPolicyDecision:
    """PolicyDecision dataclass behavior."""

    def test_defaults(self):
        d = PolicyDecision(verdict=Verdict.ALLOW)
        assert d.reason == ""
        assert d.matched_rule == ""
        assert d.metadata == {}
        assert d.timestamp is not None

    def test_verdict_enum_values(self):
        assert Verdict.ALLOW.value == "allow"
        assert Verdict.DENY.value == "deny"
        assert Verdict.ESCALATE.value == "escalate"


# ---------------------------------------------------------------------------
# Delegation evaluation
# ---------------------------------------------------------------------------

class TestDelegationEvaluation:
    """Agent delegation evaluation."""

    @pytest.mark.asyncio
    async def test_delegation_allowed_by_default(self):
        evaluator = ADKPolicyEvaluator()
        decision = await evaluator.evaluate_agent_delegation(
            parent_agent="orchestrator",
            child_agent="worker",
        )
        assert decision.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_delegation_logged(self):
        evaluator = ADKPolicyEvaluator()
        await evaluator.evaluate_agent_delegation(
            parent_agent="orchestrator",
            child_agent="worker",
            scope="read_only",
        )
        log = evaluator.get_audit_log()
        assert any(e["event"] == "delegation_evaluated" for e in log)
