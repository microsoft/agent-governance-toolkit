# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for PydanticAI governance adapter.

No real pydantic-ai dependency required — uses mock Agent objects.

Run with: python -m pytest tests/test_pydantic_ai_adapter.py -v --tb=short
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_os.integrations.pydantic_ai_adapter import (
    HumanApprovalRequired,
    PydanticAIKernel,
    wrap,
)
from agent_os.integrations.base import (
    GovernancePolicy,
    PolicyViolationError,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_tool(name="search", return_value="tool result"):
    """Create a mock PydanticAI tool entry."""
    tool = MagicMock()
    tool.name = name
    tool.function = MagicMock(return_value=return_value)
    tool._governed = False
    return tool


def _make_agent(name="assistant", tools=None):
    """Create a mock PydanticAI Agent."""
    agent = MagicMock()
    agent.name = name
    agent._function_tools = tools or []
    agent.run = AsyncMock(return_value="async result")
    agent.run_sync = MagicMock(return_value="sync result")
    return agent


# =============================================================================
# 1. Basic wrapping
# =============================================================================


class TestBasicWrapping:
    def test_wrap_returns_governed_agent(self):
        """wrap() should return a governed wrapper, not the original."""
        agent = _make_agent()
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)
        assert governed is not agent
        assert governed.original is agent

    def test_unwrap_returns_original(self):
        """unwrap() should return the original agent."""
        agent = _make_agent()
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)
        assert kernel.unwrap(governed) is agent

    def test_unwrap_passthrough(self):
        """unwrap() on a non-wrapped object returns it unchanged."""
        kernel = PydanticAIKernel()
        plain = object()
        assert kernel.unwrap(plain) is plain

    def test_getattr_delegates(self):
        """Unknown attributes proxy to the original agent."""
        agent = _make_agent()
        agent.custom_attr = "hello"
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)
        assert governed.custom_attr == "hello"

    def test_context_created(self):
        """Wrapping creates an ExecutionContext."""
        agent = _make_agent(name="ctx-test")
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)
        assert governed.context is not None
        assert governed.context.agent_id == "ctx-test"

    def test_convenience_wrap(self):
        """Module-level wrap() helper works."""
        agent = _make_agent()
        governed = wrap(agent)
        assert governed.original is agent


# =============================================================================
# 2. Policy enforcement — allowed / denied tools
# =============================================================================


class TestPolicyEnforcement:
    def test_allowed_tool_passes(self):
        """A tool on the allowlist should execute normally."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(allowed_tools=["search", "read_file"])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        tool.function(query="test")

    def test_blocked_tool_raises(self):
        """A tool NOT on the allowlist should be blocked."""
        tool = _make_tool("shell_exec")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(allowed_tools=["search"])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        with pytest.raises(PolicyViolationError, match="not in allowed list"):
            tool.function(command="ls")

    def test_empty_allowlist_permits_all(self):
        """An empty allowed_tools list permits any tool."""
        tool = _make_tool("anything")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(allowed_tools=[])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        tool.function()  # should not raise


# =============================================================================
# 3. Tool call interception
# =============================================================================


class TestToolCallInterception:
    def test_tool_marked_governed(self):
        """After wrapping, the tool entry should be marked _governed."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        kernel = PydanticAIKernel()
        kernel.wrap(agent)
        assert tool._governed is True

    def test_tool_original_fn_called(self):
        """When allowed, the original function should still be invoked."""
        original_fn = MagicMock(return_value="ok")
        tool = _make_tool("search")
        tool.function = original_fn
        agent = _make_agent(tools=[tool])
        kernel = PydanticAIKernel()
        kernel.wrap(agent)

        result = tool.function(query="hello")
        assert result == "ok"
        original_fn.assert_called_once_with(query="hello")

    def test_intercept_tool_call_allowed(self):
        """intercept_tool_call returns allowed=True for valid calls."""
        kernel = PydanticAIKernel()
        agent = _make_agent(name="test-agent")
        governed = kernel.wrap(agent)
        result = kernel.intercept_tool_call(governed.context, "search", {"q": "hi"})
        assert result.allowed is True

    def test_intercept_tool_call_denied(self):
        """intercept_tool_call returns allowed=False for disallowed tools."""
        policy = GovernancePolicy(allowed_tools=["search"])
        kernel = PydanticAIKernel(policy=policy)
        agent = _make_agent(name="test-agent")
        governed = kernel.wrap(agent)
        result = kernel.intercept_tool_call(governed.context, "shell", {"cmd": "ls"})
        assert result.allowed is False
        assert "not in allowed list" in result.reason


# =============================================================================
# 4. Blocked pattern detection
# =============================================================================


class TestBlockedPatterns:
    def test_blocked_pattern_in_args(self):
        """Tool args matching a blocked pattern should be rejected."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(blocked_patterns=["password", "secret"])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            tool.function(query="show me the password")

    def test_no_match_passes(self):
        """Arguments not matching blocked patterns should pass."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        tool.function(query="SELECT * FROM users")  # should not raise

    def test_blocked_pattern_in_run_prompt(self):
        """Blocked patterns in the run prompt should block execution."""
        agent = _make_agent()
        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        kernel = PydanticAIKernel(policy=policy)
        governed = kernel.wrap(agent)

        with pytest.raises(PolicyViolationError):
            governed.run_sync("Please run DROP TABLE users")


# =============================================================================
# 5. Human approval flow
# =============================================================================


class TestHumanApproval:
    def test_approval_required_no_callback(self):
        """When require_human_approval=True and no callback, tool is blocked."""
        policy = GovernancePolicy(require_human_approval=True)
        kernel = PydanticAIKernel(policy=policy)
        agent = _make_agent(name="approval-test")
        governed = kernel.wrap(agent)

        result = kernel.intercept_tool_call(governed.context, "deploy", {"env": "prod"})
        assert result.allowed is False
        assert "requires human approval" in result.reason

    def test_approval_granted(self):
        """When callback returns True, tool is allowed."""
        policy = GovernancePolicy(require_human_approval=True)
        callback = MagicMock(return_value=True)
        kernel = PydanticAIKernel(policy=policy, approval_callback=callback)
        agent = _make_agent(name="approval-test")
        governed = kernel.wrap(agent)

        result = kernel.intercept_tool_call(governed.context, "deploy", {"env": "prod"})
        assert result.allowed is True
        callback.assert_called_once_with("deploy", {"env": "prod"})

    def test_approval_denied(self):
        """When callback returns False, tool is blocked."""
        policy = GovernancePolicy(require_human_approval=True)
        callback = MagicMock(return_value=False)
        kernel = PydanticAIKernel(policy=policy, approval_callback=callback)
        agent = _make_agent(name="approval-test")
        governed = kernel.wrap(agent)

        result = kernel.intercept_tool_call(governed.context, "deploy", {"env": "prod"})
        assert result.allowed is False
        assert "denied" in result.reason


# =============================================================================
# 6. Call budget enforcement
# =============================================================================


class TestCallBudget:
    def test_budget_enforced(self):
        """After max_tool_calls, further calls should be blocked."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(max_tool_calls=2)
        kernel = PydanticAIKernel(policy=policy)
        governed = kernel.wrap(agent)

        tool.function(query="one")
        tool.function(query="two")

        with pytest.raises(PolicyViolationError, match="Max tool calls exceeded"):
            tool.function(query="three")

    def test_budget_not_exceeded(self):
        """Calls within the budget should succeed."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(max_tool_calls=5)
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        for i in range(5):
            tool.function(query=f"call-{i}")


# =============================================================================
# 7. Audit logging
# =============================================================================


class TestAuditLogging:
    def test_tool_calls_logged(self):
        """Each tool call should produce an audit entry."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        kernel = PydanticAIKernel()
        kernel.wrap(agent)

        tool.function(query="test")
        assert len(kernel.audit_log) >= 1
        entry = [e for e in kernel.audit_log if e["event_type"] == "tool_executed"]
        assert len(entry) == 1
        assert entry[0]["tool_name"] == "search"
        assert entry[0]["allowed"] is True

    def test_blocked_calls_logged(self):
        """Blocked tool calls should be logged with allowed=False."""
        tool = _make_tool("shell")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(allowed_tools=["search"])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        with pytest.raises(PolicyViolationError):
            tool.function(cmd="ls")

        blocked = [e for e in kernel.audit_log if e["event_type"] == "tool_blocked"]
        assert len(blocked) == 1
        assert blocked[0]["allowed"] is False

    def test_run_sync_logged(self):
        """run_sync should produce audit entries."""
        agent = _make_agent()
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)
        governed.run_sync("hello")

        starts = [e for e in kernel.audit_log if e["event_type"] == "run_start"]
        completes = [e for e in kernel.audit_log if e["event_type"] == "run_complete"]
        assert len(starts) == 1
        assert len(completes) == 1

    def test_log_all_calls_disabled(self):
        """When log_all_calls=False, audit log should stay empty."""
        tool = _make_tool("search")
        agent = _make_agent(tools=[tool])
        policy = GovernancePolicy(log_all_calls=False)
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        tool.function(query="test")
        assert len(kernel.audit_log) == 0


# =============================================================================
# 8. Error handling
# =============================================================================


class TestErrorHandling:
    def test_run_sync_exception_recorded(self):
        """Exceptions during run_sync should be re-raised and logged."""
        agent = _make_agent()
        agent.run_sync.side_effect = RuntimeError("boom")
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)

        with pytest.raises(RuntimeError, match="boom"):
            governed.run_sync("test")

        errors = [e for e in kernel.audit_log if e["event_type"] == "run_error"]
        assert len(errors) == 1
        assert kernel._last_error == "boom"

    @pytest.mark.asyncio
    async def test_run_async_exception_recorded(self):
        """Exceptions during run() should be re-raised and logged."""
        agent = _make_agent()
        agent.run = AsyncMock(side_effect=RuntimeError("async boom"))
        kernel = PydanticAIKernel()
        governed = kernel.wrap(agent)

        with pytest.raises(RuntimeError, match="async boom"):
            await governed.run("test")

        errors = [e for e in kernel.audit_log if e["event_type"] == "run_error"]
        assert len(errors) == 1

    def test_health_check_healthy(self):
        """Health check should report healthy when no errors."""
        kernel = PydanticAIKernel()
        agent = _make_agent()
        kernel.wrap(agent)
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "pydantic_ai"
        assert health["backend_connected"] is True

    def test_health_check_degraded(self):
        """Health check should report degraded after an error."""
        kernel = PydanticAIKernel()
        kernel._last_error = "something failed"
        health = kernel.health_check()
        assert health["status"] == "degraded"


# =============================================================================
# 9. Multiple tools governance
# =============================================================================


class TestMultipleToolsGovernance:
    def test_multiple_tools_wrapped(self):
        """All tools on an agent should be wrapped."""
        t1 = _make_tool("search")
        t2 = _make_tool("read_file")
        t3 = _make_tool("write_file")
        agent = _make_agent(tools=[t1, t2, t3])
        kernel = PydanticAIKernel()
        kernel.wrap(agent)

        assert t1._governed is True
        assert t2._governed is True
        assert t3._governed is True

    def test_mixed_allow_deny(self):
        """Allowlist should permit some tools and deny others."""
        allowed = _make_tool("search")
        denied = _make_tool("delete_db")
        agent = _make_agent(tools=[allowed, denied])
        policy = GovernancePolicy(allowed_tools=["search"])
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        allowed.function(query="ok")  # should succeed

        with pytest.raises(PolicyViolationError):
            denied.function(target="users")

    def test_stats_reflect_calls(self):
        """get_stats should reflect actual tool call counts."""
        t1 = _make_tool("search")
        t2 = _make_tool("read_file")
        agent = _make_agent(tools=[t1, t2])
        kernel = PydanticAIKernel()
        kernel.wrap(agent)

        t1.function(q="a")
        t1.function(q="b")
        t2.function(path="x")

        stats = kernel.get_stats()
        assert stats["total_tool_calls"] == 3
        assert stats["wrapped_agents"] == 1

    def test_budget_shared_across_tools(self):
        """Call budget is shared across all tools on the same agent."""
        t1 = _make_tool("search")
        t2 = _make_tool("read_file")
        agent = _make_agent(tools=[t1, t2])
        policy = GovernancePolicy(max_tool_calls=3)
        kernel = PydanticAIKernel(policy=policy)
        kernel.wrap(agent)

        t1.function(q="1")
        t2.function(p="2")
        t1.function(q="3")

        with pytest.raises(PolicyViolationError, match="Max tool calls exceeded"):
            t2.function(p="4")
