# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for HuggingFace smolagents governance adapter.

No real smolagents dependency required — uses mock Tool/Agent objects.

Run with: python -m pytest tests/test_smolagents_adapter.py -v --tb=short
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.smolagents_adapter import (
    AuditEvent,
    PolicyConfig,
    PolicyViolationError,
    SmolagentsKernel,
    _HAS_SMOLAGENTS,
    _check_smolagents_available,
)


# =============================================================================
# Fake smolagents objects (no real smolagents dependency)
# =============================================================================


class FakeTool:
    """Mimics a smolagents.Tool with name, description, inputs, output_type, and forward."""

    def __init__(self, name: str = "my_tool", description: str = "A test tool"):
        self.name = name
        self.description = description
        self.inputs: Dict[str, Any] = {"query": {"type": "string", "description": "input"}}
        self.output_type = "string"

    def forward(self, **kwargs: Any) -> str:
        return f"result from {self.name}"


class FakeToolbox:
    """Mimics smolagents Toolbox which has a .tools dict."""

    def __init__(self, tools: Dict[str, FakeTool]):
        self.tools = tools


class FakeAgent:
    """Mimics a smolagents CodeAgent or ToolCallingAgent."""

    def __init__(
        self,
        name: str = "test-agent",
        tools: Optional[List[FakeTool]] = None,
    ):
        self.name = name
        tool_list = tools or []
        self.toolbox = FakeToolbox({t.name: t for t in tool_list})

    def run(self, task: str) -> str:
        results = []
        for tool in self.toolbox.tools.values():
            results.append(tool.forward())
        return "; ".join(results) if results else "no tools"


# =============================================================================
# PolicyConfig tests
# =============================================================================


class TestPolicyConfig:
    def test_defaults(self):
        p = PolicyConfig()
        assert p.max_tool_calls == 50
        assert p.max_agent_calls == 20
        assert p.timeout_seconds == 300
        assert p.allowed_tools == []
        assert p.blocked_tools == []
        assert p.blocked_patterns == []
        assert p.log_all_calls is True
        assert p.require_human_approval is False
        assert p.sensitive_tools == []
        assert p.max_budget is None

    def test_custom(self):
        p = PolicyConfig(max_tool_calls=5, blocked_tools=["exec"])
        assert p.max_tool_calls == 5
        assert p.blocked_tools == ["exec"]

    def test_human_approval_fields(self):
        p = PolicyConfig(require_human_approval=True, sensitive_tools=["delete", "send_email"])
        assert p.require_human_approval is True
        assert p.sensitive_tools == ["delete", "send_email"]

    def test_budget_field(self):
        p = PolicyConfig(max_budget=100.0)
        assert p.max_budget == 100.0


# =============================================================================
# Kernel init
# =============================================================================


class TestSmolagentsKernelInit:
    def test_default_policy(self):
        k = SmolagentsKernel()
        assert k._sm_config.max_tool_calls == 50

    def test_explicit_policy(self):
        p = PolicyConfig(max_tool_calls=3)
        k = SmolagentsKernel(policy=p)
        assert k._sm_config.max_tool_calls == 3

    def test_convenience_kwargs(self):
        k = SmolagentsKernel(
            max_tool_calls=7,
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE"],
        )
        assert k._sm_config.max_tool_calls == 7
        assert k._sm_config.blocked_tools == ["shell"]
        assert k._sm_config.blocked_patterns == ["DROP TABLE"]

    def test_initial_counters(self):
        k = SmolagentsKernel()
        assert k._tool_call_count == 0
        assert k._agent_call_count == 0
        assert k._budget_spent == 0.0

    def test_empty_audit_log(self):
        k = SmolagentsKernel()
        assert k.get_audit_log() == []
        assert k.get_violations() == []


# =============================================================================
# Tool-call governance (before_tool_call)
# =============================================================================


class TestBeforeToolCall:
    def test_allow_normal_call(self):
        k = SmolagentsKernel()
        result = k.before_tool_call(tool_name="search", tool_args={"q": "hello"})
        assert result is None

    def test_block_blocked_tool(self):
        k = SmolagentsKernel(blocked_tools=["exec_code"])
        result = k.before_tool_call(tool_name="exec_code")
        assert result is not None
        assert "blocked" in result["error"].lower()
        assert len(k.get_violations()) == 1

    def test_allowed_tools_whitelist(self):
        k = SmolagentsKernel(allowed_tools=["search", "read"])
        # Allowed
        assert k.before_tool_call(tool_name="search") is None
        # Not allowed
        result = k.before_tool_call(tool_name="write")
        assert result is not None
        assert "not in allowed" in result["error"].lower()

    def test_content_filter_blocks_pattern(self):
        k = SmolagentsKernel(blocked_patterns=["DROP TABLE"])
        result = k.before_tool_call(
            tool_name="sql",
            tool_args={"query": "DROP TABLE users"},
        )
        assert result is not None
        assert "blocked pattern" in result["error"].lower()

    def test_content_filter_case_insensitive(self):
        k = SmolagentsKernel(blocked_patterns=["rm -rf"])
        result = k.before_tool_call(
            tool_name="shell",
            tool_args={"cmd": "RM -RF /tmp"},
        )
        assert result is not None

    def test_tool_call_limit(self):
        k = SmolagentsKernel(max_tool_calls=2)
        assert k.before_tool_call(tool_name="a") is None
        assert k.before_tool_call(tool_name="b") is None
        result = k.before_tool_call(tool_name="c")
        assert result is not None
        assert "exceeds limit" in result["error"].lower()

    def test_budget_limit(self):
        k = SmolagentsKernel(max_budget=2.0)
        assert k.before_tool_call(tool_name="a", cost=1.0) is None
        assert k.before_tool_call(tool_name="b", cost=1.0) is None
        result = k.before_tool_call(tool_name="c", cost=1.0)
        assert result is not None
        assert "budget" in result["error"].lower()

    def test_timeout(self):
        k = SmolagentsKernel(timeout_seconds=1)
        k._start_time = time.time() - 2  # simulate elapsed time
        result = k.before_tool_call(tool_name="a")
        assert result is not None
        assert "timeout" in result["error"].lower()

    def test_string_tool_args_content_filter(self):
        k = SmolagentsKernel(blocked_patterns=["secret"])
        result = k.before_tool_call(tool_name="echo", tool_args="this is secret data")
        assert result is not None
        assert "blocked pattern" in result["error"].lower()


# =============================================================================
# After-tool governance
# =============================================================================


class TestAfterToolCall:
    def test_pass_through_clean_result(self):
        k = SmolagentsKernel()
        result = k.after_tool_call(tool_name="search", tool_result="clean data")
        assert result == "clean data"

    def test_block_output_with_pattern(self):
        k = SmolagentsKernel(blocked_patterns=["SSN"])
        result = k.after_tool_call(tool_name="search", tool_result="SSN: 123-45-6789")
        assert "[BLOCKED]" in result
        assert len(k.get_violations()) == 1

    def test_block_dict_output_with_pattern(self):
        k = SmolagentsKernel(blocked_patterns=["password"])
        result = k.after_tool_call(
            tool_name="db",
            tool_result={"data": "password=abc123"},
        )
        assert "error" in result


# =============================================================================
# Human approval
# =============================================================================


class TestHumanApproval:
    def test_approval_required_for_sensitive_tool(self):
        k = SmolagentsKernel(
            require_human_approval=True,
            sensitive_tools=["delete_file"],
        )
        result = k.before_tool_call(tool_name="delete_file", agent_name="agent1")
        assert result is not None
        assert result.get("needs_approval") is True
        assert "call_id" in result
        assert len(k.get_pending_approvals()) == 1

    def test_no_approval_for_non_sensitive_tool(self):
        k = SmolagentsKernel(
            require_human_approval=True,
            sensitive_tools=["delete_file"],
        )
        result = k.before_tool_call(tool_name="search")
        assert result is None

    def test_all_tools_need_approval_when_no_sensitive_list(self):
        k = SmolagentsKernel(require_human_approval=True)
        result = k.before_tool_call(tool_name="anything")
        assert result is not None
        assert result.get("needs_approval") is True

    def test_approve_pending_call(self):
        k = SmolagentsKernel(require_human_approval=True, sensitive_tools=["delete"])
        result = k.before_tool_call(tool_name="delete", agent_name="a")
        call_id = result["call_id"]
        assert k.approve(call_id) is True
        assert len(k.get_pending_approvals()) == 0

    def test_deny_pending_call(self):
        k = SmolagentsKernel(require_human_approval=True, sensitive_tools=["delete"])
        result = k.before_tool_call(tool_name="delete", agent_name="a")
        call_id = result["call_id"]
        assert k.deny(call_id) is True
        assert len(k.get_pending_approvals()) == 0

    def test_approve_nonexistent_returns_false(self):
        k = SmolagentsKernel()
        assert k.approve("nonexistent") is False

    def test_deny_nonexistent_returns_false(self):
        k = SmolagentsKernel()
        assert k.deny("nonexistent") is False


# =============================================================================
# Wrap / Unwrap
# =============================================================================


class TestWrapUnwrap:
    def test_wrap_agent(self):
        tool = FakeTool(name="search")
        agent = FakeAgent(name="assistant", tools=[tool])
        k = SmolagentsKernel()
        wrapped = k.wrap(agent)
        assert wrapped is agent
        assert "assistant" in k._wrapped_agents

    def test_wrapped_tool_forward_is_governed(self):
        tool = FakeTool(name="search")
        agent = FakeAgent(name="assistant", tools=[tool])
        k = SmolagentsKernel()
        k.wrap(agent)
        # The forward method should now be governed
        result = tool.forward()
        assert "result from search" in result
        assert k._tool_call_count == 1

    def test_wrapped_tool_blocked_raises(self):
        tool = FakeTool(name="exec_code")
        agent = FakeAgent(name="assistant", tools=[tool])
        k = SmolagentsKernel(blocked_tools=["exec_code"])
        k.wrap(agent)
        with pytest.raises(PolicyViolationError):
            tool.forward()

    def test_unwrap_restores_original(self):
        tool = FakeTool(name="search")
        agent = FakeAgent(name="assistant", tools=[tool])
        k = SmolagentsKernel()
        # Before wrapping, forward is a regular method
        original_result = tool.forward()
        k.wrap(agent)
        # After wrapping, forward is governed (still works)
        wrapped_result = tool.forward()
        assert k._tool_call_count == 1
        k.unwrap(agent)
        # After unwrapping, forward should work as original (no governance)
        k._tool_call_count = 0
        tool.forward()
        # If unwrap restored the original, tool_call_count stays 0
        assert k._tool_call_count == 0

    def test_wrap_agent_with_dict_toolbox(self):
        """Agent with toolbox as plain dict (no .tools attribute)."""
        tool = FakeTool(name="calc")
        agent = MagicMock()
        agent.name = "dict-agent"
        agent.toolbox = {"calc": tool}
        k = SmolagentsKernel()
        k.wrap(agent)
        assert "dict-agent" in k._wrapped_agents

    def test_wrap_agent_without_toolbox(self):
        """Agent with no toolbox attribute should wrap without error."""
        agent = MagicMock(spec=[])
        agent.name = "empty-agent"
        k = SmolagentsKernel()
        k.wrap(agent)
        assert "empty-agent" in k._wrapped_agents


# =============================================================================
# Audit log & stats
# =============================================================================


class TestAuditAndStats:
    def test_audit_log_records_calls(self):
        k = SmolagentsKernel()
        k.before_tool_call(tool_name="search", agent_name="a")
        k.after_tool_call(tool_name="search", tool_result="data", agent_name="a")
        log = k.get_audit_log()
        assert len(log) == 2
        assert log[0].event_type == "before_tool"
        assert log[1].event_type == "after_tool"

    def test_stats_structure(self):
        k = SmolagentsKernel()
        k.before_tool_call(tool_name="t1")
        stats = k.get_stats()
        assert stats["tool_calls"] == 1
        assert "policy" in stats
        assert "elapsed_seconds" in stats
        assert stats["violations"] == 0

    def test_violation_handler_called(self):
        violations = []
        k = SmolagentsKernel(
            blocked_tools=["bad"],
            on_violation=lambda e: violations.append(e),
        )
        k.before_tool_call(tool_name="bad")
        assert len(violations) == 1
        assert isinstance(violations[0], PolicyViolationError)


# =============================================================================
# Reset
# =============================================================================


class TestReset:
    def test_reset_clears_counters(self):
        k = SmolagentsKernel()
        k.before_tool_call(tool_name="a")
        k.before_tool_call(tool_name="b")
        assert k._tool_call_count == 2
        k.reset()
        assert k._tool_call_count == 0
        assert k._budget_spent == 0.0


# =============================================================================
# Health check
# =============================================================================


class TestHealthCheck:
    def test_healthy_status(self):
        k = SmolagentsKernel()
        h = k.health_check()
        assert h["status"] == "healthy"
        assert h["backend"] == "smolagents"
        assert "smolagents_available" in h

    def test_degraded_after_violation(self):
        k = SmolagentsKernel(blocked_tools=["bad"])
        k.before_tool_call(tool_name="bad")
        h = k.health_check()
        assert h["status"] == "degraded"
        assert h["violations"] == 1


# =============================================================================
# Graceful import handling
# =============================================================================


class TestImportHandling:
    def test_has_smolagents_flag_is_bool(self):
        assert isinstance(_HAS_SMOLAGENTS, bool)

    def test_check_available_raises_when_missing(self):
        if not _HAS_SMOLAGENTS:
            with pytest.raises(ImportError, match="smolagents"):
                _check_smolagents_available()

    def test_kernel_works_without_smolagents(self):
        """The kernel itself should be usable even without smolagents installed."""
        k = SmolagentsKernel()
        assert k.before_tool_call(tool_name="search") is None


# =============================================================================
# PolicyViolationError
# =============================================================================


class TestPolicyViolationError:
    def test_error_attributes(self):
        e = PolicyViolationError("test_policy", "something bad", severity="critical")
        assert e.policy_name == "test_policy"
        assert e.description == "something bad"
        assert e.severity == "critical"
        assert "test_policy" in str(e)

    def test_default_severity(self):
        e = PolicyViolationError("p", "d")
        assert e.severity == "high"


# =============================================================================
# Edge cases
# =============================================================================


class TestEdgeCases:
    def test_multiple_violations_collected(self):
        k = SmolagentsKernel(blocked_tools=["a", "b"])
        k.before_tool_call(tool_name="a")
        k.before_tool_call(tool_name="b")
        assert len(k.get_violations()) == 2

    def test_no_logging_when_disabled(self):
        p = PolicyConfig(log_all_calls=False)
        k = SmolagentsKernel(policy=p)
        k.before_tool_call(tool_name="x")
        assert len(k.get_audit_log()) == 0

    def test_after_tool_call_nonstring_passthrough(self):
        k = SmolagentsKernel()
        result = k.after_tool_call(tool_name="calc", tool_result=42)
        assert result == 42

    def test_wrap_records_audit_event(self):
        tool = FakeTool(name="t")
        agent = FakeAgent(name="a", tools=[tool])
        k = SmolagentsKernel()
        k.wrap(agent)
        events = [e for e in k.get_audit_log() if e.event_type == "agent_wrapped"]
        assert len(events) == 1
