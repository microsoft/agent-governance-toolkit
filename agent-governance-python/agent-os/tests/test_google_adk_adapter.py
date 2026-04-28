# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Google ADK (Agent Development Kit) governance adapter.

No real ADK dependency required — uses mock ToolContext/CallbackContext objects.

Run with: python -m pytest tests/test_google_adk_adapter.py -v --tb=short
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.google_adk_adapter import (
    ADKExecutionContext,
    AuditEvent,
    GovernancePlugin,
    GoogleADKKernel,
    PolicyConfig,
    PolicyViolationError,
    _HAS_ADK,
    _HAS_ADK_PLUGINS,
    _check_adk_available,
)
from agent_os.integrations.base import GovernancePolicy


# =============================================================================
# Fake ADK context objects (no real google.adk dependency)
# =============================================================================


@dataclass
class FakeToolContext:
    tool_name: str = "my_tool"
    tool_args: Dict[str, Any] = field(default_factory=dict)
    agent_name: str = "test-agent"


@dataclass
class FakeCallbackContext:
    agent_name: str = "test-agent"


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
        assert p.pii_detection is True
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


class TestGoogleADKKernelInit:
    def test_default_policy(self):
        k = GoogleADKKernel()
        assert k._adk_config.max_tool_calls == 50

    def test_explicit_policy(self):
        p = PolicyConfig(max_tool_calls=3)
        k = GoogleADKKernel(policy=p)
        assert k._adk_config.max_tool_calls == 3

    def test_convenience_kwargs(self):
        k = GoogleADKKernel(
            max_tool_calls=7,
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE"],
        )
        assert k._adk_config.max_tool_calls == 7
        assert k._adk_config.blocked_tools == ["shell"]
        assert k._adk_config.blocked_patterns == ["DROP TABLE"]

    def test_custom_violation_handler(self):
        captured = []
        k = GoogleADKKernel(on_violation=lambda e: captured.append(e))
        k.before_tool_callback(FakeToolContext(tool_name="blocked"), blocked_tools=None)
        # No violation yet, should be empty
        assert captured == []

    def test_extends_base_integration(self):
        """GoogleADKKernel should extend BaseIntegration."""
        from agent_os.integrations.base import BaseIntegration
        k = GoogleADKKernel()
        assert isinstance(k, BaseIntegration)

    def test_graceful_import_handling(self):
        """_HAS_ADK should be a boolean (True if google-adk is installed, False otherwise)."""
        assert isinstance(_HAS_ADK, bool)

    def test_check_adk_available_when_missing(self):
        """_check_adk_available should raise ImportError when google-adk is not installed."""
        if not _HAS_ADK:
            with pytest.raises(ImportError, match="google-adk"):
                _check_adk_available()


# =============================================================================
# before_tool_callback
# =============================================================================


class TestBeforeToolCallback:
    def test_allowed_tool(self):
        k = GoogleADKKernel()
        result = k.before_tool_callback(FakeToolContext(tool_name="search"))
        assert result is None  # None = allow

    def test_blocked_tool(self):
        k = GoogleADKKernel(blocked_tools=["exec_code", "shell"])
        result = k.before_tool_callback(FakeToolContext(tool_name="exec_code"))
        assert result is not None
        assert "error" in result
        assert "blocked" in result["error"].lower()

    def test_allowed_list_accepts(self):
        k = GoogleADKKernel(allowed_tools=["search", "calculator"])
        result = k.before_tool_callback(FakeToolContext(tool_name="search"))
        assert result is None

    def test_allowed_list_rejects(self):
        k = GoogleADKKernel(allowed_tools=["search", "calculator"])
        result = k.before_tool_callback(FakeToolContext(tool_name="exec_code"))
        assert result is not None
        assert "error" in result

    def test_tool_call_limit(self):
        k = GoogleADKKernel(max_tool_calls=3)
        for _ in range(3):
            assert k.before_tool_callback(FakeToolContext()) is None
        result = k.before_tool_callback(FakeToolContext())
        assert result is not None
        assert "limit" in result["error"].lower()

    def test_content_filter_in_args(self):
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        ctx = FakeToolContext(tool_args={"query": "DROP TABLE users"})
        result = k.before_tool_callback(ctx)
        assert result is not None
        assert "error" in result

    def test_content_filter_case_insensitive(self):
        k = GoogleADKKernel(blocked_patterns=["rm -rf"])
        ctx = FakeToolContext(tool_args={"cmd": "RM -RF /"})
        result = k.before_tool_callback(ctx)
        assert result is not None

    def test_increments_counter(self):
        k = GoogleADKKernel()
        k.before_tool_callback(FakeToolContext())
        k.before_tool_callback(FakeToolContext())
        assert k._tool_call_count == 2

    def test_timeout(self):
        k = GoogleADKKernel(timeout_seconds=1)
        k._start_time = time.time() - 10  # force expired
        result = k.before_tool_callback(FakeToolContext())
        assert result is not None
        assert "timeout" in result["error"].lower()

    def test_kwargs_fallback_when_no_context(self):
        k = GoogleADKKernel(blocked_tools=["shell"])
        result = k.before_tool_callback(tool_name="shell", tool_args={})
        assert result is not None
        assert "blocked" in result["error"].lower()

    def test_records_violation(self):
        k = GoogleADKKernel(blocked_tools=["danger"])
        k.before_tool_callback(FakeToolContext(tool_name="danger"))
        assert len(k.get_violations()) == 1
        assert k.get_violations()[0].policy_name == "tool_filter"


# =============================================================================
# after_tool_callback
# =============================================================================


class TestAfterToolCallback:
    def test_passes_result_through(self):
        k = GoogleADKKernel()
        result = k.after_tool_callback(FakeToolContext(), tool_result={"data": 42})
        assert result == {"data": 42}

    def test_blocks_string_output(self):
        k = GoogleADKKernel(blocked_patterns=["SECRET_TOKEN"])
        result = k.after_tool_callback(FakeToolContext(), tool_result="key=SECRET_TOKEN_123")
        assert "error" in result

    def test_blocks_dict_output(self):
        k = GoogleADKKernel(blocked_patterns=["password"])
        result = k.after_tool_callback(
            FakeToolContext(), tool_result={"msg": "your password is 1234"}
        )
        assert "error" in result

    def test_allows_safe_output(self):
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        result = k.after_tool_callback(FakeToolContext(), tool_result="query succeeded")
        assert result == "query succeeded"

    def test_none_result(self):
        k = GoogleADKKernel()
        result = k.after_tool_callback(FakeToolContext(), tool_result=None)
        assert result is None


# =============================================================================
# before_agent_callback
# =============================================================================


class TestBeforeAgentCallback:
    def test_allows_agent(self):
        k = GoogleADKKernel()
        result = k.before_agent_callback(FakeCallbackContext())
        assert result is None

    def test_agent_call_limit(self):
        k = GoogleADKKernel(max_agent_calls=2)
        assert k.before_agent_callback(FakeCallbackContext()) is None
        assert k.before_agent_callback(FakeCallbackContext()) is None
        result = k.before_agent_callback(FakeCallbackContext())
        assert result is not None
        assert "error" in result

    def test_timeout(self):
        k = GoogleADKKernel(timeout_seconds=1)
        k._start_time = time.time() - 10
        result = k.before_agent_callback(FakeCallbackContext())
        assert result is not None
        assert "timeout" in result["error"].lower()

    def test_increments_counter(self):
        k = GoogleADKKernel()
        k.before_agent_callback(FakeCallbackContext())
        k.before_agent_callback(FakeCallbackContext())
        assert k._agent_call_count == 2


# =============================================================================
# after_agent_callback
# =============================================================================


class TestAfterAgentCallback:
    def test_passes_content_through(self):
        k = GoogleADKKernel()
        result = k.after_agent_callback(FakeCallbackContext(), content="Hello world")
        assert result == "Hello world"

    def test_blocks_string_content(self):
        k = GoogleADKKernel(blocked_patterns=["rm -rf"])
        result = k.after_agent_callback(FakeCallbackContext(), content="run rm -rf /")
        assert "error" in result

    def test_allows_safe_content(self):
        k = GoogleADKKernel(blocked_patterns=["DROP"])
        result = k.after_agent_callback(FakeCallbackContext(), content="All good")
        assert result == "All good"

    def test_none_content(self):
        k = GoogleADKKernel()
        result = k.after_agent_callback(FakeCallbackContext(), content=None)
        assert result is None


# =============================================================================
# Human Approval Flow
# =============================================================================


class TestHumanApproval:
    def test_no_approval_needed_by_default(self):
        k = GoogleADKKernel()
        result = k.before_tool_callback(FakeToolContext(tool_name="search"))
        assert result is None

    def test_approval_required_for_all_tools(self):
        k = GoogleADKKernel(require_human_approval=True)
        result = k.before_tool_callback(FakeToolContext(tool_name="search"))
        assert result is not None
        assert result.get("needs_approval") is True
        assert "call_id" in result

    def test_approval_required_only_for_sensitive_tools(self):
        k = GoogleADKKernel(
            require_human_approval=True,
            sensitive_tools=["delete_file", "send_email"],
        )
        # Non-sensitive tool: allowed
        result = k.before_tool_callback(FakeToolContext(tool_name="search"))
        assert result is None
        # Sensitive tool: needs approval
        result = k.before_tool_callback(FakeToolContext(tool_name="delete_file"))
        assert result is not None
        assert result.get("needs_approval") is True

    def test_approve_pending_call(self):
        k = GoogleADKKernel(require_human_approval=True, sensitive_tools=["delete_file"])
        result = k.before_tool_callback(FakeToolContext(tool_name="delete_file"))
        call_id = result["call_id"]

        assert len(k.get_pending_approvals()) == 1
        assert k.approve(call_id) is True
        assert len(k.get_pending_approvals()) == 0

    def test_deny_pending_call(self):
        k = GoogleADKKernel(require_human_approval=True, sensitive_tools=["send_email"])
        result = k.before_tool_callback(FakeToolContext(tool_name="send_email"))
        call_id = result["call_id"]

        assert k.deny(call_id) is True
        assert len(k.get_pending_approvals()) == 0

    def test_approve_nonexistent_call_returns_false(self):
        k = GoogleADKKernel()
        assert k.approve("nonexistent") is False

    def test_deny_nonexistent_call_returns_false(self):
        k = GoogleADKKernel()
        assert k.deny("nonexistent") is False

    def test_approval_logs_audit_events(self):
        k = GoogleADKKernel(require_human_approval=True, sensitive_tools=["delete_file"])
        result = k.before_tool_callback(FakeToolContext(tool_name="delete_file"))
        call_id = result["call_id"]
        k.approve(call_id)

        event_types = [e.event_type for e in k.get_audit_log()]
        assert "approval_required" in event_types
        assert "approval_granted" in event_types

    def test_denial_logs_audit_events(self):
        k = GoogleADKKernel(require_human_approval=True, sensitive_tools=["delete_file"])
        result = k.before_tool_callback(FakeToolContext(tool_name="delete_file"))
        call_id = result["call_id"]
        k.deny(call_id)

        event_types = [e.event_type for e in k.get_audit_log()]
        assert "approval_denied" in event_types


# =============================================================================
# Budget Limits
# =============================================================================


class TestBudgetLimits:
    def test_no_budget_by_default(self):
        k = GoogleADKKernel()
        assert k._adk_config.max_budget is None
        # Should not block any calls
        for _ in range(10):
            assert k.before_tool_callback(FakeToolContext()) is None

    def test_budget_enforced(self):
        k = GoogleADKKernel(max_budget=3.0)
        # Each call costs 1.0 by default
        assert k.before_tool_callback(FakeToolContext()) is None  # spent=1
        assert k.before_tool_callback(FakeToolContext()) is None  # spent=2
        assert k.before_tool_callback(FakeToolContext()) is None  # spent=3
        result = k.before_tool_callback(FakeToolContext())  # would be 4 > 3
        assert result is not None
        assert "budget" in result["error"].lower()

    def test_budget_custom_cost(self):
        k = GoogleADKKernel(max_budget=5.0)
        assert k.before_tool_callback(FakeToolContext(), cost=3.0) is None  # spent=3
        result = k.before_tool_callback(FakeToolContext(), cost=3.0)  # 3+3=6 > 5
        assert result is not None
        assert "budget" in result["error"].lower()

    def test_budget_tracked_in_stats(self):
        k = GoogleADKKernel(max_budget=10.0)
        k.before_tool_callback(FakeToolContext(), cost=2.5)
        stats = k.get_stats()
        assert stats["budget_spent"] == 2.5
        assert stats["budget_limit"] == 10.0

    def test_budget_resets(self):
        k = GoogleADKKernel(max_budget=2.0)
        k.before_tool_callback(FakeToolContext())
        k.before_tool_callback(FakeToolContext())
        # Budget exhausted
        result = k.before_tool_callback(FakeToolContext())
        assert result is not None

        k.reset()
        # After reset, budget is fresh
        assert k.before_tool_callback(FakeToolContext()) is None


# =============================================================================
# Wrap / Unwrap
# =============================================================================


class TestWrapUnwrap:
    def test_wrap_injects_callbacks(self):
        k = GoogleADKKernel()
        agent = MagicMock()
        agent.name = "test-agent"
        agent.before_tool_callback = None
        agent.after_tool_callback = None
        agent.before_agent_callback = None
        agent.after_agent_callback = None

        wrapped = k.wrap(agent)
        assert wrapped.before_tool_callback is not None
        assert wrapped.after_tool_callback is not None
        assert callable(wrapped.before_tool_callback)

    def test_unwrap_clears_callbacks(self):
        k = GoogleADKKernel()
        agent = MagicMock()
        agent.name = "test-agent"
        agent.before_tool_callback = None
        agent.after_tool_callback = None
        agent.before_agent_callback = None
        agent.after_agent_callback = None

        k.wrap(agent)
        k.unwrap(agent)
        assert agent.before_tool_callback is None
        assert agent.after_tool_callback is None

    def test_wrap_logs_audit_event(self):
        k = GoogleADKKernel()
        agent = MagicMock()
        agent.name = "my-agent"
        agent.before_tool_callback = None

        k.wrap(agent)
        events = k.get_audit_log()
        assert any(e.event_type == "agent_wrapped" for e in events)

    def test_wrap_returns_same_agent(self):
        """wrap() modifies in-place and returns the same agent reference."""
        k = GoogleADKKernel()
        agent = MagicMock()
        agent.name = "a"
        agent.before_tool_callback = None

        wrapped = k.wrap(agent)
        assert wrapped is agent


# =============================================================================
# Audit & Stats
# =============================================================================


class TestAuditAndStats:
    def test_audit_log_records_events(self):
        k = GoogleADKKernel()
        k.before_tool_callback(FakeToolContext(tool_name="search", agent_name="a1"))
        k.after_tool_callback(FakeToolContext(tool_name="search", agent_name="a1"), tool_result="ok")
        k.before_agent_callback(FakeCallbackContext(agent_name="a1"))
        k.after_agent_callback(FakeCallbackContext(agent_name="a1"), content="done")

        log = k.get_audit_log()
        assert len(log) == 4
        assert log[0].event_type == "before_tool"
        assert log[1].event_type == "after_tool"
        assert log[2].event_type == "before_agent"
        assert log[3].event_type == "after_agent"

    def test_audit_log_disabled(self):
        p = PolicyConfig(log_all_calls=False)
        k = GoogleADKKernel(policy=p)
        k.before_tool_callback(FakeToolContext())
        assert len(k.get_audit_log()) == 0

    def test_audit_event_fields(self):
        k = GoogleADKKernel()
        k.before_tool_callback(FakeToolContext(tool_name="calc", agent_name="bot"))
        event = k.get_audit_log()[0]
        assert isinstance(event, AuditEvent)
        assert event.agent_name == "bot"
        assert event.details["tool"] == "calc"
        assert event.timestamp > 0

    def test_stats(self):
        k = GoogleADKKernel(max_tool_calls=10, blocked_tools=["shell"])
        k.before_tool_callback(FakeToolContext(tool_name="search"))
        k.before_tool_callback(FakeToolContext(tool_name="shell"))  # violation
        k.before_agent_callback(FakeCallbackContext())

        stats = k.get_stats()
        assert stats["tool_calls"] == 2
        assert stats["agent_calls"] == 1
        assert stats["violations"] == 1
        assert stats["audit_events"] == 3
        assert stats["elapsed_seconds"] >= 0

    def test_reset(self):
        k = GoogleADKKernel(max_tool_calls=2)
        k.before_tool_callback(FakeToolContext())
        k.before_tool_callback(FakeToolContext())
        # Limit reached
        result = k.before_tool_callback(FakeToolContext())
        assert result is not None

        k.reset()
        # After reset, counter is fresh
        result = k.before_tool_callback(FakeToolContext())
        assert result is None
        assert k._tool_call_count == 1

    def test_violations_list(self):
        k = GoogleADKKernel(blocked_tools=["exec", "shell"])
        k.before_tool_callback(FakeToolContext(tool_name="exec"))
        k.before_tool_callback(FakeToolContext(tool_name="shell"))
        v = k.get_violations()
        assert len(v) == 2
        assert all(isinstance(e, PolicyViolationError) for e in v)

    def test_stats_include_approval_and_budget(self):
        k = GoogleADKKernel(
            require_human_approval=True,
            sensitive_tools=["delete"],
            max_budget=100.0,
        )
        stats = k.get_stats()
        assert "pending_approvals" in stats
        assert "budget_spent" in stats
        assert "budget_limit" in stats
        assert stats["policy"]["require_human_approval"] is True
        assert stats["policy"]["sensitive_tools"] == ["delete"]


# =============================================================================
# get_callbacks()
# =============================================================================


class TestGetCallbacks:
    def test_returns_four_callbacks(self):
        k = GoogleADKKernel()
        cbs = k.get_callbacks()
        assert "before_tool_callback" in cbs
        assert "after_tool_callback" in cbs
        assert "before_agent_callback" in cbs
        assert "after_agent_callback" in cbs

    def test_callbacks_are_callable(self):
        k = GoogleADKKernel()
        cbs = k.get_callbacks()
        for name, cb in cbs.items():
            assert callable(cb), f"{name} is not callable"

    def test_unpack_into_agent(self):
        """Simulate **kernel.get_callbacks() usage for LlmAgent constructor."""
        k = GoogleADKKernel(blocked_tools=["danger"])
        cbs = k.get_callbacks()

        # Simulate ADK calling the callbacks
        result = cbs["before_tool_callback"](FakeToolContext(tool_name="danger"))
        assert result is not None
        assert "error" in result


# =============================================================================
# Health Check
# =============================================================================


class TestHealthCheck:
    def test_healthy_by_default(self):
        k = GoogleADKKernel()
        health = k.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "google_adk"
        assert isinstance(health["adk_available"], bool)
        assert health["violations"] == 0

    def test_degraded_after_violation(self):
        k = GoogleADKKernel(blocked_tools=["shell"])
        k.before_tool_callback(FakeToolContext(tool_name="shell"))
        health = k.health_check()
        assert health["status"] == "degraded"
        assert health["violations"] == 1

    def test_health_includes_uptime(self):
        k = GoogleADKKernel()
        health = k.health_check()
        assert "uptime_seconds" in health
        assert health["uptime_seconds"] >= 0


# =============================================================================
# Error Handling
# =============================================================================


class TestErrorHandling:
    def test_policy_violation_error_attributes(self):
        e = PolicyViolationError("test_policy", "something bad", severity="critical")
        assert e.policy_name == "test_policy"
        assert e.description == "something bad"
        assert e.severity == "critical"
        assert "test_policy" in str(e)

    def test_violation_handler_receives_errors(self):
        violations = []
        k = GoogleADKKernel(
            blocked_tools=["shell"],
            on_violation=lambda e: violations.append(e),
        )
        k.before_tool_callback(FakeToolContext(tool_name="shell"))
        assert len(violations) == 1
        assert isinstance(violations[0], PolicyViolationError)

    def test_multiple_violations_accumulated(self):
        k = GoogleADKKernel(blocked_tools=["a", "b", "c"])
        k.before_tool_callback(FakeToolContext(tool_name="a"))
        k.before_tool_callback(FakeToolContext(tool_name="b"))
        k.before_tool_callback(FakeToolContext(tool_name="c"))
        assert len(k.get_violations()) == 3


# =============================================================================
# Integration: full lifecycle
# =============================================================================


class TestIntegration:
    def test_full_lifecycle(self):
        """Simulate a complete agent run with multiple tool calls."""
        violations = []
        k = GoogleADKKernel(
            max_tool_calls=5,
            blocked_tools=["shell"],
            blocked_patterns=["SECRET"],
            on_violation=lambda e: violations.append(e),
        )

        # Agent starts
        assert k.before_agent_callback(FakeCallbackContext(agent_name="assistant")) is None

        # Tool 1: allowed
        assert k.before_tool_callback(
            FakeToolContext(tool_name="search", tool_args={"q": "weather"}, agent_name="assistant")
        ) is None
        assert k.after_tool_callback(
            FakeToolContext(tool_name="search", agent_name="assistant"),
            tool_result="Sunny, 72°F",
        ) == "Sunny, 72°F"

        # Tool 2: blocked tool
        result = k.before_tool_callback(
            FakeToolContext(tool_name="shell", tool_args={"cmd": "ls"}, agent_name="assistant")
        )
        assert result is not None

        # Tool 3: blocked content in args
        result = k.before_tool_callback(
            FakeToolContext(
                tool_name="search",
                tool_args={"q": "find SECRET key"},
                agent_name="assistant",
            )
        )
        assert result is not None

        # Tool 4: allowed tool but blocked output
        assert k.before_tool_callback(
            FakeToolContext(tool_name="db_query", tool_args={"q": "SELECT *"}, agent_name="assistant")
        ) is None
        result = k.after_tool_callback(
            FakeToolContext(tool_name="db_query", agent_name="assistant"),
            tool_result="SECRET_API_KEY=abc123",
        )
        assert "error" in result

        # Agent finishes
        final = k.after_agent_callback(
            FakeCallbackContext(agent_name="assistant"),
            content="The weather is sunny.",
        )
        assert final == "The weather is sunny."

        # Verify stats
        assert k._tool_call_count == 4
        assert k._agent_call_count == 1
        assert len(violations) == 3  # blocked tool + content in args + output filter
        assert len(k.get_audit_log()) >= 6

    def test_full_lifecycle_with_approval(self):
        """End-to-end test with human approval in the loop."""
        k = GoogleADKKernel(
            require_human_approval=True,
            sensitive_tools=["delete_file"],
            blocked_tools=["shell"],
        )

        # Non-sensitive tool: allowed immediately
        assert k.before_tool_callback(FakeToolContext(tool_name="search")) is None

        # Sensitive tool: blocked pending approval
        result = k.before_tool_callback(FakeToolContext(tool_name="delete_file"))
        assert result is not None
        assert result["needs_approval"] is True
        call_id = result["call_id"]

        # Approve and verify audit trail
        assert k.approve(call_id) is True
        audit_types = [e.event_type for e in k.get_audit_log()]
        assert "approval_required" in audit_types
        assert "approval_granted" in audit_types

        # Blocked tool still blocked (not just approval-gated)
        result = k.before_tool_callback(FakeToolContext(tool_name="shell"))
        assert result is not None
        assert "blocked" in result["error"].lower()


# =============================================================================
# Fake ADK objects for Plugin testing
# =============================================================================


@dataclass
class FakeInvocationContext:
    """Simulates ADK InvocationContext."""
    invocation_id: str = "inv-001"
    session_id: str = "sess-001"
    agent_name: str = "root-agent"


@dataclass
class FakePart:
    text: str = "hello world"


@dataclass
class FakeContent:
    parts: list = field(default_factory=lambda: [FakePart(text="hello")])
    role: str = "user"


@dataclass
class FakeAgent:
    name: str = "my-agent"


@dataclass
class FakeUsageMetadata:
    """Simulates Gemini-style usage metadata."""
    prompt_token_count: int = 100
    candidates_token_count: int = 50


@dataclass
class FakeLlmResponse:
    usage_metadata: Optional[FakeUsageMetadata] = None


@dataclass
class FakeEvent:
    author: str = "agent"


# =============================================================================
# ADKExecutionContext tests
# =============================================================================


class TestADKExecutionContext:
    def test_construction_defaults(self):
        ctx = ADKExecutionContext(
            agent_id="test-agent",
            session_id="sess-123",
            policy=GovernancePolicy(name="test"),
        )
        assert ctx.invocation_id == ""
        assert ctx.agent_names == []
        assert ctx.run_history == []
        assert ctx.prompt_tokens == 0
        assert ctx.completion_tokens == 0
        assert ctx.model_calls == 0
        assert ctx.cancelled is False

    def test_construction_with_values(self):
        ctx = ADKExecutionContext(
            agent_id="test-agent",
            session_id="sess-123",
            policy=GovernancePolicy(name="test"),
            invocation_id="inv-42",
            prompt_tokens=100,
            completion_tokens=50,
            model_calls=3,
            cancelled=True,
        )
        assert ctx.invocation_id == "inv-42"
        assert ctx.prompt_tokens == 100
        assert ctx.completion_tokens == 50
        assert ctx.model_calls == 3
        assert ctx.cancelled is True

    def test_inherits_execution_context(self):
        from agent_os.integrations.base import ExecutionContext

        assert issubclass(ADKExecutionContext, ExecutionContext)

    def test_validation_from_parent(self):
        """Parent ExecutionContext validation still applies."""
        with pytest.raises(ValueError, match="agent_id"):
            ADKExecutionContext(
                agent_id="",
                session_id="sess",
                policy=GovernancePolicy(name="test"),
            )


# =============================================================================
# SIGKILL / Cancellation tests
# =============================================================================


class TestSIGKILL:
    def test_cancel_run(self):
        k = GoogleADKKernel()
        assert k.is_cancelled("inv-001") is False
        k.cancel_run("inv-001")
        assert k.is_cancelled("inv-001") is True

    def test_cancel_marks_context(self):
        k = GoogleADKKernel()
        ctx = ADKExecutionContext(
            agent_id="test",
            session_id="sess",
            policy=GovernancePolicy(name="test"),
            invocation_id="inv-002",
        )
        k._contexts["inv-002"] = ctx
        assert ctx.cancelled is False
        k.cancel_run("inv-002")
        assert ctx.cancelled is True

    def test_cancel_records_audit(self):
        k = GoogleADKKernel()
        k.cancel_run("inv-003")
        events = [e for e in k.get_audit_log() if e.event_type == "run_cancelled"]
        assert len(events) == 1
        assert events[0].details["invocation_id"] == "inv-003"

    def test_multiple_cancels_idempotent(self):
        k = GoogleADKKernel()
        k.cancel_run("inv-004")
        k.cancel_run("inv-004")
        assert k.is_cancelled("inv-004") is True


# =============================================================================
# GovernancePlugin tests
# =============================================================================


class TestGovernancePlugin:
    def _make_plugin(self, **kwargs):
        k = GoogleADKKernel(**kwargs)
        p = k.as_plugin()
        return k, p

    def test_as_plugin_returns_governance_plugin(self):
        k, p = self._make_plugin()
        assert isinstance(p, GovernancePlugin)
        assert p.plugin_name == "governance"

    def test_custom_name(self):
        k = GoogleADKKernel()
        p = k.as_plugin(name="my-gov")
        assert p.plugin_name == "my-gov"

    @pytest.mark.asyncio
    async def test_before_run_creates_context(self):
        k, p = self._make_plugin()
        inv = FakeInvocationContext(invocation_id="inv-10")
        result = await p.before_run_callback(invocation_context=inv)
        assert result is None
        assert "inv-10" in k._contexts
        ctx = k._contexts["inv-10"]
        assert ctx.invocation_id == "inv-10"

    @pytest.mark.asyncio
    async def test_before_run_blocked_when_cancelled(self):
        k, p = self._make_plugin()
        k.cancel_run("inv-11")
        inv = FakeInvocationContext(invocation_id="inv-11")
        result = await p.before_run_callback(invocation_context=inv)
        assert result is not None
        assert "cancelled" in str(result["error"]).lower()

    @pytest.mark.asyncio
    async def test_before_model_increments_count(self):
        k, p = self._make_plugin()
        ctx = FakeCallbackContext(agent_name="test-agent")
        ctx.invocation_id = "inv-20"  # type: ignore[attr-defined]
        await p.before_model_callback(callback_context=ctx)
        assert k._model_call_count == 1
        await p.before_model_callback(callback_context=ctx)
        assert k._model_call_count == 2

    @pytest.mark.asyncio
    async def test_after_model_tracks_tokens(self):
        k, p = self._make_plugin()
        # Create context so token tracking works
        inv = FakeInvocationContext(invocation_id="inv-30")
        await p.before_run_callback(invocation_context=inv)

        ctx = FakeCallbackContext(agent_name="test-agent")
        ctx.invocation_id = "inv-30"  # type: ignore[attr-defined]
        resp = FakeLlmResponse(usage_metadata=FakeUsageMetadata(
            prompt_token_count=100, candidates_token_count=50
        ))
        await p.after_model_callback(callback_context=ctx, llm_response=resp)

        assert k._prompt_tokens == 100
        assert k._completion_tokens == 50
        exec_ctx = k._contexts["inv-30"]
        assert exec_ctx.prompt_tokens == 100
        assert exec_ctx.completion_tokens == 50

    @pytest.mark.asyncio
    async def test_after_model_graceful_no_usage(self):
        k, p = self._make_plugin()
        ctx = FakeCallbackContext(agent_name="test-agent")
        resp = FakeLlmResponse(usage_metadata=None)
        # Should not raise
        await p.after_model_callback(callback_context=ctx, llm_response=resp)
        assert k._prompt_tokens == 0
        assert k._completion_tokens == 0

    @pytest.mark.asyncio
    async def test_on_model_error_records_audit(self):
        k, p = self._make_plugin()
        ctx = FakeCallbackContext(agent_name="test-agent")
        err = RuntimeError("boom")
        result = await p.on_model_error_callback(
            callback_context=ctx, llm_request=None, error=err
        )
        assert result is None  # don't swallow the error
        events = [e for e in k.get_audit_log() if e.event_type == "model_error"]
        assert len(events) == 1
        assert "boom" in events[0].details["error"]

    @pytest.mark.asyncio
    async def test_before_tool_delegates_to_kernel(self):
        k, p = self._make_plugin(blocked_tools=["shell"])
        tool = FakeAgent(name="shell")
        result = await p.before_tool_callback(
            tool=tool, tool_args={}, tool_context=FakeToolContext(tool_name="shell")
        )
        assert result is not None
        assert "blocked" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_before_tool_cancelled(self):
        k, p = self._make_plugin()
        k.cancel_run("inv-40")
        ctx = FakeToolContext()
        ctx.invocation_id = "inv-40"  # type: ignore[attr-defined]
        result = await p.before_tool_callback(
            tool=FakeAgent(name="safe_tool"), tool_args={}, tool_context=ctx
        )
        assert result is not None
        assert "cancelled" in str(result["error"]).lower()

    @pytest.mark.asyncio
    async def test_after_tool_delegates_to_kernel(self):
        k, p = self._make_plugin(blocked_patterns=["DROP TABLE"])
        tool = FakeAgent(name="sql")
        result = await p.after_tool_callback(
            tool=tool, tool_args={}, tool_context=FakeToolContext(),
            tool_result="DROP TABLE users"
        )
        assert result is not None  # blocked

    @pytest.mark.asyncio
    async def test_on_tool_error_records_audit(self):
        k, p = self._make_plugin()
        tool = FakeAgent(name="broken_tool")
        err = ValueError("tool failed")
        result = await p.on_tool_error_callback(
            tool=tool, tool_args={}, tool_context=FakeToolContext(), error=err
        )
        assert result is None
        events = [e for e in k.get_audit_log() if e.event_type == "tool_error"]
        assert len(events) == 1
        assert events[0].details["tool"] == "broken_tool"

    @pytest.mark.asyncio
    async def test_before_agent_tracks_name(self):
        k, p = self._make_plugin()
        # Setup context
        inv = FakeInvocationContext(invocation_id="inv-50")
        await p.before_run_callback(invocation_context=inv)

        agent = FakeAgent(name="report-agent")
        ctx = FakeCallbackContext(agent_name="report-agent")
        ctx.invocation_id = "inv-50"  # type: ignore[attr-defined]
        await p.before_agent_callback(agent=agent, callback_context=ctx)

        exec_ctx = k._contexts["inv-50"]
        assert "report-agent" in exec_ctx.agent_names

    @pytest.mark.asyncio
    async def test_after_agent_records_audit(self):
        k, p = self._make_plugin()
        agent = FakeAgent(name="search-agent")
        await p.after_agent_callback(agent=agent, callback_context=FakeCallbackContext())
        events = [e for e in k.get_audit_log() if e.event_type == "after_agent"]
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_on_event_records_audit(self):
        k, p = self._make_plugin()
        event = FakeEvent(author="my-agent")
        await p.on_event_callback(
            invocation_context=FakeInvocationContext(), event=event
        )
        events = [e for e in k.get_audit_log() if e.event_type == "event"]
        assert len(events) == 1
        assert events[0].agent_name == "my-agent"

    @pytest.mark.asyncio
    async def test_after_run_records_summary(self):
        k, p = self._make_plugin()
        # Setup full lifecycle
        inv = FakeInvocationContext(invocation_id="inv-60")
        await p.before_run_callback(invocation_context=inv)
        await p.after_run_callback(invocation_context=inv)

        events = [e for e in k.get_audit_log() if e.event_type == "run_completed"]
        assert len(events) == 1
        assert events[0].details["invocation_id"] == "inv-60"

    @pytest.mark.asyncio
    async def test_on_user_message_flags_violation(self):
        violations = []
        k = GoogleADKKernel(
            blocked_patterns=["DROP TABLE"],
            on_violation=lambda v: violations.append(v),
        )
        p = k.as_plugin()
        inv = FakeInvocationContext()
        msg = FakeContent(parts=[FakePart(text="DROP TABLE users")])
        await p.on_user_message_callback(
            invocation_context=inv, user_message=msg
        )
        assert len(violations) > 0

    @pytest.mark.asyncio
    async def test_full_plugin_lifecycle(self):
        """End-to-end: run → agent → model → tool → complete."""
        k, p = self._make_plugin()
        inv = FakeInvocationContext(invocation_id="inv-100")

        # 1. Start run
        await p.before_run_callback(invocation_context=inv)
        assert "inv-100" in k._contexts

        # 2. Before agent
        agent = FakeAgent(name="worker")
        cb = FakeCallbackContext(agent_name="worker")
        cb.invocation_id = "inv-100"  # type: ignore[attr-defined]
        await p.before_agent_callback(agent=agent, callback_context=cb)

        # 3. Model call
        await p.before_model_callback(callback_context=cb)
        resp = FakeLlmResponse(usage_metadata=FakeUsageMetadata(
            prompt_token_count=200, candidates_token_count=80
        ))
        await p.after_model_callback(callback_context=cb, llm_response=resp)

        # 4. After agent
        await p.after_agent_callback(agent=agent, callback_context=cb)

        # 5. End run
        await p.after_run_callback(invocation_context=inv)

        # Verify final state
        ctx = k._contexts["inv-100"]
        assert "worker" in ctx.agent_names
        assert ctx.model_calls == 1
        assert ctx.prompt_tokens == 200
        assert ctx.completion_tokens == 80
        assert k.health_check()["model_calls"] == 1


# =============================================================================
# Enhanced health_check tests
# =============================================================================


class TestEnhancedHealthCheck:
    def test_includes_new_fields(self):
        k = GoogleADKKernel()
        health = k.health_check()
        assert "model_calls" in health
        assert "token_usage" in health
        assert "cancelled_runs" in health
        assert "context_count" in health
        assert "adk_plugins_available" in health

    def test_token_usage_structure(self):
        k = GoogleADKKernel()
        health = k.health_check()
        usage = health["token_usage"]
        assert "prompt" in usage
        assert "completion" in usage
        assert "total" in usage
        assert usage["total"] == usage["prompt"] + usage["completion"]

    def test_cancelled_runs_count(self):
        k = GoogleADKKernel()
        assert k.health_check()["cancelled_runs"] == 0
        k.cancel_run("inv-1")
        k.cancel_run("inv-2")
        assert k.health_check()["cancelled_runs"] == 2

    def test_model_calls_tracked(self):
        k = GoogleADKKernel()
        assert k.health_check()["model_calls"] == 0
        k._model_call_count = 5
        assert k.health_check()["model_calls"] == 5

    def test_reset_clears_model_counters(self):
        k = GoogleADKKernel()
        k._model_call_count = 10
        k._prompt_tokens = 500
        k._completion_tokens = 200
        k.reset()
        assert k._model_call_count == 0
        assert k._prompt_tokens == 0
        assert k._completion_tokens == 0


# ── Edge-Case / Robustness Tests ─────────────────────────────────────

class TestEdgeCases:
    """Edge-case tests for malformed inputs, boundary conditions,
    and graceful degradation — requested by CI review bots."""

    # -- Malformed user_message inputs --

    @pytest.mark.asyncio
    async def test_user_message_none_parts(self):
        """on_user_message_callback handles user_message with parts=None."""
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        plugin = k.as_plugin()
        msg = MagicMock()
        msg.parts = None
        inv = MagicMock()
        inv.invocation_id = "inv-edge-1"
        result = await plugin.on_user_message_callback(
            invocation_context=inv, user_message=msg
        )
        assert result is None  # no crash, no false positive

    @pytest.mark.asyncio
    async def test_user_message_parts_is_string(self):
        """on_user_message_callback handles parts being a raw string (not list)."""
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        plugin = k.as_plugin()
        msg = MagicMock()
        msg.parts = "this is not a list"
        inv = MagicMock()
        inv.invocation_id = "inv-edge-2"
        result = await plugin.on_user_message_callback(
            invocation_context=inv, user_message=msg
        )
        assert result is None  # graceful degradation

    @pytest.mark.asyncio
    async def test_user_message_parts_is_integer(self):
        """on_user_message_callback handles parts being an integer."""
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        plugin = k.as_plugin()
        msg = MagicMock()
        msg.parts = 42
        inv = MagicMock()
        inv.invocation_id = "inv-edge-3"
        result = await plugin.on_user_message_callback(
            invocation_context=inv, user_message=msg
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_user_message_missing_parts_attr(self):
        """on_user_message_callback handles user_message without parts attr."""
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        plugin = k.as_plugin()
        msg = object()  # no .parts at all
        inv = MagicMock()
        inv.invocation_id = "inv-edge-4"
        result = await plugin.on_user_message_callback(
            invocation_context=inv, user_message=msg
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_user_message_parts_with_no_text(self):
        """Parts that lack a .text attribute are silently skipped."""
        k = GoogleADKKernel(blocked_patterns=["DROP TABLE"])
        plugin = k.as_plugin()
        part_no_text = MagicMock(spec=[])  # no attributes at all
        msg = MagicMock()
        msg.parts = [part_no_text]
        inv = MagicMock()
        inv.invocation_id = "inv-edge-5"
        result = await plugin.on_user_message_callback(
            invocation_context=inv, user_message=msg
        )
        assert result is None

    # -- ADKExecutionContext boundary conditions --

    def test_context_empty_invocation_id(self):
        """ADKExecutionContext works with an empty invocation_id."""
        ctx = ADKExecutionContext(
            agent_id="test", session_id="sess",
            policy=GovernancePolicy(), invocation_id=""
        )
        assert ctx.invocation_id == ""
        assert ctx.cancelled is False

    def test_context_large_token_counts(self):
        """ADKExecutionContext supports very large token counts."""
        ctx = ADKExecutionContext(
            agent_id="test", session_id="sess",
            policy=GovernancePolicy(),
            prompt_tokens=10**9, completion_tokens=10**9,
            model_calls=10**6,
        )
        assert ctx.prompt_tokens == 10**9
        assert ctx.completion_tokens == 10**9
        assert ctx.model_calls == 10**6

    # -- cancel_run edge cases --

    def test_cancel_run_nonexistent_context(self):
        """cancel_run for an ID with no context doesn't raise."""
        k = GoogleADKKernel()
        # No context exists for this ID — should not raise
        k.cancel_run("does-not-exist")
        assert k.is_cancelled("does-not-exist")

    def test_cancel_run_empty_string_id(self):
        """cancel_run works with empty string invocation ID."""
        k = GoogleADKKernel()
        k.cancel_run("")
        assert k.is_cancelled("")

    # -- GovernancePlugin fallback base class --

    def test_governance_plugin_is_class(self):
        """GovernancePlugin is always a usable class regardless of ADK install."""
        assert isinstance(GovernancePlugin, type)
        k = GoogleADKKernel()
        plugin = k.as_plugin()
        assert hasattr(plugin, "before_run_callback")
        assert hasattr(plugin, "after_run_callback")
        assert hasattr(plugin, "before_tool_callback")
        assert hasattr(plugin, "after_tool_callback")

    # -- health_check resilience --

    def test_health_check_negative_counters(self):
        """health_check returns data even if counters are unexpected values."""
        k = GoogleADKKernel()
        k._model_call_count = -1  # shouldn't happen, but shouldn't crash
        k._prompt_tokens = -100
        hc = k.health_check()
        assert hc["model_calls"] == -1
        assert hc["token_usage"]["prompt"] == -100
        assert "status" in hc

    @pytest.mark.asyncio
    async def test_before_tool_malformed_tool_context(self):
        """before_tool_callback handles tool_context without expected attrs."""
        k = GoogleADKKernel(blocked_tools=["shell"])
        plugin = k.as_plugin()
        inv = MagicMock()
        inv.invocation_id = "inv-edge-6"
        # tool_context without .function_name or .tool_name
        tc = object()
        result = await plugin.before_tool_callback(
            tool=MagicMock(name="safe_tool"),
            tool_args={"input": "hello"},
            tool_context=tc,
        )
        # Should not crash — falls back to tool.name or "unknown"
        assert result is None or isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_on_model_error_none_error(self):
        """on_model_error_callback handles error=None gracefully."""
        k = GoogleADKKernel()
        plugin = k.as_plugin()
        result = await plugin.on_model_error_callback(
            callback_context=MagicMock(),
            llm_request=None,
            error=None,
        )
        assert result is None
        # Should have recorded an audit event with "unknown" error
        assert any(e.event_type == "model_error" for e in k._audit_log)
