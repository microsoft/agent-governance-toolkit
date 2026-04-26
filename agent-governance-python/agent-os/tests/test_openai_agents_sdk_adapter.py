# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration tests for OpenAI Agents SDK governance adapter.

No real OpenAI Agents SDK dependency required — uses mock Agent/Runner objects.

Run with: python -m pytest tests/test_openai_agents_sdk_adapter.py -v --tb=short
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_os.integrations.openai_agents_sdk import (
    ExecutionContext,
    GovernancePolicy,
    OpenAIAgentsKernel,
    PolicyViolationError,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_agent(name="assistant", model="gpt-4o", tools=None):
    """Create a mock OpenAI Agent."""
    agent = MagicMock()
    agent.name = name
    agent.model = model
    agent.instructions = "You are a helpful assistant."
    agent.tools = tools or []
    return agent


def _make_runner(result="run result"):
    """Create a mock OpenAI Runner class with an async run method."""
    runner = MagicMock()
    runner.run = AsyncMock(return_value=result)
    return runner


# =============================================================================
# GovernancePolicy tests
# =============================================================================


class TestGovernancePolicy:
    def test_defaults(self):
        p = GovernancePolicy()
        assert p.max_tool_calls == 50
        assert p.max_handoffs == 5
        assert p.timeout_seconds == 300
        assert p.allowed_tools == []
        assert p.blocked_tools == []
        assert p.blocked_patterns == []
        assert p.pii_detection is True
        assert p.require_human_approval is False
        assert p.log_all_calls is True
        assert p.checkpoint_frequency == 5

    def test_custom(self):
        p = GovernancePolicy(
            max_tool_calls=5,
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE"],
            require_human_approval=True,
        )
        assert p.max_tool_calls == 5
        assert p.blocked_tools == ["shell"]
        assert p.blocked_patterns == ["DROP TABLE"]
        assert p.require_human_approval is True


# =============================================================================
# Kernel initialisation
# =============================================================================


class TestKernelInit:
    def test_default_policy(self):
        k = OpenAIAgentsKernel()
        assert k.policy.max_tool_calls == 50

    def test_explicit_policy(self):
        p = GovernancePolicy(max_tool_calls=3)
        k = OpenAIAgentsKernel(policy=p)
        assert k.policy.max_tool_calls == 3

    def test_custom_violation_handler(self):
        captured = []
        k = OpenAIAgentsKernel(on_violation=lambda e: captured.append(e))
        err = PolicyViolationError("test", "oops")
        k.on_violation(err)
        assert len(captured) == 1
        assert captured[0] is err


# =============================================================================
# Wrapping / unwrapping agents
# =============================================================================


class TestWrapAgent:
    def test_wrap_copies_attributes(self):
        agent = _make_agent(name="bot", model="gpt-4o")
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)

        assert governed.name == "bot"
        assert governed.model == "gpt-4o"
        assert governed.instructions == "You are a helpful assistant."

    def test_wrap_creates_context(self):
        agent = _make_agent(name="bot")
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)

        assert governed._context is not None
        assert isinstance(governed._context, ExecutionContext)
        assert governed._context.agent_id == "bot"

    def test_wrap_registers_agent(self):
        agent = _make_agent(name="bot")
        k = OpenAIAgentsKernel()
        k.wrap(agent)

        assert "bot" in k._wrapped_agents

    def test_unwrap_returns_original(self):
        agent = _make_agent()
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)

        assert k.unwrap(governed) is agent

    def test_unwrap_plain_object_returns_itself(self):
        k = OpenAIAgentsKernel()
        obj = MagicMock(spec=[])  # no _original attribute
        assert k.unwrap(obj) is obj

    def test_original_property(self):
        agent = _make_agent()
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)

        assert governed.original is agent

    def test_getattr_proxies_to_original(self):
        agent = _make_agent()
        agent.custom_attr = "hello"
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)

        assert governed.custom_attr == "hello"


# =============================================================================
# Tool policy enforcement
# =============================================================================


class TestToolPolicyEnforcement:
    def test_allowed_tool_passes(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(allowed_tools=["file_search", "code_interpreter"])
        )
        ok, reason = k._check_tool_allowed("file_search")
        assert ok is True
        assert reason == ""

    def test_tool_not_in_allowed_list_blocked(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(allowed_tools=["file_search"])
        )
        ok, reason = k._check_tool_allowed("shell")
        assert ok is False
        assert "not in allowed list" in reason

    def test_blocked_tool_rejected(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_tools=["shell", "exec"])
        )
        ok, reason = k._check_tool_allowed("shell")
        assert ok is False
        assert "blocked by policy" in reason

    def test_no_restrictions_allows_all(self):
        k = OpenAIAgentsKernel(policy=GovernancePolicy())
        ok, reason = k._check_tool_allowed("anything")
        assert ok is True


# =============================================================================
# Blocked patterns / content filtering
# =============================================================================


class TestBlockedPatterns:
    def test_blocked_pattern_detected(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["rm -rf", "DROP TABLE"])
        )
        ok, reason = k._check_content("please run rm -rf /")
        assert ok is False
        assert "rm -rf" in reason

    def test_blocked_pattern_case_insensitive(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["DROP TABLE"])
        )
        ok, reason = k._check_content("drop table users")
        assert ok is False

    def test_safe_content_passes(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["DROP TABLE"])
        )
        ok, reason = k._check_content("SELECT * FROM users")
        assert ok is True

    def test_no_patterns_allows_all(self):
        k = OpenAIAgentsKernel(policy=GovernancePolicy())
        ok, reason = k._check_content("anything goes")
        assert ok is True


# =============================================================================
# Tool guard decorator
# =============================================================================


class TestToolGuard:
    def test_allowed_tool_executes(self):
        k = OpenAIAgentsKernel(policy=GovernancePolicy())
        guard = k.create_tool_guard()

        @guard
        async def search(query: str) -> str:
            return f"results for {query}"

        result = asyncio.run(search("test"))
        assert result == "results for test"

    def test_blocked_tool_raises(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_tools=["dangerous_tool"])
        )
        guard = k.create_tool_guard()

        @guard
        async def dangerous_tool(cmd: str) -> str:
            return cmd

        with pytest.raises(PolicyViolationError, match="blocked by policy"):
            asyncio.run(dangerous_tool("hello"))

    def test_blocked_pattern_in_args_raises(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["password"])
        )
        guard = k.create_tool_guard()

        @guard
        async def search(query: str) -> str:
            return query

        with pytest.raises(PolicyViolationError, match="blocked pattern"):
            asyncio.run(search("find the password"))

    def test_blocked_pattern_in_kwargs_raises(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["secret"])
        )
        guard = k.create_tool_guard()

        @guard
        async def lookup(key: str) -> str:
            return key

        with pytest.raises(PolicyViolationError, match="blocked pattern"):
            asyncio.run(lookup(key="the secret value"))

    def test_sync_function_wrapped(self):
        k = OpenAIAgentsKernel(policy=GovernancePolicy())
        guard = k.create_tool_guard()

        @guard
        def add(a: int, b: int) -> int:
            return a + b

        result = asyncio.run(add(2, 3))
        assert result == 5


# =============================================================================
# Guardrail
# =============================================================================


class TestGuardrail:
    def test_guardrail_allows_safe_input(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["DROP TABLE"])
        )
        guardrail = k.create_guardrail()
        result = asyncio.run(guardrail(MagicMock(), _make_agent(), "hello world"))
        assert result is None  # None = allowed

    def test_guardrail_blocks_bad_input(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_patterns=["DROP TABLE"])
        )
        guardrail = k.create_guardrail()
        result = asyncio.run(
            guardrail(MagicMock(), _make_agent(), "please DROP TABLE users")
        )
        assert result is not None
        assert "blocked" in result.lower()

    def test_guardrail_checks_tool_calls(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_tools=["shell"])
        )
        guardrail = k.create_guardrail()

        ctx = MagicMock()
        tool_call = MagicMock()
        tool_call.name = "shell"
        ctx.tool_calls = [tool_call]

        result = asyncio.run(guardrail(ctx, _make_agent(), "run command"))
        assert result is not None
        assert "blocked" in result.lower()


# =============================================================================
# Runner governance (async)
# =============================================================================


class TestGovernedRunner:
    def test_run_delegates_to_original(self):
        agent = _make_agent()
        runner = _make_runner(result="hello")
        k = OpenAIAgentsKernel()
        governed_agent = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        result = asyncio.run(GovernedRunner.run(governed_agent, "hi"))
        assert result == "hello"
        runner.run.assert_awaited_once()

    def test_run_records_events(self):
        agent = _make_agent()
        runner = _make_runner()
        k = OpenAIAgentsKernel()
        governed_agent = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        asyncio.run(GovernedRunner.run(governed_agent, "hi"))

        events = governed_agent._context.events
        types = [e["type"] for e in events]
        assert "run_start" in types
        assert "run_complete" in types

    def test_run_blocks_content_with_human_approval(self):
        policy = GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
            require_human_approval=True,
        )
        agent = _make_agent()
        runner = _make_runner()
        k = OpenAIAgentsKernel(policy=policy)
        governed_agent = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        with pytest.raises(PolicyViolationError, match="content_filter"):
            asyncio.run(
                GovernedRunner.run(governed_agent, "DROP TABLE users")
            )

    def test_run_violation_without_human_approval_continues(self):
        """Without require_human_approval, violations are logged but run continues."""
        violations = []
        policy = GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
            require_human_approval=False,
        )
        k = OpenAIAgentsKernel(
            policy=policy, on_violation=lambda e: violations.append(e)
        )
        agent = _make_agent()
        runner = _make_runner(result="done")
        governed_agent = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        result = asyncio.run(
            GovernedRunner.run(governed_agent, "DROP TABLE users")
        )
        assert result == "done"
        assert len(violations) == 1

    def test_run_records_error_on_failure(self):
        agent = _make_agent()
        runner = _make_runner()
        runner.run = AsyncMock(side_effect=RuntimeError("boom"))
        k = OpenAIAgentsKernel()
        governed_agent = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(GovernedRunner.run(governed_agent, "hi"))

        events = governed_agent._context.events
        types = [e["type"] for e in events]
        assert "run_error" in types

    def test_run_sync(self):
        agent = _make_agent()
        runner = _make_runner(result="sync result")
        k = OpenAIAgentsKernel()
        governed_agent = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        result = GovernedRunner.run_sync(governed_agent, "hello")
        assert result == "sync result"


# =============================================================================
# Handoff governance
# =============================================================================


class TestHandoffGovernance:
    def test_handoff_counter_tracked(self):
        k = OpenAIAgentsKernel(policy=GovernancePolicy(max_handoffs=3))
        agent_a = _make_agent(name="agent-a")
        agent_b = _make_agent(name="agent-b")

        wrapped_a = k.wrap(agent_a)
        wrapped_b = k.wrap(agent_b)

        # Simulate handoffs by incrementing context
        wrapped_a._context.handoffs += 1
        wrapped_b._context.handoffs += 1

        stats = k.get_stats()
        assert stats["total_handoffs"] == 2

    def test_multiple_agents_wrapped(self):
        k = OpenAIAgentsKernel()
        agents = [_make_agent(name=f"agent-{i}") for i in range(3)]
        for a in agents:
            k.wrap(a)

        assert k.get_stats()["wrapped_agents"] == 3


# =============================================================================
# Max calls enforcement
# =============================================================================


class TestMaxCallsEnforcement:
    def test_tool_guard_respects_max_calls_via_blocked_tools(self):
        """Tool guard blocks tools on the blocked list immediately."""
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_tools=["tool_x"])
        )
        guard = k.create_tool_guard()

        @guard
        async def tool_x():
            return "should not run"

        with pytest.raises(PolicyViolationError):
            asyncio.run(tool_x())

    def test_context_tracks_tool_calls(self):
        agent = _make_agent()
        k = OpenAIAgentsKernel(policy=GovernancePolicy(max_tool_calls=3))
        governed = k.wrap(agent)

        governed._context.tool_calls += 1
        governed._context.tool_calls += 1
        governed._context.tool_calls += 1

        assert governed._context.tool_calls == 3
        assert governed._context.policy.max_tool_calls == 3


# =============================================================================
# Human approval workflow
# =============================================================================


class TestHumanApproval:
    def test_approval_required_blocks_on_violation(self):
        policy = GovernancePolicy(
            require_human_approval=True,
            blocked_patterns=["sudo"],
        )
        k = OpenAIAgentsKernel(policy=policy)
        agent = _make_agent()
        runner = _make_runner()
        governed = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        with pytest.raises(PolicyViolationError):
            asyncio.run(GovernedRunner.run(governed, "sudo rm -rf /"))

    def test_approval_not_required_logs_only(self):
        violations = []
        policy = GovernancePolicy(
            require_human_approval=False,
            blocked_patterns=["sudo"],
        )
        k = OpenAIAgentsKernel(
            policy=policy, on_violation=lambda e: violations.append(e)
        )
        agent = _make_agent()
        runner = _make_runner(result="ok")
        governed = k.wrap(agent)
        GovernedRunner = k.wrap_runner(runner)

        result = asyncio.run(GovernedRunner.run(governed, "sudo rm -rf /"))
        assert result == "ok"
        assert len(violations) == 1


# =============================================================================
# Error handling
# =============================================================================


class TestErrorHandling:
    def test_policy_violation_error_fields(self):
        e = PolicyViolationError("tool_filter", "blocked", severity="critical")
        assert e.policy_name == "tool_filter"
        assert e.description == "blocked"
        assert e.severity == "critical"
        assert "tool_filter" in str(e)
        assert "blocked" in str(e)

    def test_policy_violation_default_severity(self):
        e = PolicyViolationError("test", "desc")
        assert e.severity == "high"

    def test_violation_handler_receives_error(self):
        captured = []
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(blocked_tools=["bad_tool"]),
            on_violation=lambda e: captured.append(e),
        )
        guard = k.create_tool_guard()

        @guard
        async def bad_tool():
            return "nope"

        with pytest.raises(PolicyViolationError):
            asyncio.run(bad_tool())

        assert len(captured) == 1
        assert captured[0].policy_name == "tool_filter"


# =============================================================================
# Audit & stats
# =============================================================================


class TestAuditAndStats:
    def test_get_context(self):
        agent = _make_agent(name="bot")
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)

        ctx = k.get_context(governed._context.session_id)
        assert ctx is not None
        assert ctx.agent_id == "bot"

    def test_get_context_missing(self):
        k = OpenAIAgentsKernel()
        assert k.get_context("nonexistent") is None

    def test_get_audit_log(self):
        agent = _make_agent()
        k = OpenAIAgentsKernel()
        governed = k.wrap(agent)
        governed._context.record_event("test_event", {"key": "value"})

        log = k.get_audit_log(governed._context.session_id)
        assert len(log) == 1
        assert log[0]["type"] == "test_event"

    def test_get_audit_log_missing_session(self):
        k = OpenAIAgentsKernel()
        assert k.get_audit_log("missing") == []

    def test_get_stats(self):
        k = OpenAIAgentsKernel(
            policy=GovernancePolicy(
                max_tool_calls=10,
                max_handoffs=3,
                blocked_tools=["shell"],
            )
        )
        agent = _make_agent()
        governed = k.wrap(agent)
        governed._context.tool_calls = 5
        governed._context.handoffs = 2

        stats = k.get_stats()
        assert stats["total_sessions"] == 1
        assert stats["wrapped_agents"] == 1
        assert stats["total_tool_calls"] == 5
        assert stats["total_handoffs"] == 2
        assert stats["policy"]["max_tool_calls"] == 10
        assert stats["policy"]["blocked_tools"] == ["shell"]

    def test_health_check_healthy(self):
        k = OpenAIAgentsKernel()
        k.wrap(_make_agent())
        h = k.health_check()

        assert h["status"] == "healthy"
        assert h["backend"] == "openai_agents_sdk"
        assert h["backend_connected"] is True
        assert h["last_error"] is None
        assert h["uptime_seconds"] >= 0

    def test_health_check_degraded(self):
        k = OpenAIAgentsKernel()
        k._last_error = "something broke"
        h = k.health_check()

        assert h["status"] == "degraded"
        assert h["last_error"] == "something broke"


# =============================================================================
# ExecutionContext
# =============================================================================


class TestExecutionContext:
    def test_record_event(self):
        ctx = ExecutionContext(
            session_id="s1", agent_id="a1", policy=GovernancePolicy()
        )
        ctx.record_event("tool_call", {"tool": "search"})

        assert len(ctx.events) == 1
        assert ctx.events[0]["type"] == "tool_call"
        assert ctx.events[0]["data"]["tool"] == "search"
        assert "timestamp" in ctx.events[0]

    def test_defaults(self):
        ctx = ExecutionContext(
            session_id="s1", agent_id="a1", policy=GovernancePolicy()
        )
        assert ctx.tool_calls == 0
        assert ctx.handoffs == 0
        assert ctx.events == []


# =============================================================================
# Integration: full lifecycle
# =============================================================================


class TestFullLifecycle:
    def test_end_to_end_governed_run(self):
        """Simulate a full governed agent run with tool guard + runner."""
        violations = []
        policy = GovernancePolicy(
            max_tool_calls=10,
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE", "password"],
            allowed_tools=["search", "calculator"],
        )
        k = OpenAIAgentsKernel(
            policy=policy, on_violation=lambda e: violations.append(e)
        )

        # Wrap agent
        agent = _make_agent(name="assistant")
        governed = k.wrap(agent)
        assert governed.name == "assistant"

        # Create tool guard
        guard = k.create_tool_guard()

        @guard
        async def search(query: str) -> str:
            return f"results: {query}"

        @guard
        async def calculator(expr: str) -> str:
            return f"answer: {expr}"

        @guard
        async def shell(cmd: str) -> str:
            return cmd

        # Allowed tool works
        result = asyncio.run(search("weather"))
        assert result == "results: weather"

        # Another allowed tool works
        result = asyncio.run(calculator("2+2"))
        assert result == "answer: 2+2"

        # Blocked tool raises
        with pytest.raises(PolicyViolationError):
            asyncio.run(shell("ls"))

        # Blocked pattern in args raises
        with pytest.raises(PolicyViolationError):
            asyncio.run(search("find the password"))

        # Verify violations captured
        assert len(violations) == 2

        # Stats reflect wrapped agent
        stats = k.get_stats()
        assert stats["wrapped_agents"] == 1

        # Health is good
        health = k.health_check()
        assert health["status"] == "healthy"
