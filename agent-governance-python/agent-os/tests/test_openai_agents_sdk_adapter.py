# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for OpenAI Agents SDK governance adapter.

Covers:
1. Native RunHooks lifecycle (primary API)
2. BaseIntegration / Cedar / OPA inheritance
3. Deprecated wrap() / wrap_runner() / create_tool_guard() backward-compat
4. Audit, stats, and health check

No real OpenAI Agents SDK dependency required — uses mock objects.

Run with: python -m pytest tests/test_openai_agents_sdk_adapter.py -v --tb=short
"""

import asyncio
import warnings
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_os.integrations.openai_agents_sdk import (
    GovernanceRunHooks,
    OpenAIAgentsKernel,
)
from agent_os.integrations.base import GovernancePolicy
from agent_os.exceptions import PolicyViolationError


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


def _make_context(input_text="hello"):
    """Create a mock RunHooks context."""
    ctx = MagicMock()
    ctx.input = input_text
    return ctx


def _make_tool(name="search", args=None):
    """Create a mock tool."""
    tool = MagicMock()
    tool.name = name
    tool.__name__ = name
    tool.args = args or {}
    return tool


class _FakeEvaluator:
    """Minimal evaluator for Cedar/OPA testing."""

    def __init__(self, allowed=True, reason=""):
        self._allowed = allowed
        self._reason = reason
        self.last_context = None

    def evaluate(self, ctx):
        self.last_context = ctx

        class _Decision:
            def __init__(d, allowed, reason):
                d.allowed = allowed
                d.reason = reason

        return _Decision(self._allowed, self._reason)


# =============================================================================
# 1. Kernel initialisation & BaseIntegration inheritance
# =============================================================================


class TestKernelInit:
    def test_default_policy(self):
        k = OpenAIAgentsKernel()
        assert isinstance(k.policy, GovernancePolicy)
        assert k.policy.max_tool_calls == 50

    def test_explicit_policy(self):
        p = GovernancePolicy(max_tool_calls=3)
        k = OpenAIAgentsKernel(policy=p)
        assert k.policy.max_tool_calls == 3

    def test_convenience_kwargs(self):
        k = OpenAIAgentsKernel(
            max_tool_calls=10,
            blocked_tools=["shell"],
            allowed_tools=["search"],
            blocked_patterns=["DROP TABLE"],
        )
        assert k.policy.max_tool_calls == 10
        assert "shell" in k._blocked_tools
        assert "search" in k._allowed_tools
        assert "DROP TABLE" in k.policy.blocked_patterns

    def test_custom_violation_handler(self):
        captured = []
        k = OpenAIAgentsKernel(on_violation=lambda e: captured.append(e))
        err = PolicyViolationError("oops")
        k.on_violation(err)
        assert len(captured) == 1
        assert captured[0] is err

    def test_inherits_base_integration(self):
        """Kernel inherits from BaseIntegration, getting Cedar/pre_execute."""
        from agent_os.integrations.base import BaseIntegration
        k = OpenAIAgentsKernel()
        assert isinstance(k, BaseIntegration)

    def test_evaluator_parameter_accepted(self):
        """Cedar/OPA evaluator can be passed through."""
        evaluator = _FakeEvaluator()
        k = OpenAIAgentsKernel(evaluator=evaluator)
        assert k._evaluator is evaluator


# =============================================================================
# 2. as_hooks() — primary API  (GovernanceRunHooks)
# =============================================================================


class TestAsHooks:
    def test_returns_governance_run_hooks(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks()
        assert isinstance(hooks, GovernanceRunHooks)

    def test_custom_name(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks(name="my-governance")
        assert hooks.hook_name == "my-governance"

    def test_hooks_reference_kernel(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks()
        assert hooks._kernel is k


# =============================================================================
# 3. RunHooks lifecycle callbacks
# =============================================================================


class TestOnAgentStart:
    def test_allows_safe_input(self):
        k = OpenAIAgentsKernel(blocked_patterns=["DROP TABLE"])
        hooks = k.as_hooks()
        ctx = _make_context(input_text="Hello world")
        agent = _make_agent()

        # Should not raise
        asyncio.run(hooks.on_agent_start(ctx, agent))

    def test_blocks_bad_content_with_human_approval(self):
        k = OpenAIAgentsKernel(
            blocked_patterns=["DROP TABLE"],
            require_human_approval=True,
        )
        hooks = k.as_hooks()
        ctx = _make_context(input_text="DROP TABLE users")
        agent = _make_agent()

        with pytest.raises(PolicyViolationError, match="blocked"):
            asyncio.run(hooks.on_agent_start(ctx, agent))

    def test_logs_violation_without_human_approval(self):
        violations = []
        k = OpenAIAgentsKernel(
            blocked_patterns=["DROP TABLE"],
            require_human_approval=False,
            on_violation=lambda e: violations.append(e),
        )
        hooks = k.as_hooks()
        ctx = _make_context(input_text="DROP TABLE users")
        agent = _make_agent()

        # Should not raise, but should record violation
        asyncio.run(hooks.on_agent_start(ctx, agent))
        assert len(violations) == 1

    def test_records_audit_event(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks()
        ctx = _make_context(input_text="test")
        agent = _make_agent(name="bot")

        asyncio.run(hooks.on_agent_start(ctx, agent))

        events = k.get_audit_log()
        assert any(e["type"] == "agent_start" for e in events)
        assert events[-1]["data"]["agent"] == "bot"


class TestOnAgentEnd:
    def test_records_audit_event(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent(name="bot")

        asyncio.run(hooks.on_agent_end(ctx, agent, "result text"))

        events = k.get_audit_log()
        assert any(e["type"] == "agent_end" for e in events)
        assert events[-1]["data"]["success"] is True

    def test_post_execute_validation(self):
        """post_execute is called on agent output."""
        k = OpenAIAgentsKernel(blocked_patterns=["SECRET_API_KEY"])
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()

        # Should not raise, but should log warning
        asyncio.run(hooks.on_agent_end(ctx, agent, "The SECRET_API_KEY is..."))


class TestOnToolStart:
    def test_allowed_tool_passes(self):
        k = OpenAIAgentsKernel(allowed_tools=["search", "calculator"])
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="search")

        asyncio.run(hooks.on_tool_start(ctx, agent, tool))
        assert k._tool_call_count == 1

    def test_blocked_tool_raises(self):
        k = OpenAIAgentsKernel(blocked_tools=["shell"])
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="shell")

        with pytest.raises(PolicyViolationError, match="blocked"):
            asyncio.run(hooks.on_tool_start(ctx, agent, tool))

    def test_tool_not_in_allowed_list_blocked(self):
        k = OpenAIAgentsKernel(allowed_tools=["search"])
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="shell")

        with pytest.raises(PolicyViolationError, match="not in allowed list"):
            asyncio.run(hooks.on_tool_start(ctx, agent, tool))

    def test_tool_call_budget_enforced(self):
        k = OpenAIAgentsKernel(max_tool_calls=2)
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="search")

        asyncio.run(hooks.on_tool_start(ctx, agent, tool))  # 1
        asyncio.run(hooks.on_tool_start(ctx, agent, tool))  # 2

        with pytest.raises(PolicyViolationError, match="budget exceeded"):
            asyncio.run(hooks.on_tool_start(ctx, agent, tool))  # 3 = over

    def test_content_filter_on_tool_args(self):
        k = OpenAIAgentsKernel(blocked_patterns=["password"])
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="search", args={"query": "find the password"})

        with pytest.raises(PolicyViolationError, match="blocked"):
            asyncio.run(hooks.on_tool_start(ctx, agent, tool))

    def test_records_audit_event(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent(name="bot")
        tool = _make_tool(name="search")

        asyncio.run(hooks.on_tool_start(ctx, agent, tool))

        events = k.get_audit_log()
        assert any(e["type"] == "tool_start" for e in events)

    def test_cedar_gate_on_tool(self):
        """Cedar evaluator receives tool_name and can block specific tools."""

        class ToolBlockEvaluator:
            def evaluate(self, ctx):
                class D:
                    def __init__(d):
                        d.allowed = ctx.get("tool_name") != "shell_exec"
                        d.reason = "shell blocked" if not d.allowed else ""
                return D()

        k = OpenAIAgentsKernel(evaluator=ToolBlockEvaluator())
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()

        # Allowed tool
        tool_ok = _make_tool(name="search")
        asyncio.run(hooks.on_tool_start(ctx, agent, tool_ok))

        # Blocked by Cedar
        tool_bad = _make_tool(name="shell_exec")
        with pytest.raises(PolicyViolationError, match="blocked by governance"):
            asyncio.run(hooks.on_tool_start(ctx, agent, tool_bad))


class TestOnToolEnd:
    def test_records_audit_event(self):
        k = OpenAIAgentsKernel()
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent(name="bot")
        tool = _make_tool(name="search")

        asyncio.run(hooks.on_tool_end(ctx, agent, tool, "result data"))

        events = k.get_audit_log()
        assert any(e["type"] == "tool_end" for e in events)

    def test_content_filter_on_output(self):
        """Blocked pattern in tool output is logged (not raised)."""
        k = OpenAIAgentsKernel(blocked_patterns=["SECRET"])
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="search")

        # Should not raise, just log warning
        asyncio.run(hooks.on_tool_end(ctx, agent, tool, "output: SECRET"))


class TestOnHandoff:
    def test_handoff_recorded(self):
        k = OpenAIAgentsKernel(max_handoffs=10)
        hooks = k.as_hooks()
        ctx = _make_context()
        from_agent = _make_agent(name="agent-a")
        to_agent = _make_agent(name="agent-b")

        asyncio.run(hooks.on_handoff(ctx, from_agent, to_agent))

        assert k._handoff_count == 1
        events = k.get_audit_log()
        assert any(e["type"] == "handoff" for e in events)
        assert events[-1]["data"]["from"] == "agent-a"
        assert events[-1]["data"]["to"] == "agent-b"

    def test_handoff_limit_enforced(self):
        k = OpenAIAgentsKernel(max_handoffs=2)
        hooks = k.as_hooks()
        ctx = _make_context()
        a = _make_agent(name="a")
        b = _make_agent(name="b")

        asyncio.run(hooks.on_handoff(ctx, a, b))  # 1
        asyncio.run(hooks.on_handoff(ctx, b, a))  # 2

        with pytest.raises(PolicyViolationError, match="Handoff limit"):
            asyncio.run(hooks.on_handoff(ctx, a, b))  # 3 = over


# =============================================================================
# 4. Full RunHooks lifecycle integration
# =============================================================================


class TestFullHooksLifecycle:
    def test_end_to_end_hooks_lifecycle(self):
        """Simulate a full agent execution via RunHooks callbacks."""
        k = OpenAIAgentsKernel(
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE"],
            allowed_tools=["search", "calculator"],
            max_tool_calls=10,
            max_handoffs=3,
        )
        hooks = k.as_hooks()
        ctx = _make_context(input_text="Analyze this data")
        primary = _make_agent(name="primary")
        helper = _make_agent(name="helper")

        # Agent start
        asyncio.run(hooks.on_agent_start(ctx, primary))

        # Tool calls
        search_tool = _make_tool(name="search")
        asyncio.run(hooks.on_tool_start(ctx, primary, search_tool))
        asyncio.run(hooks.on_tool_end(ctx, primary, search_tool, "results"))

        calc_tool = _make_tool(name="calculator")
        asyncio.run(hooks.on_tool_start(ctx, primary, calc_tool))
        asyncio.run(hooks.on_tool_end(ctx, primary, calc_tool, "42"))

        # Blocked tool
        shell_tool = _make_tool(name="shell")
        with pytest.raises(PolicyViolationError, match="blocked"):
            asyncio.run(hooks.on_tool_start(ctx, primary, shell_tool))

        # Handoff
        asyncio.run(hooks.on_handoff(ctx, primary, helper))

        # Agent end
        asyncio.run(hooks.on_agent_end(ctx, primary, "analysis complete"))

        # Verify state
        assert k._tool_call_count == 2  # search + calculator (shell was blocked)
        assert k._handoff_count == 1
        events = k.get_audit_log()
        event_types = [e["type"] for e in events]
        assert "agent_start" in event_types
        assert "tool_start" in event_types
        assert "tool_end" in event_types
        assert "handoff" in event_types
        assert "agent_end" in event_types

        # Stats
        stats = k.get_stats()
        assert stats["total_tool_calls"] == 2
        assert stats["total_handoffs"] == 1

    def test_hooks_with_cedar_evaluator(self):
        """RunHooks callbacks correctly wire through Cedar evaluation."""
        evaluator = _FakeEvaluator(allowed=True)
        k = OpenAIAgentsKernel(evaluator=evaluator)
        hooks = k.as_hooks()
        ctx = _make_context(input_text="test")
        agent = _make_agent(name="bot")
        tool = _make_tool(name="search")

        asyncio.run(hooks.on_agent_start(ctx, agent))
        asyncio.run(hooks.on_tool_start(ctx, agent, tool))

        assert evaluator.last_context is not None
        assert evaluator.last_context["tool_name"] == "search"

    def test_hooks_cedar_deny_blocks_tool(self):
        """Cedar deny blocks tool via on_tool_start."""
        evaluator = _FakeEvaluator(allowed=False, reason="policy denied")
        k = OpenAIAgentsKernel(evaluator=evaluator)
        hooks = k.as_hooks()
        ctx = _make_context()
        agent = _make_agent()
        tool = _make_tool(name="search")

        with pytest.raises(PolicyViolationError, match="blocked by governance"):
            asyncio.run(hooks.on_tool_start(ctx, agent, tool))


# =============================================================================
# 5. Observability: stats, health, audit
# =============================================================================


class TestObservability:
    def test_get_audit_log(self):
        k = OpenAIAgentsKernel()
        k._record_event("test_event", {"key": "value"})
        log = k.get_audit_log()
        assert len(log) == 1
        assert log[0]["type"] == "test_event"

    def test_get_stats(self):
        k = OpenAIAgentsKernel(
            max_tool_calls=10,
            max_handoffs=3,
            blocked_tools=["shell"],
        )
        k._tool_call_count = 5
        k._handoff_count = 2

        stats = k.get_stats()
        assert stats["total_tool_calls"] == 5
        assert stats["total_handoffs"] == 2
        assert "shell" in stats["policy"]["blocked_tools"]

    def test_health_check_healthy(self):
        k = OpenAIAgentsKernel()
        # Create a context to simulate activity
        k._get_or_create_context("agent-1")
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
# 6. Tool / content checks (unit-level)
# =============================================================================


class TestToolPolicyChecks:
    def test_allowed_tool_passes(self):
        k = OpenAIAgentsKernel(allowed_tools=["search", "calculator"])
        ok, _ = k._check_tool_allowed("search")
        assert ok is True

    def test_tool_not_in_allowed_list_blocked(self):
        k = OpenAIAgentsKernel(allowed_tools=["search"])
        ok, reason = k._check_tool_allowed("shell")
        assert ok is False
        assert "not in allowed list" in reason

    def test_blocked_tool_rejected(self):
        k = OpenAIAgentsKernel(blocked_tools=["shell", "exec"])
        ok, reason = k._check_tool_allowed("shell")
        assert ok is False
        assert "blocked by policy" in reason

    def test_no_restrictions_allows_all(self):
        k = OpenAIAgentsKernel()
        ok, _ = k._check_tool_allowed("anything")
        assert ok is True


class TestContentFilter:
    def test_blocked_pattern_detected(self):
        k = OpenAIAgentsKernel(blocked_patterns=["rm -rf", "DROP TABLE"])
        ok, reason = k._check_content("please run rm -rf /")
        assert ok is False
        assert "rm -rf" in reason

    def test_blocked_pattern_case_insensitive(self):
        k = OpenAIAgentsKernel(blocked_patterns=["DROP TABLE"])
        ok, _ = k._check_content("drop table users")
        assert ok is False

    def test_safe_content_passes(self):
        k = OpenAIAgentsKernel(blocked_patterns=["DROP TABLE"])
        ok, _ = k._check_content("SELECT * FROM users")
        assert ok is True

    def test_no_patterns_allows_all(self):
        k = OpenAIAgentsKernel()
        ok, _ = k._check_content("anything goes")
        assert ok is True


# =============================================================================
# 7. Deprecated wrap() / wrap_runner() / create_tool_guard()
# =============================================================================


class TestDeprecatedWrap:
    def test_wrap_emits_deprecation_warning(self):
        k = OpenAIAgentsKernel()
        agent = _make_agent()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            k.wrap(agent)
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "as_hooks" in str(w[0].message)

    def test_wrap_copies_attributes(self):
        k = OpenAIAgentsKernel()
        agent = _make_agent(name="bot", model="gpt-4o")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
        assert governed.name == "bot"
        assert governed.model == "gpt-4o"

    def test_unwrap_returns_original(self):
        k = OpenAIAgentsKernel()
        agent = _make_agent()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
        assert k.unwrap(governed) is agent

    def test_unwrap_plain_object(self):
        k = OpenAIAgentsKernel()
        obj = MagicMock(spec=[])
        assert k.unwrap(obj) is obj


class TestDeprecatedWrapRunner:
    def test_wrap_runner_emits_deprecation(self):
        k = OpenAIAgentsKernel()
        runner = _make_runner()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            k.wrap_runner(runner)
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

    def test_governed_runner_delegates_to_original(self):
        k = OpenAIAgentsKernel()
        agent = _make_agent()
        runner = _make_runner(result="hello")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
            GovernedRunner = k.wrap_runner(runner)

        result = asyncio.run(GovernedRunner.run(governed, "hi"))
        assert result == "hello"
        runner.run.assert_awaited_once()

    def test_governed_runner_records_events(self):
        k = OpenAIAgentsKernel()
        agent = _make_agent()
        runner = _make_runner()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
            GovernedRunner = k.wrap_runner(runner)

        asyncio.run(GovernedRunner.run(governed, "hi"))
        entries = governed._context.tool_calls
        types = [e["type"] for e in entries]
        assert "run_start" in types
        assert "run_complete" in types

    def test_governed_runner_blocks_content_with_approval(self):
        k = OpenAIAgentsKernel(
            blocked_patterns=["DROP TABLE"],
            require_human_approval=True,
        )
        runner = _make_runner()
        agent = _make_agent()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
            GovernedRunner = k.wrap_runner(runner)

        with pytest.raises(PolicyViolationError):
            asyncio.run(GovernedRunner.run(governed, "DROP TABLE users"))

    def test_governed_runner_error_event(self):
        k = OpenAIAgentsKernel()
        runner = _make_runner()
        runner.run = AsyncMock(side_effect=RuntimeError("boom"))
        agent = _make_agent()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
            GovernedRunner = k.wrap_runner(runner)

        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(GovernedRunner.run(governed, "hi"))

        entries = governed._context.tool_calls
        types = [e["type"] for e in entries]
        assert "run_error" in types

    def test_run_sync(self):
        k = OpenAIAgentsKernel()
        runner = _make_runner(result="sync result")
        agent = _make_agent()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = k.wrap(agent)
            GovernedRunner = k.wrap_runner(runner)

        result = GovernedRunner.run_sync(governed, "hello")
        assert result == "sync result"


class TestDeprecatedToolGuard:
    def test_tool_guard_emits_deprecation(self):
        k = OpenAIAgentsKernel()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            k.create_tool_guard()
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

    def test_allowed_tool_executes(self):
        k = OpenAIAgentsKernel()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            guard = k.create_tool_guard()

        @guard
        async def search(query: str) -> str:
            return f"results for {query}"

        result = asyncio.run(search("test"))
        assert result == "results for test"

    def test_blocked_tool_raises(self):
        k = OpenAIAgentsKernel(blocked_tools=["dangerous_tool"])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            guard = k.create_tool_guard()

        @guard
        async def dangerous_tool(cmd: str) -> str:
            return cmd

        with pytest.raises(PolicyViolationError, match="blocked"):
            asyncio.run(dangerous_tool("hello"))

    def test_blocked_pattern_in_args_raises(self):
        k = OpenAIAgentsKernel(blocked_patterns=["password"])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            guard = k.create_tool_guard()

        @guard
        async def search(query: str) -> str:
            return query

        with pytest.raises(PolicyViolationError, match="blocked"):
            asyncio.run(search("find the password"))

    def test_sync_function_wrapped(self):
        k = OpenAIAgentsKernel()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            guard = k.create_tool_guard()

        @guard
        def add(a: int, b: int) -> int:
            return a + b

        result = asyncio.run(add(2, 3))
        assert result == 5


# =============================================================================
# 8. Guardrail
# =============================================================================


class TestGuardrail:
    def test_guardrail_allows_safe_input(self):
        k = OpenAIAgentsKernel(blocked_patterns=["DROP TABLE"])
        guardrail = k.create_guardrail()
        result = asyncio.run(guardrail(MagicMock(), _make_agent(), "hello world"))
        assert result is None

    def test_guardrail_blocks_bad_input(self):
        k = OpenAIAgentsKernel(blocked_patterns=["DROP TABLE"])
        guardrail = k.create_guardrail()
        result = asyncio.run(
            guardrail(MagicMock(), _make_agent(), "please DROP TABLE users")
        )
        assert result is not None
        assert "blocked" in result.lower()

    def test_guardrail_checks_tool_calls(self):
        k = OpenAIAgentsKernel(blocked_tools=["shell"])
        guardrail = k.create_guardrail()

        ctx = MagicMock()
        tool_call = MagicMock()
        tool_call.name = "shell"
        ctx.tool_calls = [tool_call]

        result = asyncio.run(guardrail(ctx, _make_agent(), "run command"))
        assert result is not None
        assert "blocked" in result.lower()


# =============================================================================
# 9. Cross-framework parity (Cedar integration via BaseIntegration)
# =============================================================================


class TestCedarParity:
    def test_evaluator_deny_blocks_pre_execute(self):
        """Same test pattern as other adapters — Cedar deny blocks."""
        evaluator = _FakeEvaluator(allowed=False, reason="enterprise deny")
        k = OpenAIAgentsKernel(evaluator=evaluator)
        ctx = k.create_context("test-agent")

        allowed, reason = k.pre_execute(ctx, "test input")
        assert allowed is False
        assert "enterprise deny" in reason

    def test_evaluator_allow_passes_through(self):
        evaluator = _FakeEvaluator(allowed=True)
        k = OpenAIAgentsKernel(evaluator=evaluator)
        ctx = k.create_context("test-agent")

        allowed, _ = k.pre_execute(ctx, "test input")
        assert allowed is True

    def test_fail_closed_on_evaluator_exception(self):
        """Evaluator crash = fail-closed (deny)."""

        class _CrashEvaluator:
            def evaluate(self, ctx):
                raise RuntimeError("boom")

        k = OpenAIAgentsKernel(evaluator=_CrashEvaluator())
        ctx = k.create_context("test-agent")

        allowed, reason = k.pre_execute(ctx, "test")
        assert allowed is False
        assert "fail-closed" in reason.lower() or "error" in reason.lower()

    def test_no_evaluator_skips_cedar_gate(self):
        """Without evaluator, pre_execute still works (local policy only)."""
        k = OpenAIAgentsKernel()
        ctx = k.create_context("test-agent")

        allowed, reason = k.pre_execute(ctx, "test input")
        assert allowed is True
