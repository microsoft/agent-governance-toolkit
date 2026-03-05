# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Microsoft Agent Framework (MAF) adapter."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_os.integrations.base import GovernancePolicy, PatternType
from agent_os.integrations.maf_adapter import (
    CapabilityGuardMiddleware,
    GovernancePolicyMiddleware,
    MAFKernel,
    OutputValidationMiddleware,
    govern,
)


# --- Fixtures ---


@pytest.fixture
def policy():
    return GovernancePolicy(
        name="test-maf",
        allowed_tools=["web_search", "file_read"],
        blocked_patterns=["password", ("rm\\s+-rf", PatternType.REGEX)],
        max_tool_calls=3,
    )


@pytest.fixture
def kernel(policy):
    return MAFKernel(policy=policy)


def _make_agent_context(agent_name="test-agent", messages=None, metadata=None):
    """Create a mock AgentContext."""
    ctx = MagicMock()
    ctx.agent = MagicMock()
    ctx.agent.name = agent_name
    ctx.messages = messages or []
    ctx.stream = False
    ctx.metadata = metadata if metadata is not None else {}
    ctx.result = None
    return ctx


def _make_function_context(func_name="web_search", arguments=None, metadata=None):
    """Create a mock FunctionInvocationContext."""
    ctx = MagicMock()
    ctx.function = MagicMock()
    ctx.function.name = func_name
    ctx.arguments = arguments or {"query": "test"}
    ctx.metadata = metadata if metadata is not None else {}
    ctx.result = None
    return ctx


def _make_chat_context(stream=False, result_content=None, metadata=None):
    """Create a mock ChatContext."""
    ctx = MagicMock()
    ctx.stream = stream
    ctx.metadata = metadata if metadata is not None else {}
    if result_content:
        ctx.result = MagicMock()
        ctx.result.content = result_content
    else:
        ctx.result = None
    return ctx


# --- MAFKernel Tests ---


class TestMAFKernel:
    def test_init(self, kernel):
        assert kernel.agent is not None
        assert kernel.function is not None
        assert kernel.chat is not None

    def test_middleware_property(self, kernel):
        mw = kernel.middleware
        assert len(mw) == 3
        assert isinstance(mw[0], GovernancePolicyMiddleware)
        assert isinstance(mw[1], CapabilityGuardMiddleware)
        assert isinstance(mw[2], OutputValidationMiddleware)

    def test_health_check(self, kernel):
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "microsoft-agent-framework"
        assert health["active_agents"] == 0

    def test_signal_stop_cont(self, kernel):
        kernel.signal("maf-test", "SIGSTOP")
        assert kernel._stopped.get("maf-test") is True

        kernel.signal("maf-test", "SIGCONT")
        assert kernel._stopped.get("maf-test") is False

    def test_signal_kill(self, kernel):
        kernel._active_agents["maf-test"] = MagicMock()
        kernel.signal("maf-test", "SIGKILL")
        assert "maf-test" not in kernel._active_agents
        assert kernel._stopped.get("maf-test") is True

    def test_govern_convenience(self, policy):
        k = govern(policy=policy)
        assert isinstance(k, MAFKernel)
        assert len(k.middleware) == 3


# --- GovernancePolicyMiddleware Tests ---


class TestAgentMiddleware:
    @pytest.mark.asyncio
    async def test_allows_valid_run(self, kernel):
        ctx = _make_agent_context()
        call_next = AsyncMock()

        await kernel.agent.process(ctx, call_next)

        call_next.assert_awaited_once()
        assert "maf-test-agent" in kernel._active_agents

    @pytest.mark.asyncio
    async def test_blocks_stopped_agent(self, kernel):
        kernel._stopped["maf-test-agent"] = True
        ctx = _make_agent_context()
        call_next = AsyncMock()

        with pytest.raises(Exception, match="stopped"):
            await kernel.agent.process(ctx, call_next)

        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_records_audit_log(self, kernel):
        ctx = _make_agent_context()
        call_next = AsyncMock()

        await kernel.agent.process(ctx, call_next)

        assert len(kernel._audit_log) == 1
        assert kernel._audit_log[0]["type"] == "agent_run"
        assert "elapsed_seconds" in kernel._audit_log[0]


# --- CapabilityGuardMiddleware Tests ---


class TestFunctionMiddleware:
    @pytest.mark.asyncio
    async def test_allows_permitted_tool(self, kernel):
        ctx = _make_function_context(func_name="web_search")
        call_next = AsyncMock()

        await kernel.function.process(ctx, call_next)

        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_blocks_forbidden_tool(self, kernel):
        ctx = _make_function_context(func_name="shell_exec")
        call_next = AsyncMock()

        with pytest.raises(Exception, match="not permitted"):
            await kernel.function.process(ctx, call_next)

        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_blocks_pattern_in_args(self, kernel):
        ctx = _make_function_context(
            func_name="web_search",
            arguments={"query": "my password is hunter2"},
        )
        call_next = AsyncMock()

        with pytest.raises(Exception, match="blocked pattern"):
            await kernel.function.process(ctx, call_next)

    @pytest.mark.asyncio
    async def test_blocks_regex_pattern_in_args(self, kernel):
        ctx = _make_function_context(
            func_name="file_read",
            arguments={"path": "rm -rf /"},
        )
        call_next = AsyncMock()

        with pytest.raises(Exception, match="blocked pattern"):
            await kernel.function.process(ctx, call_next)

    @pytest.mark.asyncio
    async def test_enforces_max_tool_calls(self, kernel):
        """Exceeding max_tool_calls (3) should block the 4th call."""
        call_next = AsyncMock()

        # Simulate 3 calls via shared context
        shared_meta = {}
        ctx1 = _make_function_context(func_name="web_search", metadata=shared_meta)
        await kernel.agent.process(
            _make_agent_context(metadata=shared_meta), AsyncMock()
        )
        exec_ctx = shared_meta.get("agent_os_context")

        for i in range(3):
            ctx = _make_function_context(func_name="web_search", metadata=shared_meta)
            await kernel.function.process(ctx, call_next)

        # 4th call should be blocked
        ctx4 = _make_function_context(func_name="web_search", metadata=shared_meta)
        with pytest.raises(Exception, match="limit exceeded"):
            await kernel.function.process(ctx4, call_next)


# --- OutputValidationMiddleware Tests ---


class TestChatMiddleware:
    @pytest.mark.asyncio
    async def test_allows_clean_output(self, kernel):
        ctx = _make_chat_context(result_content="Here are the search results.")
        call_next = AsyncMock()

        await kernel.chat.process(ctx, call_next)

        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_blocks_output_with_blocked_pattern(self, kernel):
        ctx = _make_chat_context(result_content="Your password is hunter2")
        call_next = AsyncMock()

        with pytest.raises(Exception, match="blocked content"):
            await kernel.chat.process(ctx, call_next)

    @pytest.mark.asyncio
    async def test_skips_validation_for_streaming(self, kernel):
        ctx = _make_chat_context(stream=True, result_content="password")
        call_next = AsyncMock()

        # Should not raise even with blocked content — streaming skips validation
        await kernel.chat.process(ctx, call_next)
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_passes_when_no_result(self, kernel):
        ctx = _make_chat_context()
        call_next = AsyncMock()

        await kernel.chat.process(ctx, call_next)
        call_next.assert_awaited_once()
