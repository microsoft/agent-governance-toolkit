# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for async adapter wrap/unwrap support.

Covers: async_pre_execute, async_post_execute, AsyncGovernedWrapper.
Uses pytest-asyncio — no real API calls.

Run with: python -m pytest tests/test_async_adapters.py -v --tb=short
"""

import asyncio
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.base import (
    AsyncGovernedWrapper,
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    PolicyViolationError,
)


# =============================================================================
# Helpers
# =============================================================================


class DummyIntegration(BaseIntegration):
    """Minimal concrete subclass for testing."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


async def _async_echo(*args: Any, **kwargs: Any) -> dict:
    """Simple async callable for testing."""
    return {"args": args, "kwargs": kwargs}


async def _async_add(a: int, b: int) -> int:
    return a + b


# =============================================================================
# Tests: async_pre_execute defaults to sync
# =============================================================================


@pytest.mark.asyncio
async def test_async_pre_execute_defaults_to_sync():
    """async_pre_execute should delegate to sync pre_execute by default."""
    integration = DummyIntegration()
    ctx = integration.create_context("test-agent")

    allowed, reason = await integration.async_pre_execute(ctx, "hello")
    assert allowed is True
    assert reason is None


@pytest.mark.asyncio
async def test_async_pre_execute_blocks_like_sync():
    """async_pre_execute should respect blocked patterns just like sync."""
    policy = GovernancePolicy(blocked_patterns=["secret"])
    integration = DummyIntegration(policy=policy)
    ctx = integration.create_context("test-agent")

    allowed, reason = await integration.async_pre_execute(ctx, "this has a secret")
    assert allowed is False
    assert "secret" in reason


# =============================================================================
# Tests: async_post_execute defaults to sync
# =============================================================================


@pytest.mark.asyncio
async def test_async_post_execute_defaults_to_sync():
    """async_post_execute should delegate to sync post_execute by default."""
    integration = DummyIntegration()
    ctx = integration.create_context("test-agent")

    valid, reason = await integration.async_post_execute(ctx, "result")
    assert valid is True
    assert reason is None
    assert ctx.call_count == 1


@pytest.mark.asyncio
async def test_async_post_execute_increments_call_count():
    """Each async_post_execute call should increment call_count."""
    integration = DummyIntegration()
    ctx = integration.create_context("test-agent")

    for i in range(3):
        await integration.async_post_execute(ctx, f"result-{i}")
    assert ctx.call_count == 3


# =============================================================================
# Tests: AsyncGovernedWrapper with passing policy
# =============================================================================


@pytest.mark.asyncio
async def test_governed_wrapper_passes():
    """Wrapper should call through and return result when policy allows."""
    integration = DummyIntegration()
    wrapper = AsyncGovernedWrapper(integration, _async_add, agent_id="add-agent")

    result = await wrapper(2, 3)
    assert result == 5


@pytest.mark.asyncio
async def test_governed_wrapper_tracks_calls():
    """Wrapper should increment call_count after each successful call."""
    integration = DummyIntegration()
    wrapper = AsyncGovernedWrapper(integration, _async_echo, agent_id="echo-agent")

    await wrapper("a")
    await wrapper("b")
    assert wrapper.context.call_count == 2


# =============================================================================
# Tests: AsyncGovernedWrapper with blocking policy
# =============================================================================


@pytest.mark.asyncio
async def test_governed_wrapper_blocks_on_pattern():
    """Wrapper should raise PolicyViolationError when input matches blocked pattern."""
    policy = GovernancePolicy(blocked_patterns=["forbidden"])
    integration = DummyIntegration(policy=policy)
    wrapper = AsyncGovernedWrapper(integration, _async_echo, agent_id="block-agent")

    with pytest.raises(PolicyViolationError, match="forbidden"):
        await wrapper("forbidden input")


@pytest.mark.asyncio
async def test_governed_wrapper_blocks_on_max_calls():
    """Wrapper should raise PolicyViolationError when max_tool_calls exceeded."""
    policy = GovernancePolicy(max_tool_calls=2)
    integration = DummyIntegration(policy=policy)
    wrapper = AsyncGovernedWrapper(integration, _async_echo, agent_id="limit-agent")

    await wrapper("call-1")
    await wrapper("call-2")

    with pytest.raises(PolicyViolationError, match="Max tool calls exceeded"):
        await wrapper("call-3")


# =============================================================================
# Tests: concurrent access with asyncio.Lock
# =============================================================================


@pytest.mark.asyncio
async def test_concurrent_access_serialized():
    """Concurrent calls should be serialized by the asyncio.Lock."""
    order: list[str] = []

    async def slow_fn(label: str) -> str:
        order.append(f"start-{label}")
        await asyncio.sleep(0.05)
        order.append(f"end-{label}")
        return label

    integration = DummyIntegration()
    wrapper = AsyncGovernedWrapper(integration, slow_fn, agent_id="concurrent-agent")

    # Launch two concurrent calls
    results = await asyncio.gather(wrapper("A"), wrapper("B"))

    assert set(results) == {"A", "B"}
    # Because of the lock, calls are serialized: start-X, end-X, start-Y, end-Y
    assert order[0].startswith("start-")
    assert order[1].startswith("end-")
    assert order[2].startswith("start-")
    assert order[3].startswith("end-")


@pytest.mark.asyncio
async def test_concurrent_call_count_integrity():
    """call_count should be accurate even under concurrent access."""
    async def noop() -> None:
        await asyncio.sleep(0.01)

    integration = DummyIntegration(policy=GovernancePolicy(max_tool_calls=100))
    wrapper = AsyncGovernedWrapper(integration, noop, agent_id="count-agent")

    await asyncio.gather(*(wrapper() for _ in range(20)))
    assert wrapper.context.call_count == 20


# =============================================================================
# Tests: sync methods still work unchanged (backward compatibility)
# =============================================================================


def test_sync_pre_execute_unchanged():
    """Sync pre_execute should still work as before."""
    integration = DummyIntegration()
    ctx = integration.create_context("sync-agent")
    allowed, reason = integration.pre_execute(ctx, "hello")
    assert allowed is True


def test_sync_post_execute_unchanged():
    """Sync post_execute should still work as before."""
    integration = DummyIntegration()
    ctx = integration.create_context("sync-agent")
    valid, reason = integration.post_execute(ctx, "result")
    assert valid is True
    assert ctx.call_count == 1
