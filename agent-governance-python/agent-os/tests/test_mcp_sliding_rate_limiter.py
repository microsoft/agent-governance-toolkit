# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the MCP sliding-window rate limiter."""

from __future__ import annotations

import threading
import time

import pytest

from agent_os.mcp_protocols import InMemoryRateLimitStore
from agent_os.mcp_sliding_rate_limiter import MCPSlidingRateLimiter


def test_try_acquire_enforces_limit():
    limiter = MCPSlidingRateLimiter(max_calls_per_window=2, window_size=1.0)

    assert limiter.try_acquire("agent-1") is True
    assert limiter.try_acquire("agent-1") is True
    assert limiter.try_acquire("agent-1") is False


def test_window_expiry_restores_budget():
    limiter = MCPSlidingRateLimiter(max_calls_per_window=1, window_size=0.05)

    assert limiter.try_acquire("agent-1") is True
    assert limiter.try_acquire("agent-1") is False

    time.sleep(0.08)

    assert limiter.try_acquire("agent-1") is True


def test_case_insensitive_agent_ids_share_budget():
    limiter = MCPSlidingRateLimiter(max_calls_per_window=1, window_size=1.0)

    assert limiter.try_acquire("Agent-A") is True
    assert limiter.try_acquire("agent-a") is False


def test_remaining_budget_and_cleanup():
    limiter = MCPSlidingRateLimiter(max_calls_per_window=3, window_size=0.05)
    limiter.try_acquire("agent-1")
    limiter.try_acquire("agent-1")

    assert limiter.get_remaining_budget("agent-1") == 1
    assert limiter.get_call_count("agent-1") == 2

    time.sleep(0.08)

    assert limiter.cleanup_expired() == 2
    assert limiter.get_call_count("agent-1") == 0


def test_concurrent_access_does_not_exceed_limit():
    limiter = MCPSlidingRateLimiter(max_calls_per_window=25, window_size=60.0)
    total_allowed = 0
    lock = threading.Lock()

    def worker():
        nonlocal total_allowed
        for _ in range(15):
            if limiter.try_acquire("shared-agent"):
                with lock:
                    total_allowed += 1

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert total_allowed == 25


def test_invalid_agent_id_raises():
    limiter = MCPSlidingRateLimiter()

    with pytest.raises(ValueError, match="agent_id"):
        limiter.try_acquire("")


def test_clock_and_store_injection():
    current_time = 100.0

    def clock() -> float:
        return current_time

    store = InMemoryRateLimitStore()
    limiter = MCPSlidingRateLimiter(
        max_calls_per_window=2,
        window_size=5.0,
        rate_limit_store=store,
        clock=clock,
    )

    assert limiter.try_acquire("agent-1") is True
    assert limiter.try_acquire("agent-1") is True
    assert limiter.try_acquire("agent-1") is False
    assert store.get_bucket("agent-1") == [100.0, 100.0]

    current_time = 106.0
    assert limiter.try_acquire("agent-1") is True
