# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import time
import pytest
from agent_rag_governance.rate_limiter import RateLimiter


def test_zero_limit_always_allows():
    limiter = RateLimiter()
    for _ in range(1000):
        assert limiter.check("agent", limit=0) is True


def test_under_limit_passes():
    limiter = RateLimiter()
    for _ in range(5):
        assert limiter.check("agent", limit=10) is True


def test_at_limit_fails():
    limiter = RateLimiter()
    for _ in range(10):
        limiter.check("agent", limit=10)
    assert limiter.check("agent", limit=10) is False


def test_different_agents_independent():
    limiter = RateLimiter()
    for _ in range(10):
        limiter.check("agent-a", limit=10)
    # agent-a is at limit, agent-b should still pass
    assert limiter.check("agent-b", limit=10) is True


def test_reset_clears_state():
    limiter = RateLimiter()
    for _ in range(10):
        limiter.check("agent", limit=10)
    assert limiter.check("agent", limit=10) is False
    limiter.reset("agent")
    assert limiter.check("agent", limit=10) is True


def test_window_expiry():
    limiter = RateLimiter(window_seconds=1)
    for _ in range(5):
        limiter.check("agent", limit=5)
    assert limiter.check("agent", limit=5) is False
    time.sleep(1.1)
    assert limiter.check("agent", limit=5) is True
