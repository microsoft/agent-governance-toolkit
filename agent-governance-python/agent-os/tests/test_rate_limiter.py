# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for RateLimiter.

Run with: python -m pytest tests/test_rate_limiter.py -v --tb=short
"""

import threading
import time

import pytest

from agent_os.integrations.base import GovernancePolicy
from agent_os.integrations.rate_limiter import RateLimiter, RateLimitStatus


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def limiter():
    return RateLimiter(max_calls=5, time_window=1.0)


@pytest.fixture
def global_limiter():
    return RateLimiter(max_calls=3, time_window=1.0, per_agent=False)


# =============================================================================
# Basic allow / deny
# =============================================================================


class TestAllow:
    def test_allow_under_limit(self, limiter):
        assert limiter.allow("agent-1") is True

    def test_allow_exhausts_bucket(self, limiter):
        for _ in range(5):
            assert limiter.allow("agent-1") is True
        assert limiter.allow("agent-1") is False

    def test_agents_are_independent(self, limiter):
        for _ in range(5):
            limiter.allow("a")
        # agent "a" exhausted, but "b" should still have tokens
        assert limiter.allow("a") is False
        assert limiter.allow("b") is True


# =============================================================================
# Global (per_agent=False) mode
# =============================================================================


class TestGlobalMode:
    def test_shared_bucket(self, global_limiter):
        assert global_limiter.allow("a") is True
        assert global_limiter.allow("b") is True
        assert global_limiter.allow("c") is True
        # bucket exhausted globally
        assert global_limiter.allow("d") is False


# =============================================================================
# Check (non-consuming)
# =============================================================================


class TestCheck:
    def test_check_does_not_consume(self, limiter):
        status = limiter.check("agent-1")
        assert status.allowed is True
        assert status.remaining_calls == 5
        # calling check again should not reduce tokens
        status2 = limiter.check("agent-1")
        assert status2.remaining_calls == 5

    def test_check_after_exhaustion(self, limiter):
        for _ in range(5):
            limiter.allow("a")
        status = limiter.check("a")
        assert status.allowed is False
        assert status.remaining_calls == 0
        assert status.wait_seconds > 0

    def test_check_returns_dataclass(self, limiter):
        status = limiter.check("a")
        assert isinstance(status, RateLimitStatus)


# =============================================================================
# wait_time
# =============================================================================


class TestWaitTime:
    def test_zero_when_available(self, limiter):
        assert limiter.wait_time("a") == 0.0

    def test_positive_when_exhausted(self, limiter):
        for _ in range(5):
            limiter.allow("a")
        assert limiter.wait_time("a") > 0


# =============================================================================
# Token refill
# =============================================================================


class TestRefill:
    def test_tokens_refill_over_time(self):
        limiter = RateLimiter(max_calls=5, time_window=0.2)
        for _ in range(5):
            limiter.allow("a")
        assert limiter.allow("a") is False
        # Wait for refill
        time.sleep(0.25)
        assert limiter.allow("a") is True


# =============================================================================
# Reset
# =============================================================================


class TestReset:
    def test_reset_restores_tokens(self, limiter):
        for _ in range(5):
            limiter.allow("a")
        assert limiter.allow("a") is False
        limiter.reset("a")
        assert limiter.allow("a") is True

    def test_reset_unknown_agent_is_noop(self, limiter):
        limiter.reset("nonexistent")  # should not raise


# =============================================================================
# GovernancePolicy integration
# =============================================================================


class TestPolicyIntegration:
    def test_uses_policy_max_tool_calls(self):
        policy = GovernancePolicy(max_tool_calls=3)
        limiter = RateLimiter(policy=policy, time_window=1.0)
        for _ in range(3):
            assert limiter.allow("a") is True
        assert limiter.allow("a") is False

    def test_policy_overrides_default(self):
        policy = GovernancePolicy(max_tool_calls=2)
        limiter = RateLimiter(max_calls=100, policy=policy, time_window=1.0)
        assert limiter.check("a").remaining_calls == 2


# =============================================================================
# Validation
# =============================================================================


class TestValidation:
    def test_invalid_max_calls_zero(self):
        with pytest.raises(ValueError, match="max_calls"):
            RateLimiter(max_calls=0)

    def test_invalid_max_calls_negative(self):
        with pytest.raises(ValueError, match="max_calls"):
            RateLimiter(max_calls=-1)

    def test_invalid_time_window_zero(self):
        with pytest.raises(ValueError, match="time_window"):
            RateLimiter(time_window=0)

    def test_invalid_time_window_negative(self):
        with pytest.raises(ValueError, match="time_window"):
            RateLimiter(time_window=-1)


# =============================================================================
# RateLimitStatus frozen dataclass
# =============================================================================


class TestRateLimitStatus:
    def test_status_is_immutable(self):
        status = RateLimitStatus(
            allowed=True, remaining_calls=5, reset_at=100.0, wait_seconds=0.0
        )
        with pytest.raises(AttributeError):
            status.allowed = False


# =============================================================================
# Thread safety
# =============================================================================


class TestThreadSafety:
    def test_concurrent_allow(self):
        limiter = RateLimiter(max_calls=1000, time_window=60.0)
        errors = []
        successes = []

        def worker():
            count = 0
            try:
                for _ in range(250):
                    if limiter.allow("shared"):
                        count += 1
            except Exception as exc:
                errors.append(exc)
            successes.append(count)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert sum(successes) == 1000
