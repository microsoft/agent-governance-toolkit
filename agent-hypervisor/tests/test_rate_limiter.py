# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for per-agent rate limiter."""

from datetime import UTC, datetime, timedelta

import pytest

from hypervisor.models import ExecutionRing
from hypervisor.security.rate_limiter import (
    DEFAULT_RING_LIMITS,
    AgentRateLimiter,
    RateLimitExceeded,
    RateLimitStats,
    TokenBucket,
)


class TestTokenBucket:
    def test_init(self):
        bucket = TokenBucket(capacity=10.0, tokens=10.0, refill_rate=5.0)
        assert bucket.capacity == 10.0
        assert bucket.tokens == 10.0
        assert bucket.refill_rate == 5.0
        assert isinstance(bucket.last_refill, datetime)

    def test_consume_success(self):
        bucket = TokenBucket(capacity=10.0, tokens=10.0, refill_rate=1.0)
        assert bucket.consume(1.0) is True

    def test_consume_all_tokens(self):
        bucket = TokenBucket(capacity=5.0, tokens=5.0, refill_rate=0.0)
        for _ in range(5):
            assert bucket.consume(1.0) is True
        # Tokens should be exhausted (no refill since rate=0 and very fast)
        # Need to account for possible tiny refill, so set last_refill to now
        bucket.last_refill = datetime.now(UTC)
        bucket.tokens = 0.0
        assert bucket.consume(1.0) is False

    def test_consume_insufficient(self):
        bucket = TokenBucket(capacity=10.0, tokens=0.0, refill_rate=0.0)
        bucket.last_refill = datetime.now(UTC)
        assert bucket.consume(1.0) is False

    def test_consume_exact_amount(self):
        bucket = TokenBucket(capacity=5.0, tokens=3.0, refill_rate=0.0)
        bucket.last_refill = datetime.now(UTC)
        assert bucket.consume(3.0) is True

    def test_refill_over_time(self):
        bucket = TokenBucket(capacity=10.0, tokens=0.0, refill_rate=100.0)
        # Simulate time passing by setting last_refill in the past
        bucket.last_refill = datetime.now(UTC) - timedelta(seconds=1)
        assert bucket.consume(5.0) is True

    def test_refill_caps_at_capacity(self):
        bucket = TokenBucket(capacity=10.0, tokens=0.0, refill_rate=100.0)
        bucket.last_refill = datetime.now(UTC) - timedelta(seconds=10)
        assert bucket.available <= 10.0

    def test_available_property(self):
        bucket = TokenBucket(capacity=10.0, tokens=5.0, refill_rate=0.0)
        bucket.last_refill = datetime.now(UTC)
        assert bucket.available == pytest.approx(5.0, abs=0.1)


class TestRateLimitExceeded:
    def test_is_exception(self):
        exc = RateLimitExceeded("too fast")
        assert isinstance(exc, Exception)
        assert str(exc) == "too fast"


class TestRateLimitStats:
    def test_defaults(self):
        stats = RateLimitStats(agent_did="a1", ring=ExecutionRing.RING_3_SANDBOX)
        assert stats.total_requests == 0
        assert stats.rejected_requests == 0
        assert stats.tokens_available == 0.0
        assert stats.capacity == 0.0


class TestAgentRateLimiter:
    def test_init_defaults(self):
        limiter = AgentRateLimiter()
        assert limiter.tracked_agents == 0

    def test_init_custom_limits(self):
        custom = {ExecutionRing.RING_3_SANDBOX: (1.0, 2.0)}
        limiter = AgentRateLimiter(ring_limits=custom)
        assert limiter._limits == custom

    def test_check_success(self):
        limiter = AgentRateLimiter()
        assert limiter.check("agent1", "sess1", ExecutionRing.RING_2_STANDARD) is True
        assert limiter.tracked_agents == 1

    def test_check_exceeds_limit(self):
        # Use tiny bucket to force exhaustion
        limiter = AgentRateLimiter(
            ring_limits={ExecutionRing.RING_3_SANDBOX: (0.0, 1.0)}
        )
        # First call consumes the single token
        limiter.check("a1", "s1", ExecutionRing.RING_3_SANDBOX)
        # Second call should fail (no refill since rate=0)
        with pytest.raises(RateLimitExceeded):
            limiter.check("a1", "s1", ExecutionRing.RING_3_SANDBOX)

    def test_try_check_returns_false_on_limit(self):
        limiter = AgentRateLimiter(
            ring_limits={ExecutionRing.RING_3_SANDBOX: (0.0, 1.0)}
        )
        assert limiter.try_check("a1", "s1", ExecutionRing.RING_3_SANDBOX) is True
        assert limiter.try_check("a1", "s1", ExecutionRing.RING_3_SANDBOX) is False

    def test_separate_agents_tracked_independently(self):
        limiter = AgentRateLimiter(
            ring_limits={ExecutionRing.RING_3_SANDBOX: (0.0, 1.0)}
        )
        assert limiter.check("a1", "s1", ExecutionRing.RING_3_SANDBOX) is True
        assert limiter.check("a2", "s1", ExecutionRing.RING_3_SANDBOX) is True
        assert limiter.tracked_agents == 2

    def test_update_ring_resets_bucket(self):
        limiter = AgentRateLimiter()
        limiter.check("a1", "s1", ExecutionRing.RING_3_SANDBOX)
        limiter.update_ring("a1", "s1", ExecutionRing.RING_2_STANDARD)
        # Should succeed with new generous bucket
        assert limiter.check("a1", "s1", ExecutionRing.RING_2_STANDARD) is True

    def test_get_stats(self):
        limiter = AgentRateLimiter()
        limiter.check("a1", "s1", ExecutionRing.RING_2_STANDARD)
        stats = limiter.get_stats("a1", "s1")
        assert stats is not None
        assert stats.agent_did == "a1"
        assert stats.total_requests == 1
        assert stats.rejected_requests == 0

    def test_get_stats_unknown_agent(self):
        limiter = AgentRateLimiter()
        assert limiter.get_stats("unknown", "s1") is None

    def test_stats_track_rejections(self):
        limiter = AgentRateLimiter(
            ring_limits={ExecutionRing.RING_3_SANDBOX: (0.0, 1.0)}
        )
        limiter.check("a1", "s1", ExecutionRing.RING_3_SANDBOX)
        limiter.try_check("a1", "s1", ExecutionRing.RING_3_SANDBOX)
        stats = limiter.get_stats("a1", "s1")
        assert stats.total_requests == 2
        assert stats.rejected_requests == 1

    def test_default_ring_limits_all_present(self):
        assert ExecutionRing.RING_0_ROOT in DEFAULT_RING_LIMITS
        assert ExecutionRing.RING_1_PRIVILEGED in DEFAULT_RING_LIMITS
        assert ExecutionRing.RING_2_STANDARD in DEFAULT_RING_LIMITS
        assert ExecutionRing.RING_3_SANDBOX in DEFAULT_RING_LIMITS
