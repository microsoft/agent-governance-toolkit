# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for token bucket rate limiter and middleware."""

import time

import pytest

from agentmesh.services.rate_limiter import (
    RateLimitConfig,
    RateLimitResult,
    RateLimiter,
    TokenBucket,
)
from agentmesh.services.rate_limit_middleware import (
    HEADER_AGENT_DID,
    HEADER_BACKPRESSURE,
    HEADER_RATELIMIT_REMAINING,
    HEADER_RETRY_AFTER,
    RateLimitMiddleware,
    SimpleRequest,
    SimpleResponse,
)


# ---------------------------------------------------------------------------
# TokenBucket tests
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_initial_capacity(self) -> None:
        bucket = TokenBucket(rate=10, capacity=20)
        assert bucket.tokens_available() == pytest.approx(20, abs=1)

    def test_consume_success(self) -> None:
        bucket = TokenBucket(rate=10, capacity=5)
        assert bucket.consume(3) is True
        assert bucket.tokens_available() < 5

    def test_consume_failure(self) -> None:
        bucket = TokenBucket(rate=1, capacity=2)
        assert bucket.consume(3) is False
        # Tokens should not have been consumed on failure
        assert bucket.tokens_available() == pytest.approx(2, abs=0.5)

    def test_burst_up_to_capacity(self) -> None:
        bucket = TokenBucket(rate=1, capacity=5)
        for _ in range(5):
            assert bucket.consume() is True
        assert bucket.consume() is False

    def test_refill_over_time(self) -> None:
        bucket = TokenBucket(rate=100, capacity=10)
        # Drain completely
        for _ in range(10):
            bucket.consume()
        assert bucket.tokens_available() < 1

        # Wait for refill
        time.sleep(0.1)  # 100 tokens/sec * 0.1s = ~10 tokens
        assert bucket.tokens_available() >= 5

    def test_time_until_available_zero_when_enough(self) -> None:
        bucket = TokenBucket(rate=10, capacity=10)
        assert bucket.time_until_available(1) == 0.0

    def test_time_until_available_positive_when_empty(self) -> None:
        bucket = TokenBucket(rate=10, capacity=5)
        for _ in range(5):
            bucket.consume()
        wait = bucket.time_until_available(1)
        assert wait > 0


# ---------------------------------------------------------------------------
# RateLimiter tests
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_allow_within_limits(self) -> None:
        limiter = RateLimiter(global_rate=100, global_capacity=200, per_agent_rate=10, per_agent_capacity=20)
        assert limiter.allow("did:mesh:agent1") is True

    def test_per_agent_isolation(self) -> None:
        limiter = RateLimiter(
            global_rate=1000,
            global_capacity=2000,
            per_agent_rate=5,
            per_agent_capacity=5,
        )
        # Exhaust agent1's tokens
        for _ in range(5):
            limiter.allow("did:mesh:agent1")
        assert limiter.allow("did:mesh:agent1") is False
        # Agent2 should still work
        assert limiter.allow("did:mesh:agent2") is True

    def test_global_limit_applies_to_all(self) -> None:
        limiter = RateLimiter(
            global_rate=1,
            global_capacity=3,
            per_agent_rate=100,
            per_agent_capacity=100,
        )
        assert limiter.allow("did:mesh:a") is True
        assert limiter.allow("did:mesh:b") is True
        assert limiter.allow("did:mesh:c") is True
        # Global bucket exhausted
        assert limiter.allow("did:mesh:d") is False

    def test_get_status_global(self) -> None:
        limiter = RateLimiter()
        status = limiter.get_status()
        assert "global_tokens" in status
        assert "global_capacity" in status

    def test_get_status_with_agent(self) -> None:
        limiter = RateLimiter()
        status = limiter.get_status("did:mesh:x")
        assert status["agent_did"] == "did:mesh:x"
        assert "agent_tokens" in status

    def test_reset_single_agent(self) -> None:
        limiter = RateLimiter(per_agent_rate=5, per_agent_capacity=5)
        for _ in range(5):
            limiter.allow("did:mesh:agent1")
        assert limiter.allow("did:mesh:agent1") is False
        limiter.reset("did:mesh:agent1")
        assert limiter.allow("did:mesh:agent1") is True

    def test_reset_all(self) -> None:
        limiter = RateLimiter(
            global_rate=1,
            global_capacity=2,
            per_agent_rate=100,
            per_agent_capacity=100,
        )
        limiter.allow("did:mesh:a")
        limiter.allow("did:mesh:b")
        assert limiter.allow("did:mesh:c") is False
        limiter.reset()
        assert limiter.allow("did:mesh:c") is True

    def test_backpressure_signaled_near_capacity(self) -> None:
        limiter = RateLimiter(
            global_rate=1000,
            global_capacity=2000,
            per_agent_rate=10,
            per_agent_capacity=10,
            backpressure_threshold=0.5,
        )
        # Consume enough to cross 50% usage
        for _ in range(6):
            limiter.allow("did:mesh:agent1")
        result = limiter.check("did:mesh:agent1")
        assert result.backpressure is True

    def test_check_returns_result_model(self) -> None:
        limiter = RateLimiter()
        result = limiter.check("did:mesh:x")
        assert isinstance(result, RateLimitResult)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TestModels:
    def test_rate_limit_config_defaults(self) -> None:
        config = RateLimitConfig()
        assert config.global_rate == 100.0
        assert config.backpressure_threshold == 0.8

    def test_rate_limit_result_serialization(self) -> None:
        result = RateLimitResult(
            allowed=True,
            remaining_tokens=42.0,
            retry_after_seconds=None,
            backpressure=False,
        )
        data = result.model_dump()
        assert data["allowed"] is True
        assert data["remaining_tokens"] == 42.0


# ---------------------------------------------------------------------------
# Middleware tests
# ---------------------------------------------------------------------------


def _ok_handler(request: SimpleRequest) -> SimpleResponse:
    return SimpleResponse(status_code=200, body="OK")


class TestRateLimitMiddleware:
    def test_allowed_request_has_headers(self) -> None:
        limiter = RateLimiter()
        mw = RateLimitMiddleware(limiter)
        req = SimpleRequest(headers={HEADER_AGENT_DID: "did:mesh:agent1"})
        resp = mw.handle(req, _ok_handler)
        assert resp.status_code == 200
        assert HEADER_RATELIMIT_REMAINING in resp.headers

    def test_429_when_rate_limited(self) -> None:
        limiter = RateLimiter(
            global_rate=1000,
            global_capacity=2000,
            per_agent_rate=1,
            per_agent_capacity=1,
        )
        mw = RateLimitMiddleware(limiter)
        req = SimpleRequest(headers={HEADER_AGENT_DID: "did:mesh:agent1"})
        # First request consumes via check() then allow() - exhaust quickly
        mw.handle(req, _ok_handler)
        # Next attempts should be rejected
        resp2 = mw.handle(req, _ok_handler)
        assert resp2.status_code == 429

    def test_retry_after_header_on_429(self) -> None:
        limiter = RateLimiter(
            global_rate=1000,
            global_capacity=2000,
            per_agent_rate=1,
            per_agent_capacity=1,
        )
        mw = RateLimitMiddleware(limiter)
        req = SimpleRequest(headers={HEADER_AGENT_DID: "did:mesh:agent1"})
        mw.handle(req, _ok_handler)
        resp = mw.handle(req, _ok_handler)
        assert resp.status_code == 429
        assert HEADER_RETRY_AFTER in resp.headers
        assert float(resp.headers[HEADER_RETRY_AFTER]) > 0

    def test_backpressure_header(self) -> None:
        limiter = RateLimiter(
            global_rate=1000,
            global_capacity=2000,
            per_agent_rate=10,
            per_agent_capacity=10,
            backpressure_threshold=0.5,
        )
        mw = RateLimitMiddleware(limiter)
        req = SimpleRequest(headers={HEADER_AGENT_DID: "did:mesh:agent1"})
        # Consume enough tokens to trigger backpressure
        for _ in range(6):
            mw.handle(req, _ok_handler)
        resp = mw.handle(req, _ok_handler)
        if resp.status_code == 200:
            assert resp.headers.get(HEADER_BACKPRESSURE) == "true"

    def test_anonymous_fallback(self) -> None:
        limiter = RateLimiter()
        mw = RateLimitMiddleware(limiter, default_agent_did="anon")
        req = SimpleRequest()  # no DID header
        resp = mw.handle(req, _ok_handler)
        assert resp.status_code == 200
