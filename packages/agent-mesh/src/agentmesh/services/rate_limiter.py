# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Service/proxy-level rate limiting for Agent Mesh.

This module applies token-bucket limits at the trust-proxy service layer with
per-agent and global buckets, backpressure signaling, and configurable thresholds.

See also:
    - hypervisor.security.rate_limiter: runtime-layer per-agent/per-ring limits.
    - agent_os.integrations.rate_limiter: tool-call policy limits in Agent OS.
    - agentmesh.services.rate_limit_middleware: HTTP edge middleware in Agent Mesh.
    - agent_os.policies.rate_limiting: shared token-bucket primitives.
"""

import time
import threading
from typing import Optional

from pydantic import BaseModel, Field


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""

    global_rate: float = 100.0
    global_capacity: int = 200
    per_agent_rate: float = 10.0
    per_agent_capacity: int = 20
    backpressure_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Fraction of capacity at which backpressure is signaled",
    )


class RateLimitResult(BaseModel):
    """Result of a rate limit check."""

    allowed: bool
    remaining_tokens: float
    retry_after_seconds: Optional[float] = None
    backpressure: bool


class TokenBucket:
    """Token bucket algorithm for rate limiting.

    Args:
        rate: Tokens added per second.
        capacity: Maximum burst size (max tokens in the bucket).
    """

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def tokens_available(self) -> float:
        """Current token count after refill."""
        with self._lock:
            self._refill()
            return self._tokens

    def time_until_available(self, tokens: int = 1) -> float:
        """Seconds until the requested number of tokens are available."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                return 0.0
            deficit = tokens - self._tokens
            return deficit / self._rate if self._rate > 0 else float("inf")


class RateLimiter:
    """Per-agent and global rate limiter using token buckets.

    Args:
        global_rate: Global tokens per second.
        global_capacity: Global max burst.
        per_agent_rate: Per-agent tokens per second.
        per_agent_capacity: Per-agent max burst.
        backpressure_threshold: Fraction of capacity at which backpressure is signaled.
    """

    def __init__(
        self,
        global_rate: float = 100,
        global_capacity: int = 200,
        per_agent_rate: float = 10,
        per_agent_capacity: int = 20,
        backpressure_threshold: float = 0.8,
        max_agent_buckets: int = 100_000,
    ) -> None:
        self._global_bucket = TokenBucket(rate=global_rate, capacity=global_capacity)
        self._per_agent_rate = per_agent_rate
        self._per_agent_capacity = per_agent_capacity
        self._agent_buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._global_capacity = global_capacity
        self._per_agent_capacity_val = per_agent_capacity
        self._backpressure_threshold = backpressure_threshold
        self._max_agent_buckets = max_agent_buckets

    def _get_agent_bucket(self, agent_did: str) -> TokenBucket:
        """Get or create a per-agent token bucket."""
        with self._lock:
            if agent_did not in self._agent_buckets:
                # V23: Evict oldest buckets when limit reached
                if len(self._agent_buckets) >= self._max_agent_buckets:
                    oldest_key = next(iter(self._agent_buckets))
                    del self._agent_buckets[oldest_key]
                self._agent_buckets[agent_did] = TokenBucket(
                    rate=self._per_agent_rate,
                    capacity=self._per_agent_capacity,
                )
            return self._agent_buckets[agent_did]

    def allow(self, agent_did: str) -> bool:
        """Check both per-agent and global limits. Returns True if allowed."""
        agent_bucket = self._get_agent_bucket(agent_did)
        if not agent_bucket.consume():
            return False
        if not self._global_bucket.consume():
            return False
        return True

    def check(self, agent_did: str) -> RateLimitResult:
        """Full rate limit check returning a structured result."""
        agent_bucket = self._get_agent_bucket(agent_did)
        allowed = self.allow(agent_did)

        remaining = min(
            agent_bucket.tokens_available(),
            self._global_bucket.tokens_available(),
        )

        retry_after: Optional[float] = None
        if not allowed:
            retry_after = max(
                agent_bucket.time_until_available(),
                self._global_bucket.time_until_available(),
            )

        usage_ratio = 1.0 - (remaining / max(self._per_agent_capacity_val, 1))
        backpressure = usage_ratio >= self._backpressure_threshold

        return RateLimitResult(
            allowed=allowed,
            remaining_tokens=remaining,
            retry_after_seconds=retry_after,
            backpressure=backpressure,
        )

    def get_status(self, agent_did: Optional[str] = None) -> dict:
        """Current rate limit status.

        Args:
            agent_did: If provided, include per-agent status. Otherwise global only.
        """
        status: dict = {
            "global_tokens": self._global_bucket.tokens_available(),
            "global_capacity": self._global_capacity,
        }
        if agent_did is not None:
            bucket = self._get_agent_bucket(agent_did)
            status["agent_did"] = agent_did
            status["agent_tokens"] = bucket.tokens_available()
            status["agent_capacity"] = self._per_agent_capacity_val
        return status

    def reset(self, agent_did: Optional[str] = None) -> None:
        """Reset limits for an agent or all agents.

        Args:
            agent_did: If provided, reset only that agent. Otherwise reset everything.
        """
        if agent_did is not None:
            with self._lock:
                if agent_did in self._agent_buckets:
                    self._agent_buckets[agent_did] = TokenBucket(
                        rate=self._per_agent_rate,
                        capacity=self._per_agent_capacity,
                    )
        else:
            with self._lock:
                self._agent_buckets.clear()
            self._global_bucket = TokenBucket(
                rate=self._global_bucket._rate,
                capacity=self._global_capacity,
            )
