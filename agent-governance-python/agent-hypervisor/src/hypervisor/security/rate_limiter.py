# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Runtime-layer per-agent/per-ring rate limiting.

This module enforces token-bucket limits per agent, session, and execution ring
inside the hypervisor runtime layer.

See also:
    - agent_os.integrations.rate_limiter: tool-call policy limits in Agent OS.
    - agentmesh.services.rate_limiter: service/proxy-level limits in Agent Mesh.
    - agentmesh.services.rate_limit_middleware: HTTP edge middleware in Agent Mesh.
    - agent_os.policies.rate_limiting: shared token-bucket primitives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from hypervisor.constants import (
    RATE_LIMIT_FALLBACK,
    RATE_LIMIT_RING_0,
    RATE_LIMIT_RING_1,
    RATE_LIMIT_RING_2,
    RATE_LIMIT_RING_3,
)
from hypervisor.models import ExecutionRing


class RateLimitExceeded(Exception):
    """Raised when an agent exceeds their rate limit."""


@dataclass
class TokenBucket:
    """A token bucket for rate limiting."""

    capacity: float
    tokens: float
    refill_rate: float  # tokens per second
    last_refill: datetime = field(default_factory=lambda: datetime.now(UTC))

    def consume(self, tokens: float = 1.0) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = datetime.now(UTC)
        elapsed = (now - self.last_refill).total_seconds()
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    @property
    def available(self) -> float:
        self._refill()
        return self.tokens


# Default rate limits per ring (requests per second, burst capacity)
DEFAULT_RING_LIMITS: dict[ExecutionRing, tuple[float, float]] = {
    ExecutionRing.RING_0_ROOT: RATE_LIMIT_RING_0,
    ExecutionRing.RING_1_PRIVILEGED: RATE_LIMIT_RING_1,
    ExecutionRing.RING_2_STANDARD: RATE_LIMIT_RING_2,
    ExecutionRing.RING_3_SANDBOX: RATE_LIMIT_RING_3,
}


@dataclass
class RateLimitStats:
    """Statistics for an agent's rate limiting."""

    agent_did: str
    ring: ExecutionRing
    total_requests: int = 0
    rejected_requests: int = 0
    tokens_available: float = 0.0
    capacity: float = 0.0


class AgentRateLimiter:
    """
    Rate limiting per agent per ring using token buckets.

    Higher-privilege rings get more generous limits. When an agent
    is promoted/demoted, their bucket is recreated with new limits.
    """

    def __init__(
        self,
        ring_limits: dict[ExecutionRing, tuple[float, float]] | None = None,
    ) -> None:
        self._limits = ring_limits or dict(DEFAULT_RING_LIMITS)
        # (agent_did, session_id) -> TokenBucket
        self._buckets: dict[str, TokenBucket] = {}
        self._stats: dict[str, RateLimitStats] = {}

    def check(
        self,
        agent_did: str,
        session_id: str,
        ring: ExecutionRing,
        cost: float = 1.0,
    ) -> bool:
        """
        Check if an agent can make a request.

        Returns True if allowed, raises RateLimitExceeded if not.
        """
        key = f"{agent_did}:{session_id}"
        bucket = self._get_or_create_bucket(key, ring)

        # Track stats
        stats = self._stats.setdefault(
            key,
            RateLimitStats(agent_did=agent_did, ring=ring),
        )
        stats.total_requests += 1

        if not bucket.consume(cost):
            stats.rejected_requests += 1
            raise RateLimitExceeded(
                f"Agent {agent_did} exceeded rate limit for ring "
                f"{ring.value} ({stats.rejected_requests} rejections)"
            )
        return True

    def try_check(
        self,
        agent_did: str,
        session_id: str,
        ring: ExecutionRing,
        cost: float = 1.0,
    ) -> bool:
        """Like check(), but returns False instead of raising."""
        try:
            return self.check(agent_did, session_id, ring, cost)
        except RateLimitExceeded:
            return False

    def update_ring(
        self,
        agent_did: str,
        session_id: str,
        new_ring: ExecutionRing,
    ) -> None:
        """Update an agent's rate limit when their ring changes."""
        key = f"{agent_did}:{session_id}"
        rate, capacity = self._limits.get(
            new_ring, RATE_LIMIT_FALLBACK
        )
        self._buckets[key] = TokenBucket(
            capacity=capacity,
            tokens=capacity,  # Start full
            refill_rate=rate,
        )
        if key in self._stats:
            self._stats[key].ring = new_ring

    def get_stats(self, agent_did: str, session_id: str) -> RateLimitStats | None:
        """Get rate limit stats for an agent."""
        key = f"{agent_did}:{session_id}"
        stats = self._stats.get(key)
        if stats:
            bucket = self._buckets.get(key)
            if bucket:
                stats.tokens_available = bucket.available
                stats.capacity = bucket.capacity
        return stats

    def _get_or_create_bucket(
        self, key: str, ring: ExecutionRing
    ) -> TokenBucket:
        if key not in self._buckets:
            rate, capacity = self._limits.get(ring, RATE_LIMIT_FALLBACK)
            self._buckets[key] = TokenBucket(
                capacity=capacity,
                tokens=capacity,
                refill_rate=rate,
            )
        return self._buckets[key]

    @property
    def tracked_agents(self) -> int:
        return len(self._buckets)
