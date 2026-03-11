"""Token bucket rate limiter node for Flowise flows."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    agent_id: str | None = None
    action: str | None = None
    remaining_tokens: float = 0.0
    retry_after: float | None = None


@dataclass
class _Bucket:
    """Internal token bucket state."""

    tokens: float
    max_tokens: float
    last_refill: float
    refill_rate: float  # tokens per second

    def refill(self, now: float) -> None:
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, now: float) -> bool:
        self.refill(now)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def time_until_available(self, now: float) -> float:
        self.refill(now)
        if self.tokens >= 1.0:
            return 0.0
        needed = 1.0 - self.tokens
        return needed / self.refill_rate


class RateLimiterNode:
    """Token bucket rate limiter with per-agent and per-action limits.

    Each unique (agent_id, action) pair gets its own bucket.
    """

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: float = 60.0,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._refill_rate = max_requests / window_seconds
        self._buckets: dict[str, _Bucket] = {}

    def _get_bucket(self, key: str, now: float) -> _Bucket:
        if key not in self._buckets:
            self._buckets[key] = _Bucket(
                tokens=float(self.max_requests),
                max_tokens=float(self.max_requests),
                last_refill=now,
                refill_rate=self._refill_rate,
            )
        return self._buckets[key]

    def check(
        self,
        agent_id: str | None = None,
        action: str | None = None,
        now: float | None = None,
    ) -> RateLimitResult:
        """Check and consume a token for the given agent/action pair."""
        ts = now if now is not None else time.time()
        key = f"{agent_id or '*'}:{action or '*'}"
        bucket = self._get_bucket(key, ts)

        if bucket.consume(ts):
            return RateLimitResult(
                allowed=True,
                agent_id=agent_id,
                action=action,
                remaining_tokens=bucket.tokens,
            )

        retry_after = bucket.time_until_available(ts)
        return RateLimitResult(
            allowed=False,
            agent_id=agent_id,
            action=action,
            remaining_tokens=bucket.tokens,
            retry_after=retry_after,
        )

    def reset(self, agent_id: str | None = None, action: str | None = None) -> None:
        """Reset the bucket for a specific agent/action pair, or all buckets."""
        if agent_id is None and action is None:
            self._buckets.clear()
        else:
            key = f"{agent_id or '*'}:{action or '*'}"
            self._buckets.pop(key, None)

    def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Flowise-compatible run method."""
        result = self.check(
            agent_id=input_data.get("agent_id"),
            action=input_data.get("action"),
        )
        return {
            "allowed": result.allowed,
            "remaining_tokens": result.remaining_tokens,
            "retry_after": result.retry_after,
            "output": input_data if result.allowed else None,
        }
