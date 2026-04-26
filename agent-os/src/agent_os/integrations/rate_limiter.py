# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tool-call rate limiting tied to governance policy.

This module enforces token-bucket limits for tool invocations, optionally scoped
per agent and governed by ``GovernancePolicy.max_tool_calls``.

See also:
    - hypervisor.security.rate_limiter: runtime-layer per-agent/per-ring limits.
    - agentmesh.services.rate_limiter: service/proxy-level limits in Agent Mesh.
    - agentmesh.services.rate_limit_middleware: HTTP edge middleware in Agent Mesh.
    - agent_os.policies.rate_limiting: shared token-bucket primitives.
"""

import threading
import time
from dataclasses import dataclass
from typing import Optional

from .base import GovernancePolicy


@dataclass(frozen=True)
class RateLimitStatus:
    """Snapshot of an agent's rate-limit state."""
    allowed: bool
    remaining_calls: int
    reset_at: float
    wait_seconds: float


class RateLimiter:
    """Thread-safe token-bucket rate limiter for tool calls.

    Args:
        max_calls: Maximum number of calls allowed per time window (bucket size).
        time_window: Duration of the time window in seconds.
        per_agent: If ``True``, limits are tracked independently per agent.
            If ``False``, a single global bucket is used for all agents.
        policy: Optional GovernancePolicy whose ``max_tool_calls`` overrides
            *max_calls*.
    """

    _GLOBAL_KEY = "__global__"

    def __init__(
        self,
        max_calls: int = 10,
        time_window: float = 60.0,
        per_agent: bool = True,
        policy: Optional[GovernancePolicy] = None,
    ) -> None:
        if max_calls <= 0:
            raise ValueError("max_calls must be positive")
        if time_window <= 0:
            raise ValueError("time_window must be positive")

        self._max_calls = policy.max_tool_calls if policy is not None else max_calls
        self._time_window = float(time_window)
        self._per_agent = per_agent
        self._lock = threading.Lock()
        # Each bucket: (tokens: float, last_refill: float)
        self._buckets: dict[str, list] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key(self, agent_id: str) -> str:
        return agent_id if self._per_agent else self._GLOBAL_KEY

    def _refill(self, bucket: list, now: float) -> None:
        """Add tokens accrued since the last refill."""
        elapsed = now - bucket[1]
        if elapsed > 0:
            rate = self._max_calls / self._time_window
            bucket[0] = min(self._max_calls, bucket[0] + elapsed * rate)
            bucket[1] = now

    def _get_bucket(self, key: str, now: float) -> list:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = [float(self._max_calls), now]
            self._buckets[key] = bucket
        else:
            self._refill(bucket, now)
        return bucket

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def allow(self, agent_id: str) -> bool:
        """Try to consume one token. Returns ``True`` if the call is allowed."""
        now = time.monotonic()
        with self._lock:
            bucket = self._get_bucket(self._key(agent_id), now)
            if bucket[0] >= 1.0:
                bucket[0] -= 1.0
                return True
            return False

    def check(self, agent_id: str) -> RateLimitStatus:
        """Return current rate-limit status without consuming a token."""
        now = time.monotonic()
        with self._lock:
            bucket = self._get_bucket(self._key(agent_id), now)
            remaining = int(bucket[0])
            allowed = remaining >= 1
            if allowed:
                wait = 0.0
            else:
                rate = self._max_calls / self._time_window
                wait = (1.0 - bucket[0]) / rate if rate > 0 else 0.0
            reset_at = now + self._time_window
        return RateLimitStatus(
            allowed=allowed,
            remaining_calls=remaining,
            reset_at=reset_at,
            wait_seconds=wait,
        )

    def wait_time(self, agent_id: str) -> float:
        """Return seconds until at least one token is available (0.0 if available now)."""
        return self.check(agent_id).wait_seconds

    def reset(self, agent_id: str) -> None:
        """Reset the bucket for *agent_id* (or the global bucket if ``per_agent=False``)."""
        with self._lock:
            self._buckets.pop(self._key(agent_id), None)
