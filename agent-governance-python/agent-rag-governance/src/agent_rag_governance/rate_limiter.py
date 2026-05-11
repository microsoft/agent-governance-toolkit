# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Sliding-window rate limiter for per-agent retrieval calls.

Pure Python — no external dependencies. Thread-safe.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Per-agent sliding-window rate limiter.

    Tracks retrieval timestamps per ``agent_id`` and enforces a maximum
    number of calls within a rolling window.

    Args:
        window_seconds: Length of the sliding window (default: 60).

    Example::

        limiter = RateLimiter()
        allowed = limiter.check("agent-001", limit=100)
        if not allowed:
            raise RateLimitExceededError(...)
    """

    # Run the per-agent compaction sweep every Nth check() call.
    _COMPACTION_INTERVAL = 1000

    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        self._timestamps: dict[str, deque[float]] = {}
        self._check_count = 0

    def check(self, agent_id: str, limit: int) -> bool:
        """Return ``True`` if the agent is within its limit, ``False`` if exceeded.

        Records the current call timestamp regardless of the outcome so that
        callers can decide whether to raise or simply skip.

        Args:
            agent_id: Unique identifier for the agent making the retrieval.
            limit: Maximum allowed calls within the window. ``0`` = unlimited.
        """
        if limit == 0:
            return True

        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            if agent_id not in self._timestamps:
                self._timestamps[agent_id] = deque()

            dq = self._timestamps[agent_id]

            # Evict timestamps outside the window
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= limit:
                return False

            dq.append(now)

            # Periodic compaction so long-running services with a
            # churning set of agent_ids don't leak per-agent deques.
            # Without this, an entry persists as long as the process
            # lives even if the agent never made another call after
            # its window expired.
            self._check_count += 1
            if self._check_count >= self._COMPACTION_INTERVAL:
                self._check_count = 0
                self._compact_locked(cutoff)
            return True

    def _compact_locked(self, cutoff: float) -> None:
        """Drop agent entries whose deques are entirely outside the window.

        Caller must hold self._lock.
        """
        stale = [
            agent_id
            for agent_id, dq in self._timestamps.items()
            if not dq or dq[-1] < cutoff
        ]
        for agent_id in stale:
            del self._timestamps[agent_id]

    def reset(self, agent_id: str) -> None:
        """Clear all recorded timestamps for *agent_id* (useful in tests)."""
        with self._lock:
            self._timestamps.pop(agent_id, None)
