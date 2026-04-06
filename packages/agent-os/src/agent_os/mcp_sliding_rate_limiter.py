# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Sliding-window rate limiting for MCP tool invocations."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from agent_os.mcp_protocols import InMemoryRateLimitStore, MCPRateLimitStore

logger = logging.getLogger(__name__)


class MCPSlidingRateLimiter:
    """Thread-safe per-agent sliding-window rate limiter.

    The limiter tracks recent call timestamps per normalized agent identifier
    and enforces a bounded number of calls within a moving time window. Bucket
    persistence and the clock are injectable so callers can externalize state
    or drive the limiter deterministically in tests.
    """

    def __init__(
        self,
        *,
        max_calls_per_window: int = 100,
        window_size: float = 300.0,
        rate_limit_store: MCPRateLimitStore | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the sliding-window limiter.

        Args:
            max_calls_per_window: Maximum calls allowed within a single
                sliding window.
            window_size: Size of the sliding window in seconds.
            rate_limit_store: Optional persistence backend for per-agent
                buckets. Defaults to the in-memory bucket store.
            clock: Monotonic clock used to timestamp calls.
        """
        if max_calls_per_window <= 0:
            raise ValueError("max_calls_per_window must be positive")
        if window_size <= 0:
            raise ValueError("window_size must be positive")

        self.max_calls_per_window = max_calls_per_window
        self.window_size = float(window_size)
        self._rate_limit_store = rate_limit_store or InMemoryRateLimitStore()
        self._clock = clock
        self._state_lock = threading.Lock()
        self._bucket_locks: dict[str, threading.Lock] = {}
        self._tracked_agents: set[str] = set()

    def try_acquire(self, agent_id: str) -> bool:
        """Try to acquire budget for an agent.

        Args:
            agent_id: Agent identifier whose budget should be decremented.

        Returns:
            ``True`` when a call can proceed inside the active window,
            otherwise ``False``.
        """
        key = self._normalize_agent_id(agent_id)
        bucket_lock = self._get_bucket_lock(key)
        now = self._clock()
        cutoff = now - self.window_size
        with bucket_lock:
            bucket = self._load_bucket(key)
            self._prune_expired(bucket, cutoff)
            if len(bucket) >= self.max_calls_per_window:
                logger.warning("MCP sliding window exceeded for agent %s", key)
                return False
            bucket.append(now)
            self._rate_limit_store.set_bucket(key, bucket)
            return True

    def get_remaining_budget(self, agent_id: str) -> int:
        """Return remaining calls in the active window.

        Args:
            agent_id: Agent identifier to inspect.

        Returns:
            The number of additional calls the agent may make before the
            current window is exhausted.
        """
        key = self._normalize_agent_id(agent_id)
        bucket_lock = self._get_bucket_lock(key)
        now = self._clock()
        cutoff = now - self.window_size
        with bucket_lock:
            bucket = self._load_bucket(key)
            self._prune_expired(bucket, cutoff)
            self._rate_limit_store.set_bucket(key, bucket)
            return max(0, self.max_calls_per_window - len(bucket))

    def get_call_count(self, agent_id: str) -> int:
        """Return the number of calls inside the active window.

        Args:
            agent_id: Agent identifier to inspect.

        Returns:
            The number of calls retained inside the current sliding window.
        """
        key = self._normalize_agent_id(agent_id)
        bucket_lock = self._get_bucket_lock(key)
        now = self._clock()
        cutoff = now - self.window_size
        with bucket_lock:
            bucket = self._load_bucket(key)
            self._prune_expired(bucket, cutoff)
            self._rate_limit_store.set_bucket(key, bucket)
            return len(bucket)

    def reset(self, agent_id: str) -> None:
        """Clear state for a single agent.

        Args:
            agent_id: Agent identifier whose bucket should be reset.
        """
        key = self._normalize_agent_id(agent_id)
        with self._get_bucket_lock(key):
            self._rate_limit_store.set_bucket(key, [])

    def reset_all(self) -> None:
        """Clear state for every agent.

        This removes all retained timestamps from every tracked bucket.
        """
        for key in self._tracked_agent_ids():
            with self._get_bucket_lock(key):
                self._rate_limit_store.set_bucket(key, [])

    def cleanup_expired(self) -> int:
        """Prune expired entries from all agents and return the number removed.

        Returns:
            The total number of expired timestamps removed across all tracked
            agent buckets.
        """
        now = self._clock()
        cutoff = now - self.window_size
        removed = 0
        for key in self._tracked_agent_ids():
            with self._get_bucket_lock(key):
                bucket = self._load_bucket(key)
                before = len(bucket)
                self._prune_expired(bucket, cutoff)
                removed += before - len(bucket)
                self._rate_limit_store.set_bucket(key, bucket)
        return removed

    def _get_bucket_lock(self, agent_id: str) -> threading.Lock:
        with self._state_lock:
            self._tracked_agents.add(agent_id)
            return self._bucket_locks.setdefault(agent_id, threading.Lock())

    @staticmethod
    def _prune_expired(timestamps: list[float], cutoff: float) -> None:
        while timestamps and timestamps[0] <= cutoff:
            timestamps.pop(0)

    def _load_bucket(self, agent_id: str) -> list[float]:
        bucket = self._rate_limit_store.get_bucket(agent_id)
        if bucket is None:
            return []
        if isinstance(bucket, list):
            return list(bucket)
        return [float(timestamp) for timestamp in bucket]

    def _tracked_agent_ids(self) -> list[str]:
        with self._state_lock:
            return list(self._tracked_agents)

    @staticmethod
    def _normalize_agent_id(agent_id: str) -> str:
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")
        return agent_id.casefold()
