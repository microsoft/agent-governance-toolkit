# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared rate limiting primitives for toolkit policy layers.

These primitives provide a canonical token-bucket foundation without collapsing
layer-specific limiters that serve different architectural boundaries.

See also:
    - hypervisor.security.rate_limiter: runtime-layer per-agent/per-ring limits.
    - agent_os.integrations.rate_limiter: tool-call policy limits in Agent OS.
    - agentmesh.services.rate_limiter: service/proxy-level limits in Agent Mesh.
    - agentmesh.services.rate_limit_middleware: HTTP edge middleware in Agent Mesh.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


class RateLimitExceeded(Exception):
    """Raised when a rate-limited operation cannot proceed."""


@dataclass(frozen=True)
class RateLimitConfig:
    """Basic token-bucket configuration.

    Args:
        capacity: Maximum burst size (the most tokens the bucket may hold).
        refill_rate: Tokens replenished per second.
        initial_tokens: Optional initial token count. Defaults to ``capacity``.
    """

    capacity: float
    refill_rate: float
    initial_tokens: float | None = None

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.refill_rate < 0:
            raise ValueError("refill_rate must be non-negative")
        if self.initial_tokens is not None and not 0 <= self.initial_tokens <= self.capacity:
            raise ValueError(
                "initial_tokens must be between 0 and capacity"
            )

    @property
    def rate(self) -> float:
        """Alias for ``refill_rate`` for callers that prefer ``rate`` terminology."""
        return self.refill_rate


@dataclass
class TokenBucket:
    """Thread-safe token bucket for rate limiting."""

    capacity: float
    tokens: float
    refill_rate: float
    last_refill: float = field(default_factory=time.monotonic)
    _lock: Any = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.refill_rate < 0:
            raise ValueError("refill_rate must be non-negative")
        if not 0 <= self.tokens <= self.capacity:
            raise ValueError("tokens must be between 0 and capacity")

    @classmethod
    def from_config(cls, config: RateLimitConfig) -> "TokenBucket":
        """Build a token bucket from a :class:`RateLimitConfig`."""
        initial_tokens = (
            config.capacity if config.initial_tokens is None else config.initial_tokens
        )
        return cls(
            capacity=config.capacity,
            tokens=initial_tokens,
            refill_rate=config.refill_rate,
        )

    def _refill_unlocked(self, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        elapsed = current - self.last_refill
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = current

    def consume(self, tokens: float = 1.0) -> bool:
        """Try to consume *tokens*. Returns ``True`` when enough tokens exist."""
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        with self._lock:
            self._refill_unlocked()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    @property
    def available(self) -> float:
        """Current token count after refilling for elapsed time."""
        with self._lock:
            self._refill_unlocked()
            return self.tokens

    def tokens_available(self) -> float:
        """Method alias for callers that prefer a function over a property."""
        return self.available

    def time_until_available(self, tokens: float = 1.0) -> float:
        """Return seconds until *tokens* are available."""
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        with self._lock:
            self._refill_unlocked()
            if self.tokens >= tokens:
                return 0.0
            if self.refill_rate == 0:
                return float("inf")
            deficit = tokens - self.tokens
            return deficit / self.refill_rate

    def reset(self, tokens: float | None = None) -> None:
        """Reset the bucket to *tokens* or back to full capacity."""
        target_tokens = self.capacity if tokens is None else tokens
        if not 0 <= target_tokens <= self.capacity:
            raise ValueError("tokens must be between 0 and capacity")
        with self._lock:
            self.tokens = target_tokens
            self.last_refill = time.monotonic()


__all__ = ["RateLimitConfig", "RateLimitExceeded", "TokenBucket"]
