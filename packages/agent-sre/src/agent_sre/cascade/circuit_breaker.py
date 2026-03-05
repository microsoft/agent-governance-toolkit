# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Per-agent circuit breakers with cascade detection.

Implements the circuit breaker pattern to prevent cascading failures
across multi-agent workflows, addressing OWASP ASI08.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpenError(Exception):
    """Raised when a call is attempted on an open circuit."""

    def __init__(self, agent_id: str, retry_after: float) -> None:
        self.agent_id = agent_id
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker OPEN for agent '{agent_id}'. "
            f"Retry after {retry_after:.1f}s."
        )


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker instance."""

    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    half_open_max_calls: int = 1


@dataclass
class _CircuitMetrics:
    failure_count: int = 0
    success_count: int = 0
    half_open_calls: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = field(default_factory=time.monotonic)


class CircuitBreaker:
    """Per-agent circuit breaker.

    States:
        CLOSED  — normal operation; failures are counted.
        OPEN    — all calls blocked; returns fallback or raises.
        HALF_OPEN — limited trial calls to test recovery.
    """

    def __init__(
        self,
        agent_id: str,
        config: CircuitBreakerConfig | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._metrics = _CircuitMetrics()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> str:
        """Return current state, transitioning OPEN → HALF_OPEN if timeout elapsed."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state.value

    @property
    def failure_count(self) -> int:
        return self._metrics.failure_count

    def call(
        self,
        func: Callable[..., T],
        *args: Any,
        fallback: Any = None,
        **kwargs: Any,
    ) -> T | Any:
        """Execute *func* through the circuit breaker.

        If the circuit is OPEN and a *fallback* is provided, the fallback
        value is returned instead of raising ``CircuitOpenError``.
        """
        with self._lock:
            self._maybe_transition_to_half_open()

            if self._state is CircuitState.OPEN:
                remaining = self._time_until_recovery()
                if fallback is not None:
                    return fallback
                raise CircuitOpenError(self.agent_id, remaining)

            if self._state is CircuitState.HALF_OPEN:
                if self._metrics.half_open_calls >= self.config.half_open_max_calls:
                    if fallback is not None:
                        return fallback
                    raise CircuitOpenError(self.agent_id, self._time_until_recovery())
                self._metrics.half_open_calls += 1

        # Execute outside the lock to avoid holding it during the call.
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise

        self.record_success()
        return result

    def record_success(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                # Recovery confirmed — close the circuit.
                self._transition(CircuitState.CLOSED)
            self._metrics.failure_count = 0
            self._metrics.success_count += 1

    def record_failure(self) -> None:
        with self._lock:
            self._metrics.failure_count += 1
            self._metrics.last_failure_time = time.monotonic()

            if self._state is CircuitState.HALF_OPEN:
                # Failed during trial — reopen.
                self._transition(CircuitState.OPEN)
            elif self._metrics.failure_count >= self.config.failure_threshold:
                self._transition(CircuitState.OPEN)

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        with self._lock:
            self._transition(CircuitState.CLOSED)
            self._metrics = _CircuitMetrics()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _maybe_transition_to_half_open(self) -> None:
        """Must be called while holding ``_lock``."""
        if self._state is CircuitState.OPEN:
            elapsed = time.monotonic() - self._metrics.last_failure_time
            if elapsed >= self.config.recovery_timeout_seconds:
                self._transition(CircuitState.HALF_OPEN)

    def _transition(self, new_state: CircuitState) -> None:
        self._state = new_state
        self._metrics.last_state_change = time.monotonic()
        if new_state is CircuitState.HALF_OPEN:
            self._metrics.half_open_calls = 0

    def _time_until_recovery(self) -> float:
        elapsed = time.monotonic() - self._metrics.last_failure_time
        return max(0.0, self.config.recovery_timeout_seconds - elapsed)


class CascadeDetector:
    """Detects cascading failures across multiple agents.

    When the number of simultaneously-open circuits meets or exceeds
    *cascade_threshold*, a cascade is declared.
    """

    def __init__(
        self,
        agents: list[str],
        cascade_threshold: int = 3,
        config: CircuitBreakerConfig | None = None,
    ) -> None:
        self.cascade_threshold = cascade_threshold
        self._breakers: dict[str, CircuitBreaker] = {
            agent_id: CircuitBreaker(agent_id, config) for agent_id in agents
        }

    def get_breaker(self, agent_id: str) -> CircuitBreaker:
        """Return the circuit breaker for *agent_id*."""
        return self._breakers[agent_id]

    def check_cascade(self) -> bool:
        """Return ``True`` if a cascading failure is detected."""
        return len(self.get_affected_agents()) >= self.cascade_threshold

    def get_affected_agents(self) -> list[str]:
        """Return agent IDs whose circuits are currently OPEN."""
        return [
            agent_id
            for agent_id, breaker in self._breakers.items()
            if breaker.state == CircuitState.OPEN.value
        ]

    def reset_all(self) -> None:
        """Reset every circuit breaker."""
        for breaker in self._breakers.values():
            breaker.reset()
