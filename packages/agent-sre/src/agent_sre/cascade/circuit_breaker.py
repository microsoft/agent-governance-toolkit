# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Per-agent circuit breakers with cascade detection.

Implements the circuit breaker pattern to prevent cascading failures
across multi-agent workflows, while also preserving the legacy
``agent_os.circuit_breaker`` API through compatible names and behavior.
"""

from __future__ import annotations

import inspect
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar

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


CircuitBreakerOpen = CircuitOpenError


@dataclass(init=False)
class CircuitBreakerConfig:
    """Configuration for a circuit breaker instance.

    Supports both the canonical ``recovery_timeout_seconds`` name and the
    legacy ``reset_timeout_seconds`` alias used by ``agent_os``.
    """

    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    half_open_max_calls: int = 1

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float | None = None,
        half_open_max_calls: int = 1,
        reset_timeout_seconds: float | None = None,
    ) -> None:
        if (
            recovery_timeout_seconds is not None
            and reset_timeout_seconds is not None
            and recovery_timeout_seconds != reset_timeout_seconds
        ):
            raise ValueError(
                "recovery_timeout_seconds and reset_timeout_seconds must match"
            )

        timeout = recovery_timeout_seconds
        if timeout is None:
            timeout = reset_timeout_seconds
        if timeout is None:
            timeout = 30.0

        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = timeout
        self.half_open_max_calls = half_open_max_calls

    @property
    def reset_timeout_seconds(self) -> float:
        return self.recovery_timeout_seconds

    @reset_timeout_seconds.setter
    def reset_timeout_seconds(self, value: float) -> None:
        self.recovery_timeout_seconds = value


class CircuitBreaker:
    """Hybrid circuit breaker supporting SRE and legacy agent-os callers."""

    def __init__(
        self,
        agent_id: str | CircuitBreakerConfig | None = None,
        config: CircuitBreakerConfig | None = None,
    ) -> None:
        if isinstance(agent_id, CircuitBreakerConfig) and config is None:
            config = agent_id
            agent_id = None

        self.agent_id = agent_id or "legacy"
        self.config = config or CircuitBreakerConfig()
        self._config = self.config
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        """Return the current state as an uppercase string."""
        return self.get_state().value

    @property
    def failure_count(self) -> int:
        return self._failure_count

    def get_state(self) -> CircuitState:
        """Return the current state, transitioning OPEN → HALF_OPEN if needed."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    def call(
        self,
        func: Any,
        *args: Any,
        fallback: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Execute *func* through the circuit breaker.

        Sync callables return their result directly. Awaitable results are returned
        as a coroutine so legacy async callers can ``await cb.call(...)``.
        """
        retry_after = self._prepare_call()
        if retry_after is not None:
            if fallback is not None:
                return fallback
            raise CircuitOpenError(self.agent_id, retry_after)

        try:
            result = func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise

        if inspect.isawaitable(result):
            async def _await_result() -> Any:
                try:
                    value = await result
                except Exception:
                    self.record_failure()
                    raise
                self.record_success()
                return value

            return _await_result()

        self.record_success()
        return result

    def record_success(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._transition(CircuitState.CLOSED)
            self._failure_count = 0
            self._success_count += 1
            self._half_open_calls = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state is CircuitState.HALF_OPEN:
                self._transition(CircuitState.OPEN)
                self._half_open_calls = 0
            elif self._failure_count >= self.config.failure_threshold:
                self._transition(CircuitState.OPEN)

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        with self._lock:
            self._transition(CircuitState.CLOSED)
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0
            self._last_failure_time = 0.0

    def _prepare_call(self) -> float | None:
        with self._lock:
            self._maybe_transition_to_half_open()

            if self._state is CircuitState.OPEN:
                return self._time_until_recovery()

            if self._state is CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    return self._time_until_recovery()
                self._half_open_calls += 1

            return None

    def _maybe_transition_to_half_open(self) -> None:
        if self._state is CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self.config.recovery_timeout_seconds:
                self._transition(CircuitState.HALF_OPEN)

    def _transition(self, new_state: CircuitState) -> None:
        self._state = new_state
        if new_state is CircuitState.HALF_OPEN:
            self._half_open_calls = 0

    def _time_until_recovery(self) -> float:
        elapsed = time.monotonic() - self._last_failure_time
        return max(0.0, self.config.recovery_timeout_seconds - elapsed)


class CascadeDetector:
    """Detects cascading failures across multiple agents."""

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

    def get_breaker(self, agent_id: str) -> CircuitBreaker | None:
        """Return the circuit breaker for *agent_id*, or None if not registered."""
        return self._breakers.get(agent_id)

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


__all__ = [
    "CascadeDetector",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerOpen",
    "CircuitOpenError",
    "CircuitState",
]
