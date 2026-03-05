# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Circuit Breaker pattern for backend failure protection.

Prevents cascading failures by tracking backend errors and
short-circuiting calls when a failure threshold is exceeded.
"""

import enum
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")


class CircuitState(enum.Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing — reject calls
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for the circuit breaker.

    Args:
        failure_threshold: Number of consecutive failures before opening the circuit.
        reset_timeout_seconds: Seconds to wait before transitioning from OPEN to HALF_OPEN.
        half_open_max_calls: Max calls allowed in HALF_OPEN state before deciding.
    """

    failure_threshold: int = 5
    reset_timeout_seconds: float = 30.0
    half_open_max_calls: int = 1


class CircuitBreakerOpen(Exception):
    """Raised when a call is rejected because the circuit is OPEN."""

    def __init__(self, retry_after: float) -> None:
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker is OPEN. Retry after {retry_after:.1f}s."
        )


class CircuitBreaker:
    """Circuit breaker for protecting backend calls.

    Usage::

        cb = CircuitBreaker()
        result = await cb.call(backend.get, "key")
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None) -> None:
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count: int = 0
        self._success_count: int = 0
        self._half_open_calls: int = 0
        self._last_failure_time: float = 0.0

    def get_state(self) -> CircuitState:
        """Return the current circuit state, transitioning OPEN→HALF_OPEN if timeout elapsed."""
        if self._state is CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._config.reset_timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute *func* through the circuit breaker.

        Args:
            func: An async callable to invoke.
            *args: Positional arguments forwarded to *func*.
            **kwargs: Keyword arguments forwarded to *func*.

        Returns:
            The return value of *func*.

        Raises:
            CircuitBreakerOpen: If the circuit is OPEN and the timeout has not elapsed.
        """
        state = self.get_state()

        if state is CircuitState.OPEN:
            retry_after = (
                self._config.reset_timeout_seconds
                - (time.monotonic() - self._last_failure_time)
            )
            raise CircuitBreakerOpen(max(retry_after, 0.0))

        if state is CircuitState.HALF_OPEN:
            if self._half_open_calls >= self._config.half_open_max_calls:
                raise CircuitBreakerOpen(self._config.reset_timeout_seconds)
            self._half_open_calls += 1

        try:
            result = await func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise

        self.record_success()
        return result

    def record_success(self) -> None:
        """Record a successful call and reset the breaker if needed."""
        if self._state is CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count += 1
        self._half_open_calls = 0

    def record_failure(self) -> None:
        """Record a failed call and open the circuit if threshold is reached."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self._config.failure_threshold:
            self._state = CircuitState.OPEN
        if self._state is CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._half_open_calls = 0

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time = 0.0
