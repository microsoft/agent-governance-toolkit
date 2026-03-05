# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Circuit breaker — automatic agent isolation on failure.

Basic open/closed circuit breaker. Half-open recovery is not available
in Community Edition — use force_close() or reset() to recover.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CircuitState(Enum):
    """Circuit breaker state."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject calls
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker."""
    failure_threshold: int = 5          # Failures before opening
    success_threshold: int = 3          # Successes in half-open to close
    timeout_seconds: float = 60.0       # Time in open before half-open
    half_open_max_calls: int = 3        # Max test calls in half-open

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_threshold": self.failure_threshold,
            "success_threshold": self.success_threshold,
            "timeout_seconds": self.timeout_seconds,
            "half_open_max_calls": self.half_open_max_calls,
        }


@dataclass
class CircuitEvent:
    """Record of a circuit breaker state change."""
    from_state: CircuitState
    to_state: CircuitState
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


class CircuitBreaker:
    """Circuit breaker for automatic agent isolation on failure.

    States:
    - CLOSED: Normal operation. Track failures.
    - OPEN: Agent isolated. Reject all calls. Use force_close() or reset() to recover.

    Half-open recovery is not available in Community Edition.
    """

    def __init__(self, agent_id: str, config: CircuitBreakerConfig | None = None) -> None:
        self.agent_id = agent_id
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time: float | None = None
        self._opened_at: float | None = None
        self._events: list[CircuitEvent] = []
        self._total_trips = 0

    @property
    def state(self) -> CircuitState:
        """Current state — no auto-transition in Community Edition."""
        return self._state

    @property
    def is_available(self) -> bool:
        """Whether the agent can accept calls."""
        return self._state == CircuitState.CLOSED

    def record_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.CLOSED:
            self._failure_count = max(0, self._failure_count - 1)

    def record_failure(self, error: str = "") -> None:
        """Record a failed call."""
        self._last_failure_time = time.time()
        if self._state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.config.failure_threshold:
                self._transition(CircuitState.OPEN, f"failure threshold reached: {error}")

    def force_open(self, reason: str = "manual") -> None:
        """Manually open the circuit breaker."""
        self._transition(CircuitState.OPEN, reason)

    def force_close(self, reason: str = "manual") -> None:
        """Manually close the circuit breaker."""
        self._transition(CircuitState.CLOSED, reason)

    def reset(self) -> None:
        """Reset all counters and close the circuit."""
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._opened_at = None
        self._transition(CircuitState.CLOSED, "reset")

    def _transition(self, new_state: CircuitState, reason: str) -> None:
        """Transition to a new state."""
        old_state = self._state
        if old_state == new_state:
            return

        self._events.append(CircuitEvent(
            from_state=old_state,
            to_state=new_state,
            reason=reason,
        ))
        self._state = new_state

        if new_state == CircuitState.OPEN:
            self._opened_at = time.time()
            self._total_trips += 1
        elif new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0
            self._opened_at = None

    @property
    def events(self) -> list[CircuitEvent]:
        return self._events

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "is_available": self.is_available,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "total_trips": self._total_trips,
            "config": self.config.to_dict(),
            "events": [e.to_dict() for e in self._events[-10:]],
        }


class CircuitBreakerRegistry:
    """Registry for managing circuit breakers across agents."""

    def __init__(self, default_config: CircuitBreakerConfig | None = None) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._default_config = default_config or CircuitBreakerConfig()

    def get(self, agent_id: str) -> CircuitBreaker:
        """Get or create a circuit breaker for an agent."""
        if agent_id not in self._breakers:
            self._breakers[agent_id] = CircuitBreaker(agent_id, self._default_config)
        return self._breakers[agent_id]

    def is_available(self, agent_id: str) -> bool:
        """Check if an agent is available."""
        return self.get(agent_id).is_available

    @property
    def open_breakers(self) -> list[CircuitBreaker]:
        """Get all open or half-open circuit breakers."""
        return [b for b in self._breakers.values() if b.state != CircuitState.CLOSED]

    def summary(self) -> dict[str, Any]:
        return {
            "total_agents": len(self._breakers),
            "open_circuits": len([b for b in self._breakers.values() if b.state == CircuitState.OPEN]),
            "half_open_circuits": len([b for b in self._breakers.values() if b.state == CircuitState.HALF_OPEN]),
            "agents": {aid: b.to_dict() for aid, b in self._breakers.items()},
        }
