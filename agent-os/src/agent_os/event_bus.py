# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cross-gate event bus for governance layer composition.

Enables governance gates (PolicyEvaluator, TrustGate, CircuitBreaker,
ConversationGuardian) to communicate via events without tight coupling.

Example::

    bus = GovernanceEventBus()
    bus.subscribe("policy.violation", on_violation)
    bus.publish("policy.violation", agent_id="a1", action="delete_db")
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

EventHandler = Callable[["GovernanceEvent"], None]


@dataclass
class GovernanceEvent:
    """A governance event emitted by any gate."""

    event_type: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = ""
    agent_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)


# Standard event types
POLICY_VIOLATION = "policy.violation"
POLICY_ALLOW = "policy.allow"
TRUST_PENALTY = "trust.penalty"
TRUST_BOOST = "trust.boost"
CIRCUIT_OPEN = "circuit.open"
CIRCUIT_CLOSE = "circuit.close"
ESCALATION = "governance.escalation"
BUDGET_EXCEEDED = "budget.exceeded"


class GovernanceEventBus:
    """Publish/subscribe event bus for governance gate composition.

    Example::

        bus = GovernanceEventBus()

        # Trust gate penalizes on policy violations
        def on_violation(event):
            trust_engine.penalize(event.agent_id, severity=0.3)
        bus.subscribe("policy.violation", on_violation)

        # Circuit breaker trips on trust penalties
        def on_trust_penalty(event):
            if event.data.get("new_score", 1.0) < 0.3:
                circuit_breaker.trip(event.agent_id)
        bus.subscribe("trust.penalty", on_trust_penalty)

        # Policy engine publishes violation
        bus.publish("policy.violation", agent_id="agent-1", action="drop_table")
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: list[GovernanceEvent] = []
        self._max_history: int = 1000

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Subscribe a handler to an event type."""
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a handler from an event type."""
        if event_type in self._handlers:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h is not handler
            ]

    def publish(self, event_type: str, source: str = "", agent_id: str = "", **data: Any) -> GovernanceEvent:
        """Publish an event to all subscribers."""
        event = GovernanceEvent(
            event_type=event_type,
            source=source,
            agent_id=agent_id,
            data=data,
        )
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        for handler in self._handlers.get(event_type, []):
            try:
                handler(event)
            except Exception:
                logger.exception("Event handler failed for %s", event_type)

        # Wildcard subscribers
        for handler in self._handlers.get("*", []):
            try:
                handler(event)
            except Exception:
                logger.exception("Wildcard handler failed for %s", event_type)

        return event

    def get_history(self, event_type: str | None = None, limit: int = 100) -> list[GovernanceEvent]:
        """Get recent events, optionally filtered by type."""
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()
