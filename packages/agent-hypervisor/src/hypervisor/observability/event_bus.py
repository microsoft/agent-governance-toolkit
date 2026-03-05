# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Structured event bus for the Agent Hypervisor.

Every ring transition, liability event, saga step, session write, and
security action emits a typed event to an append-only store. Enables
full replay debugging, post-mortem analysis, and real-time monitoring.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Categorised hypervisor event types."""

    # Session lifecycle
    SESSION_CREATED = "session.created"
    SESSION_JOINED = "session.joined"
    SESSION_ACTIVATED = "session.activated"
    SESSION_TERMINATED = "session.terminated"
    SESSION_ARCHIVED = "session.archived"

    # Ring transitions
    RING_ASSIGNED = "ring.assigned"
    RING_ELEVATED = "ring.elevated"
    RING_DEMOTED = "ring.demoted"
    RING_ELEVATION_EXPIRED = "ring.elevation_expired"
    RING_BREACH_DETECTED = "ring.breach_detected"

    # Liability
    VOUCH_CREATED = "liability.vouch_created"
    VOUCH_RELEASED = "liability.vouch_released"
    SLASH_EXECUTED = "liability.slash_executed"
    FAULT_ATTRIBUTED = "liability.fault_attributed"
    QUARANTINE_ENTERED = "liability.quarantine_entered"
    QUARANTINE_RELEASED = "liability.quarantine_released"

    # Saga
    SAGA_CREATED = "saga.created"
    SAGA_STEP_STARTED = "saga.step_started"
    SAGA_STEP_COMMITTED = "saga.step_committed"
    SAGA_STEP_FAILED = "saga.step_failed"
    SAGA_COMPENSATING = "saga.compensating"
    SAGA_COMPLETED = "saga.completed"
    SAGA_ESCALATED = "saga.escalated"
    SAGA_FANOUT_STARTED = "saga.fanout_started"
    SAGA_FANOUT_RESOLVED = "saga.fanout_resolved"
    SAGA_CHECKPOINT_SAVED = "saga.checkpoint_saved"

    # VFS / Session writes
    VFS_WRITE = "vfs.write"
    VFS_DELETE = "vfs.delete"
    VFS_SNAPSHOT = "vfs.snapshot"
    VFS_RESTORE = "vfs.restore"
    VFS_CONFLICT = "vfs.conflict"

    # Security
    RATE_LIMITED = "security.rate_limited"
    AGENT_KILLED = "security.agent_killed"
    SAGA_HANDOFF = "security.saga_handoff"
    IDENTITY_VERIFIED = "security.identity_verified"

    # Audit
    AUDIT_DELTA_CAPTURED = "audit.delta_captured"
    AUDIT_COMMITTED = "audit.committed"
    AUDIT_GC_COLLECTED = "audit.gc_collected"

    # Verification
    BEHAVIOR_DRIFT = "verification.behavior_drift"
    HISTORY_VERIFIED = "verification.history_verified"


@dataclass(frozen=True)
class HypervisorEvent:
    """An immutable, structured event emitted by the hypervisor."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    event_type: EventType = EventType.SESSION_CREATED
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    session_id: str | None = None
    agent_did: str | None = None
    causal_trace_id: str | None = None
    parent_event_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "agent_did": self.agent_did,
            "causal_trace_id": self.causal_trace_id,
            "parent_event_id": self.parent_event_id,
            "payload": self.payload,
        }


# Type alias for event subscribers
EventHandler = Callable[[HypervisorEvent], None]


class HypervisorEventBus:
    """
    Append-only structured event store with pub/sub.

    All hypervisor components emit events here. Supports:
    - Append-only storage (immutable event log)
    - Query by type, agent, session, time range
    - Subscribe to specific event types
    - Event count and statistics
    """

    def __init__(self) -> None:
        self._events: list[HypervisorEvent] = []
        self._subscribers: dict[EventType | None, list[EventHandler]] = {}
        self._by_type: dict[EventType, list[HypervisorEvent]] = {}
        self._by_session: dict[str, list[HypervisorEvent]] = {}
        self._by_agent: dict[str, list[HypervisorEvent]] = {}

    def emit(self, event: HypervisorEvent) -> None:
        """Append an event and notify subscribers."""
        self._events.append(event)

        # Index by type
        self._by_type.setdefault(event.event_type, []).append(event)

        # Index by session
        if event.session_id:
            self._by_session.setdefault(event.session_id, []).append(event)

        # Index by agent
        if event.agent_did:
            self._by_agent.setdefault(event.agent_did, []).append(event)

        # Notify type-specific subscribers
        for handler in self._subscribers.get(event.event_type, []):
            handler(event)

        # Notify wildcard subscribers
        for handler in self._subscribers.get(None, []):
            handler(event)

    def subscribe(
        self,
        event_type: EventType | None = None,
        handler: EventHandler | None = None,
    ) -> None:
        """Subscribe to events. Use event_type=None for all events."""
        if handler:
            self._subscribers.setdefault(event_type, []).append(handler)

    def query_by_type(self, event_type: EventType) -> list[HypervisorEvent]:
        """Get all events of a specific type."""
        return list(self._by_type.get(event_type, []))

    def query_by_session(self, session_id: str) -> list[HypervisorEvent]:
        """Get all events for a specific session."""
        return list(self._by_session.get(session_id, []))

    def query_by_agent(self, agent_did: str) -> list[HypervisorEvent]:
        """Get all events involving a specific agent."""
        return list(self._by_agent.get(agent_did, []))

    def query_by_time_range(
        self,
        start: datetime,
        end: datetime | None = None,
    ) -> list[HypervisorEvent]:
        """Get events within a time range."""
        if end is None:
            end = datetime.now(UTC)
        return [e for e in self._events if start <= e.timestamp <= end]

    def query(
        self,
        event_type: EventType | None = None,
        session_id: str | None = None,
        agent_did: str | None = None,
        limit: int | None = None,
    ) -> list[HypervisorEvent]:
        """Flexible query with multiple filters."""
        results = self._events

        if event_type is not None:
            results = [e for e in results if e.event_type == event_type]
        if session_id is not None:
            results = [e for e in results if e.session_id == session_id]
        if agent_did is not None:
            results = [e for e in results if e.agent_did == agent_did]

        if limit is not None:
            results = results[-limit:]

        return results

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def all_events(self) -> list[HypervisorEvent]:
        return list(self._events)

    def type_counts(self) -> dict[str, int]:
        """Return count of events per type."""
        return {t.value: len(evts) for t, evts in self._by_type.items()}

    def clear(self) -> None:
        """Clear all events (for testing)."""
        self._events.clear()
        self._by_type.clear()
        self._by_session.clear()
        self._by_agent.clear()
