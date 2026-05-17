# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Structured event bus for the Agent Hypervisor.

Every ring transition, liability event, saga step, session write, and
security action emits a typed event to an append-only store. Enables
full replay debugging, post-mortem analysis, and real-time monitoring.
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# Default cap for the in-memory event store. Hypervisor deployments run for
# weeks; an unbounded list eventually OOMs. The cap is configurable via the
# ``HypervisorEventBus(max_events=...)`` constructor; ``None`` opts back into
# unbounded growth for tests or analysis tooling that needs full history.
DEFAULT_MAX_EVENTS = 100_000


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

    def __init__(self, max_events: int | None = DEFAULT_MAX_EVENTS) -> None:
        """Create an event bus.

        ``max_events`` caps the in-memory store. Each per-key index list
        (by-type, by-session, by-agent) is independently capped to the
        same value, so a single chatty session cannot starve the
        history of other sessions. Pass ``None`` to disable the cap
        (testing or full-replay tooling).
        """
        self._max_events = max_events
        # `deque` with `maxlen` evicts the oldest entry on overflow in
        # O(1), avoiding the OOM cliff of an unbounded `list`.
        self._events: deque[HypervisorEvent] = deque(maxlen=max_events)
        self._subscribers: dict[EventType | None, list[EventHandler]] = {}
        self._by_type: dict[EventType, deque[HypervisorEvent]] = {}
        self._by_session: dict[str, deque[HypervisorEvent]] = {}
        self._by_agent: dict[str, deque[HypervisorEvent]] = {}
        # Use an RLock so a subscriber that re-enters the bus (e.g.
        # emits an event in response to another event) doesn't deadlock.
        self._lock = threading.RLock()

    def _new_index_deque(self) -> deque[HypervisorEvent]:
        return deque(maxlen=self._max_events)

    def emit(self, event: HypervisorEvent) -> None:
        """Append an event and notify subscribers."""
        with self._lock:
            self._events.append(event)

            self._by_type.setdefault(
                event.event_type, self._new_index_deque()
            ).append(event)

            if event.session_id:
                self._by_session.setdefault(
                    event.session_id, self._new_index_deque()
                ).append(event)

            if event.agent_did:
                self._by_agent.setdefault(
                    event.agent_did, self._new_index_deque()
                ).append(event)

            # Snapshot subscriber lists while holding the lock so a
            # subscriber that mutates the registry mid-notify doesn't
            # invalidate iteration.
            type_subs = list(self._subscribers.get(event.event_type, ()))
            wildcard_subs = list(self._subscribers.get(None, ()))

        # Invoke handlers outside the lock so a slow subscriber can't
        # serialize the entire bus or, worse, deadlock with a caller
        # that also holds an external lock.
        for handler in type_subs:
            handler(event)
        for handler in wildcard_subs:
            handler(event)

    def subscribe(
        self,
        event_type: EventType | None = None,
        handler: EventHandler | None = None,
    ) -> None:
        """Subscribe to events. Use event_type=None for all events."""
        if not handler:
            return
        with self._lock:
            self._subscribers.setdefault(event_type, []).append(handler)

    def query_by_type(self, event_type: EventType) -> list[HypervisorEvent]:
        """Get all events of a specific type."""
        with self._lock:
            return list(self._by_type.get(event_type, ()))

    def query_by_session(self, session_id: str) -> list[HypervisorEvent]:
        """Get all events for a specific session."""
        with self._lock:
            return list(self._by_session.get(session_id, ()))

    def query_by_agent(self, agent_did: str) -> list[HypervisorEvent]:
        """Get all events involving a specific agent."""
        with self._lock:
            return list(self._by_agent.get(agent_did, ()))

    def query_by_time_range(
        self,
        start: datetime,
        end: datetime | None = None,
    ) -> list[HypervisorEvent]:
        """Get events within a time range."""
        if end is None:
            end = datetime.now(UTC)
        with self._lock:
            return [e for e in self._events if start <= e.timestamp <= end]

    def query(
        self,
        event_type: EventType | None = None,
        session_id: str | None = None,
        agent_did: str | None = None,
        limit: int | None = None,
    ) -> list[HypervisorEvent]:
        """Flexible query with multiple filters."""
        with self._lock:
            results: list[HypervisorEvent] = list(self._events)

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
        with self._lock:
            return len(self._events)

    @property
    def all_events(self) -> list[HypervisorEvent]:
        with self._lock:
            return list(self._events)

    def type_counts(self) -> dict[str, int]:
        """Return count of events per type."""
        with self._lock:
            return {t.value: len(evts) for t, evts in self._by_type.items()}

    def _clear(self) -> None:
        """Clear all events. **Test-only — do not call in production.**

        The event bus is wired into the hypervisor as a long-lived,
        process-singleton-shaped collaborator (see
        ``hypervisor.api.server._event_bus``): production calls would
        wipe the audit trail of every running session at once.

        The leading underscore makes the test-only contract visible at
        every call site. The method is kept on the class (rather than
        moved to a test helper) because some tests construct a fresh
        bus and then exercise the clear path itself; it just shouldn't
        be reached from non-test code.
        """
        with self._lock:
            self._events.clear()
            self._by_type.clear()
            self._by_session.clear()
            self._by_agent.clear()
