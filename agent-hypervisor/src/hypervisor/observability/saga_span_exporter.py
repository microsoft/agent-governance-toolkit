# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenTelemetry-compatible span exporter for Saga orchestration steps.

Subscribes to the HypervisorEventBus for saga lifecycle events and
produces span records that can be forwarded to any tracing backend
via the ``SpanSink`` protocol.

No external dependencies — the hypervisor stays standalone.  A concrete
``OTelSpanSink`` adapter lives in ``agent-sre`` and bridges into the
existing ``TraceExporter``.

Usage::

    from hypervisor.observability import SagaSpanExporter, HypervisorEventBus

    bus = HypervisorEventBus()
    exporter = SagaSpanExporter(bus)

    # Optionally attach a sink (e.g. OTelSpanSink from agent-sre)
    exporter.attach_sink(my_sink)

    # ... saga events flow through the bus ...

    # Or inspect buffered spans directly
    spans = exporter.completed_spans
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from hypervisor.observability.event_bus import EventType, HypervisorEvent, HypervisorEventBus

# Saga event types we subscribe to
_SAGA_LIFECYCLE_EVENTS = frozenset({
    EventType.SAGA_CREATED,
    EventType.SAGA_STEP_STARTED,
    EventType.SAGA_STEP_COMMITTED,
    EventType.SAGA_STEP_FAILED,
    EventType.SAGA_COMPENSATING,
    EventType.SAGA_COMPLETED,
    EventType.SAGA_ESCALATED,
})


# ---------------------------------------------------------------------------
# SpanSink protocol — no hard OTel dependency in hypervisor
# ---------------------------------------------------------------------------


@runtime_checkable
class SpanSink(Protocol):
    """Protocol for receiving completed span records.

    Any object implementing this interface can receive spans from the
    ``SagaSpanExporter``.  The ``agent-sre`` package ships an
    ``OTelSpanSink`` adapter that bridges into the native OTel SDK.
    """

    def record_span(
        self,
        name: str,
        start_time: float,
        end_time: float,
        attributes: dict[str, Any],
        status: str,
    ) -> None: ...


# ---------------------------------------------------------------------------
# Span record dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SagaSpanRecord:
    """An immutable record of a completed saga span."""

    name: str
    saga_id: str
    step_id: str
    step_action: str
    start_time: float
    end_time: float
    status: str  # "ok", "error", "compensating"
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time


# ---------------------------------------------------------------------------
# SagaSpanExporter
# ---------------------------------------------------------------------------


class SagaSpanExporter:
    """Exports OpenTelemetry-compatible spans for saga orchestration steps.

    Subscribes to the ``HypervisorEventBus`` for saga lifecycle events.
    On each step completion (committed, failed, escalated), records a span
    with timing, saga context, and status information.

    Completed spans are:
    1. Buffered internally in ``completed_spans``
    2. Forwarded to an attached ``SpanSink`` (if any)

    Attributes:
        _bus: The event bus this exporter is subscribed to.
        _sink: Optional SpanSink for forwarding completed spans.
        _step_starts: Tracks step start times: ``(saga_id, step_id) -> timestamp``.
        _saga_starts: Tracks saga creation times: ``saga_id -> timestamp``.
        _completed_spans: Buffer of completed span records.
    """

    def __init__(self, bus: HypervisorEventBus, sink: SpanSink | None = None) -> None:
        self._bus = bus
        self._sink = sink

        # In-flight tracking: (saga_id, step_id) -> start timestamp
        self._step_starts: dict[tuple[str, str], float] = {}

        # Saga-level tracking: saga_id -> creation timestamp
        self._saga_starts: dict[str, float] = {}

        # Completed span buffer
        self._completed_spans: list[SagaSpanRecord] = []

        # Total events processed
        self._events_processed: int = 0

        # Subscribe to all saga lifecycle events
        for event_type in _SAGA_LIFECYCLE_EVENTS:
            bus.subscribe(event_type=event_type, handler=self._handle_event)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def attach_sink(self, sink: SpanSink) -> None:
        """Attach a SpanSink to receive completed spans in real time."""
        self._sink = sink

    def detach_sink(self) -> None:
        """Detach the current SpanSink."""
        self._sink = None

    @property
    def completed_spans(self) -> list[SagaSpanRecord]:
        """Return a copy of all completed span records."""
        return list(self._completed_spans)

    @property
    def events_processed(self) -> int:
        """Total saga events processed."""
        return self._events_processed

    def reset(self) -> None:
        """Reset all internal state (for testing)."""
        self._step_starts.clear()
        self._saga_starts.clear()
        self._completed_spans.clear()
        self._events_processed = 0

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def _handle_event(self, event: HypervisorEvent) -> None:
        """Process a saga lifecycle event from the bus."""
        self._events_processed += 1
        payload = event.payload
        saga_id = payload.get("saga_id", event.causal_trace_id or "unknown")
        step_id = payload.get("step_id", "")
        step_action = payload.get("action", payload.get("step_action", ""))

        if event.event_type == EventType.SAGA_CREATED:
            self._saga_starts[saga_id] = event.timestamp.timestamp()

        elif event.event_type == EventType.SAGA_STEP_STARTED:
            key = (saga_id, step_id or step_action)
            self._step_starts[key] = event.timestamp.timestamp()

        elif event.event_type == EventType.SAGA_STEP_COMMITTED:
            self._complete_step(
                saga_id=saga_id,
                step_id=step_id or step_action,
                step_action=step_action,
                end_time=event.timestamp.timestamp(),
                status="ok",
                extra_attrs=payload,
                agent_did=event.agent_did,
                session_id=event.session_id,
            )

        elif event.event_type == EventType.SAGA_STEP_FAILED:
            self._complete_step(
                saga_id=saga_id,
                step_id=step_id or step_action,
                step_action=step_action,
                end_time=event.timestamp.timestamp(),
                status="error",
                extra_attrs=payload,
                agent_did=event.agent_did,
                session_id=event.session_id,
            )

        elif event.event_type == EventType.SAGA_COMPENSATING:
            # Compensation is a span in its own right
            self._record_span(
                name=f"saga.compensate.{step_action or step_id}",
                saga_id=saga_id,
                step_id=step_id or "compensation",
                step_action=step_action or "compensate",
                start_time=event.timestamp.timestamp(),
                end_time=event.timestamp.timestamp(),  # instantaneous marker
                status="compensating",
                extra_attrs=payload,
                agent_did=event.agent_did,
                session_id=event.session_id,
            )

        elif event.event_type == EventType.SAGA_COMPLETED:
            # Record a saga-level span from creation to completion
            start = self._saga_starts.pop(saga_id, None)
            if start is not None:
                self._record_span(
                    name=f"saga.completed.{saga_id}",
                    saga_id=saga_id,
                    step_id="",
                    step_action="complete",
                    start_time=start,
                    end_time=event.timestamp.timestamp(),
                    status="ok",
                    extra_attrs=payload,
                    agent_did=event.agent_did,
                    session_id=event.session_id,
                )

        elif event.event_type == EventType.SAGA_ESCALATED:
            start = self._saga_starts.pop(saga_id, None)
            if start is not None:
                self._record_span(
                    name=f"saga.escalated.{saga_id}",
                    saga_id=saga_id,
                    step_id="",
                    step_action="escalate",
                    start_time=start,
                    end_time=event.timestamp.timestamp(),
                    status="error",
                    extra_attrs=payload,
                    agent_did=event.agent_did,
                    session_id=event.session_id,
                )

    def _complete_step(
        self,
        saga_id: str,
        step_id: str,
        step_action: str,
        end_time: float,
        status: str,
        extra_attrs: dict[str, Any],
        agent_did: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Complete an in-flight step span."""
        key = (saga_id, step_id)
        start_time = self._step_starts.pop(key, None)
        if start_time is None:
            # Step started before we subscribed, use end_time as fallback
            start_time = end_time

        self._record_span(
            name=f"saga.step.{step_action or step_id}",
            saga_id=saga_id,
            step_id=step_id,
            step_action=step_action,
            start_time=start_time,
            end_time=end_time,
            status=status,
            extra_attrs=extra_attrs,
            agent_did=agent_did,
            session_id=session_id,
        )

    def _record_span(
        self,
        name: str,
        saga_id: str,
        step_id: str,
        step_action: str,
        start_time: float,
        end_time: float,
        status: str,
        extra_attrs: dict[str, Any] | None = None,
        agent_did: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Create a span record, buffer it, and forward to sink if attached."""
        attrs: dict[str, Any] = {
            "agent.saga.id": saga_id,
            "agent.saga.step_id": step_id,
            "agent.saga.step_action": step_action,
            "agent.saga.state": status,
        }
        if agent_did:
            attrs["agent.did"] = agent_did
        if session_id:
            attrs["session.id"] = session_id
        if extra_attrs:
            # Include select payload fields as span attributes
            for key in ("error", "reason", "result"):
                if key in extra_attrs:
                    attrs[f"agent.saga.{key}"] = str(extra_attrs[key])

        record = SagaSpanRecord(
            name=name,
            saga_id=saga_id,
            step_id=step_id,
            step_action=step_action,
            start_time=start_time,
            end_time=end_time,
            status=status,
            attributes=attrs,
        )
        self._completed_spans.append(record)

        # Forward to sink if attached
        if self._sink is not None:
            self._sink.record_span(
                name=record.name,
                start_time=record.start_time,
                end_time=record.end_time,
                attributes=record.attributes,
                status=record.status,
            )
