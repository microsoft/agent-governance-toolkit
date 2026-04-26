# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the SagaSpanExporter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from hypervisor.observability.event_bus import (
    EventType,
    HypervisorEvent,
    HypervisorEventBus,
)
from hypervisor.observability.saga_span_exporter import (
    SagaSpanExporter,
    SagaSpanRecord,
    SpanSink,
)


class _MockSpanSink:
    """Mock sink implementing SpanSink protocol."""

    def __init__(self) -> None:
        self.spans: list[dict[str, Any]] = []

    def record_span(
        self,
        name: str,
        start_time: float,
        end_time: float,
        attributes: dict[str, Any],
        status: str,
    ) -> None:
        self.spans.append({
            "name": name,
            "start_time": start_time,
            "end_time": end_time,
            "attributes": attributes,
            "status": status,
        })


class TestSagaSpanExporter:
    def test_saga_step_creates_span(self):
        """Emit start + committed events → span appears in buffer."""
        bus = HypervisorEventBus()
        exporter = SagaSpanExporter(bus)

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_STARTED,
            agent_did="agent-1",
            session_id="sess-1",
            timestamp=now,
            payload={"saga_id": "saga-abc", "step_id": "step-1", "action": "validate"},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_COMMITTED,
            agent_did="agent-1",
            session_id="sess-1",
            timestamp=now + timedelta(seconds=2),
            payload={"saga_id": "saga-abc", "step_id": "step-1", "action": "validate"},
        ))

        spans = exporter.completed_spans
        assert len(spans) == 1
        assert spans[0].saga_id == "saga-abc"
        assert spans[0].step_id == "step-1"
        assert spans[0].status == "ok"
        assert abs(spans[0].duration_seconds - 2.0) < 1.0

    def test_protocol_sink(self):
        """Mock SpanSink receives correct arguments when attached."""
        bus = HypervisorEventBus()
        sink = _MockSpanSink()
        exporter = SagaSpanExporter(bus, sink=sink)

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_STARTED,
            timestamp=now,
            payload={"saga_id": "s1", "step_id": "st1", "action": "execute"},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_COMMITTED,
            timestamp=now + timedelta(seconds=5),
            payload={"saga_id": "s1", "step_id": "st1", "action": "execute"},
        ))

        assert len(sink.spans) == 1
        span = sink.spans[0]
        assert span["status"] == "ok"
        assert span["attributes"]["agent.saga.id"] == "s1"
        assert span["attributes"]["agent.saga.step_action"] == "execute"

    def test_compensation_span(self):
        """Compensation events create spans with 'compensating' status."""
        bus = HypervisorEventBus()
        sink = _MockSpanSink()
        exporter = SagaSpanExporter(bus, sink=sink)

        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_COMPENSATING,
            payload={"saga_id": "s1", "step_id": "rollback-1", "action": "undo"},
        ))

        assert len(sink.spans) == 1
        assert sink.spans[0]["status"] == "compensating"
        assert "compensate" in sink.spans[0]["name"]

    def test_failed_step_creates_error_span(self):
        """Failed saga steps produce spans with 'error' status."""
        bus = HypervisorEventBus()
        exporter = SagaSpanExporter(bus)

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_STARTED,
            timestamp=now,
            payload={"saga_id": "s2", "step_id": "st2", "action": "deploy"},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_FAILED,
            timestamp=now + timedelta(seconds=1),
            payload={"saga_id": "s2", "step_id": "st2", "action": "deploy", "error": "timeout"},
        ))

        spans = exporter.completed_spans
        assert len(spans) == 1
        assert spans[0].status == "error"
        assert spans[0].attributes["agent.saga.error"] == "timeout"

    def test_saga_without_sink(self):
        """Spans buffer internally when no sink is attached."""
        bus = HypervisorEventBus()
        exporter = SagaSpanExporter(bus)  # no sink

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_STARTED,
            timestamp=now,
            payload={"saga_id": "s3", "step_id": "st3"},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_STEP_COMMITTED,
            timestamp=now + timedelta(seconds=1),
            payload={"saga_id": "s3", "step_id": "st3"},
        ))

        assert len(exporter.completed_spans) == 1
        assert exporter.events_processed == 2

    def test_saga_completed_creates_saga_level_span(self):
        """SAGA_CREATED + SAGA_COMPLETED produces a saga-level span."""
        bus = HypervisorEventBus()
        exporter = SagaSpanExporter(bus)

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_CREATED,
            timestamp=now,
            payload={"saga_id": "saga-full"},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_COMPLETED,
            timestamp=now + timedelta(seconds=10),
            payload={"saga_id": "saga-full"},
        ))

        saga_spans = [s for s in exporter.completed_spans if "completed" in s.name]
        assert len(saga_spans) == 1
        assert abs(saga_spans[0].duration_seconds - 10.0) < 1.0

    def test_saga_escalated_creates_error_span(self):
        """SAGA_ESCALATED produces a saga-level span with error status."""
        bus = HypervisorEventBus()
        exporter = SagaSpanExporter(bus)

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_CREATED,
            timestamp=now,
            payload={"saga_id": "saga-esc"},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_ESCALATED,
            timestamp=now + timedelta(seconds=3),
            payload={"saga_id": "saga-esc", "reason": "max retries"},
        ))

        saga_spans = [s for s in exporter.completed_spans if "escalated" in s.name]
        assert len(saga_spans) == 1
        assert saga_spans[0].status == "error"

    def test_attach_detach_sink(self):
        """Attaching and detaching sinks works correctly."""
        bus = HypervisorEventBus()
        sink = _MockSpanSink()
        exporter = SagaSpanExporter(bus)

        # No sink — spans buffer only
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_COMPENSATING,
            payload={"saga_id": "s1"},
        ))
        assert len(sink.spans) == 0
        assert len(exporter.completed_spans) == 1

        # Attach sink — new spans go to sink
        exporter.attach_sink(sink)
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_COMPENSATING,
            payload={"saga_id": "s2"},
        ))
        assert len(sink.spans) == 1

        # Detach — back to buffer only
        exporter.detach_sink()
        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_COMPENSATING,
            payload={"saga_id": "s3"},
        ))
        assert len(sink.spans) == 1  # still 1

    def test_reset(self):
        """Reset clears all internal state."""
        bus = HypervisorEventBus()
        exporter = SagaSpanExporter(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.SAGA_COMPENSATING,
            payload={"saga_id": "s1"},
        ))
        assert exporter.events_processed == 1

        exporter.reset()
        assert exporter.events_processed == 0
        assert len(exporter.completed_spans) == 0
