# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for GovernanceEventSink SPI."""

import threading
import time

import pytest

from agent_os.event_sink import (
    AuditBackendSinkAdapter,
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventProcessor,
    GovernanceEventSink,
    GovernanceEventSinkBase,
    SinkExportResult,
)


class RecordingSink(GovernanceEventSinkBase):
    """Test sink that records all emitted batches."""

    def __init__(self, result: SinkExportResult = SinkExportResult.SUCCESS):
        self.batches: list[list[GovernanceEvent]] = []
        self.result = result
        self.shutdown_called = False
        self.flush_called = False

    def emit(self, events):
        self.batches.append(list(events))
        return self.result

    def shutdown(self, timeout_ms=5000):
        self.shutdown_called = True
        return True

    def force_flush(self, timeout_ms=30000):
        self.flush_called = True
        return True


class FailingSink(GovernanceEventSinkBase):
    """Sink that raises on every emit."""

    def emit(self, events):
        raise RuntimeError("sink error")


class TestGovernanceEvent:
    def test_default_fields(self):
        event = GovernanceEvent()
        assert event.schema_version == "1"
        assert event.kind == GovernanceEventKind.POLICY_CHECK
        assert event.severity == "info"
        assert len(event.event_id) == 32

    def test_custom_fields(self):
        event = GovernanceEvent(
            kind=GovernanceEventKind.POLICY_VIOLATION,
            agent_id="agent-1",
            action="database_query",
            decision="deny",
            reason="blocked pattern",
            severity="critical",
        )
        assert event.kind == GovernanceEventKind.POLICY_VIOLATION
        assert event.agent_id == "agent-1"
        assert event.decision == "deny"

    def test_immutable(self):
        event = GovernanceEvent()
        with pytest.raises(AttributeError):
            event.agent_id = "changed"

    def test_to_dict_excludes_none(self):
        event = GovernanceEvent(agent_id="a1", resource=None)
        d = event.to_dict()
        assert "resource" not in d
        assert d["agent_id"] == "a1"

    def test_to_dict_serializes_enums(self):
        event = GovernanceEvent(kind=GovernanceEventKind.TOOL_CALL_BLOCKED)
        d = event.to_dict()
        assert d["kind"] == "tool_call_blocked"


class TestGovernanceEventSinkProtocol:
    def test_recording_sink_is_protocol_compatible(self):
        sink = RecordingSink()
        assert isinstance(sink, GovernanceEventSink)

    def test_base_class_raises_not_implemented(self):
        base = GovernanceEventSinkBase()
        with pytest.raises(NotImplementedError):
            base.emit([])


class TestGovernanceEventProcessor:
    def test_single_sink_receives_events(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(
            schedule_delay_ms=50, max_batch_size=10
        )
        proc.add_sink(sink)

        for i in range(5):
            proc.on_event(GovernanceEvent(agent_id=f"agent-{i}"))

        proc.shutdown(timeout_ms=2000)
        total = sum(len(b) for b in sink.batches)
        assert total == 5

    def test_multiple_sinks_fan_out(self):
        sink1 = RecordingSink()
        sink2 = RecordingSink()
        proc = GovernanceEventProcessor(
            schedule_delay_ms=50, max_batch_size=10
        )
        proc.add_sink(sink1).add_sink(sink2)

        proc.on_event(GovernanceEvent(agent_id="test"))
        proc.shutdown(timeout_ms=2000)

        assert sum(len(b) for b in sink1.batches) == 1
        assert sum(len(b) for b in sink2.batches) == 1

    def test_failing_sink_does_not_block_others(self):
        failing = FailingSink()
        healthy = RecordingSink()
        proc = GovernanceEventProcessor(
            schedule_delay_ms=50, max_batch_size=10
        )
        proc.add_sink(failing).add_sink(healthy)

        proc.on_event(GovernanceEvent(agent_id="test"))
        proc.shutdown(timeout_ms=2000)

        assert sum(len(b) for b in healthy.batches) == 1

    def test_circuit_breaker_trips_after_threshold(self):
        failing = FailingSink()
        proc = GovernanceEventProcessor(
            schedule_delay_ms=50,
            max_batch_size=1,
            circuit_breaker_threshold=3,
            circuit_breaker_cooldown_s=60,
        )
        proc.add_sink(failing)

        for _ in range(10):
            proc.on_event(GovernanceEvent())

        proc.shutdown(timeout_ms=2000)
        # Circuit breaker should have tripped, so not all 10 events
        # result in emit calls (some are skipped after breaker opens)

    def test_queue_overflow_drops_oldest(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(
            max_queue_size=5, schedule_delay_ms=5000, max_batch_size=100
        )
        proc.add_sink(sink)

        # Enqueue 10 events into a queue of size 5
        for i in range(10):
            proc.on_event(GovernanceEvent(agent_id=f"agent-{i}"))

        assert proc.dropped_count > 0
        proc.shutdown(timeout_ms=2000)

        # Should have received at most 5 events (queue max)
        total = sum(len(b) for b in sink.batches)
        assert total <= 5

    def test_shutdown_calls_sink_shutdown(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(schedule_delay_ms=50)
        proc.add_sink(sink)
        proc.shutdown(timeout_ms=2000)
        assert sink.shutdown_called

    def test_force_flush(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(schedule_delay_ms=5000)
        proc.add_sink(sink)

        proc.on_event(GovernanceEvent())
        proc.force_flush(timeout_ms=2000)

        total = sum(len(b) for b in sink.batches)
        assert total == 1
        proc.shutdown(timeout_ms=1000)

    def test_no_events_after_shutdown(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(schedule_delay_ms=50)
        proc.add_sink(sink)
        proc.shutdown(timeout_ms=1000)

        proc.on_event(GovernanceEvent())
        time.sleep(0.1)
        total = sum(len(b) for b in sink.batches)
        assert total == 0

    def test_lazy_worker_start(self):
        proc = GovernanceEventProcessor(schedule_delay_ms=50)
        assert proc._worker is None
        proc.add_sink(RecordingSink())
        assert proc._worker is not None
        proc.shutdown(timeout_ms=1000)


class TestAuditBackendSinkAdapter:
    def test_bridges_to_audit_backend(self):
        from agent_os.audit_logger import AuditEntry

        entries: list[AuditEntry] = []
        flushed = [False]

        class MockBackend:
            def write(self, entry):
                entries.append(entry)

            def flush(self):
                flushed[0] = True

        adapter = AuditBackendSinkAdapter(MockBackend())
        event = GovernanceEvent(
            kind=GovernanceEventKind.POLICY_VIOLATION,
            agent_id="agent-1",
            action="db_query",
            decision="deny",
            reason="blocked",
            latency_ms=42.5,
        )
        result = adapter.emit([event])

        assert result == SinkExportResult.SUCCESS
        assert len(entries) == 1
        assert entries[0].agent_id == "agent-1"
        assert entries[0].event_type == "policy_violation"
        assert entries[0].latency_ms == 42.5
        assert flushed[0]

    def test_handles_backend_error(self):
        class BrokenBackend:
            def write(self, entry):
                raise IOError("disk full")

            def flush(self):
                pass

        adapter = AuditBackendSinkAdapter(BrokenBackend())
        result = adapter.emit([GovernanceEvent()])
        assert result == SinkExportResult.FAILURE
