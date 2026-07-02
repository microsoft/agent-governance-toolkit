# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for GovernanceEventSink SPI."""

import time

import pytest

from agent_os.event_sink import (
    AuditBackendSinkAdapter,
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventProcessor,
    GovernanceEventSigner,
    GovernanceEventSink,
    GovernanceEventSinkBase,
    OTLPGovernanceSink,
    SinkExportResult,
    StdoutGovernanceSink,
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
        # Enqueue BEFORE adding sink so the worker thread is not yet started.
        # This avoids a race where notify() wakes the worker which drains
        # events between on_event() calls, preventing overflow.
        for i in range(10):
            proc.on_event(GovernanceEvent(agent_id=f"agent-{i}"))

        assert proc.dropped_count > 0

        proc.add_sink(sink)
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

    def test_accounting_reconciles_happy_path(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(schedule_delay_ms=5000)
        proc.add_sink(sink)
        for _ in range(50):
            proc.on_event(GovernanceEvent())
        proc.force_flush(timeout_ms=2000)
        proc.shutdown(timeout_ms=2000)

        assert proc.submitted_count == 50
        assert proc.delivered_count == 50
        assert proc.failed_count == 0
        assert proc.dropped_count == 0
        assert (
            proc.submitted_count
            == proc.delivered_count + proc.failed_count + proc.dropped_count
        )

    def test_failing_sink_events_counted_not_silently_lost(self):
        """TASK defect 3, flipped: a FAILURE sink must not silently lose events."""
        sink = RecordingSink(result=SinkExportResult.FAILURE)
        proc = GovernanceEventProcessor(schedule_delay_ms=5000)
        proc.add_sink(sink)
        for _ in range(50):
            proc.on_event(GovernanceEvent())
        proc.force_flush(timeout_ms=2000)
        proc.shutdown(timeout_ms=2000)

        assert proc.submitted_count == 50
        assert proc.delivered_count == 0
        assert proc.failed_count == 50
        assert (
            proc.submitted_count
            == proc.delivered_count + proc.failed_count + proc.dropped_count
        )

    def test_post_shutdown_submissions_counted_as_dropped(self):
        sink = RecordingSink()
        proc = GovernanceEventProcessor(schedule_delay_ms=50)
        proc.add_sink(sink)
        proc.shutdown(timeout_ms=1000)

        proc.on_event(GovernanceEvent())
        assert proc.submitted_count == 1
        assert proc.dropped_count == 1
        assert (
            proc.submitted_count
            == proc.delivered_count + proc.failed_count + proc.dropped_count
        )


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


class TestCloudEventExport:
    def test_required_cloudevents_attributes_present(self):
        event = GovernanceEvent(
            kind=GovernanceEventKind.POLICY_VIOLATION,
            agent_id="agent-1",
            action="db_query",
            decision="deny",
        )
        ce = event.to_cloudevent(source="/agent-os/test")
        # CloudEvents 1.0 required attributes (the defect: these were missing).
        assert ce["specversion"] == "1.0"
        assert ce["id"] == event.event_id
        assert ce["source"] == "/agent-os/test"
        assert ce["type"] == "ai.agentmesh.policy.violation"
        assert ce["datacontenttype"] == "application/json"
        assert ce["data"]["action"] == "db_query"

    def test_source_defaults_and_requires_non_empty(self):
        # Derived from agent_id when no explicit source is given.
        ce = GovernanceEvent(agent_id="a7").to_cloudevent()
        assert ce["source"] == "/agent-os/agent/a7"
        # Fail closed when nothing can be resolved.
        with pytest.raises(ValueError):
            GovernanceEvent().to_cloudevent()

    def test_to_dict_unchanged_backward_compat(self):
        # to_dict() stays the flat legacy shape (AuditBackendSinkAdapter relies on it).
        d = GovernanceEvent().to_dict()
        assert "specversion" not in d
        assert "event_id" in d and "kind" in d and "occurred_at" in d


class TestGovernanceEventSigner:
    def test_sign_verify_round_trip(self):
        signer = GovernanceEventSigner(GovernanceEventSigner.generate_key())
        ce = GovernanceEvent(agent_id="a1").to_cloudevent(source="/s", signer=signer)
        assert ce["agtsignaturealg"] == "HMAC-SHA256"
        assert isinstance(ce["agtsignature"], str)
        assert signer.verify(ce) is True

    def test_tampered_data_fails_verification(self):
        signer = GovernanceEventSigner(GovernanceEventSigner.generate_key())
        ce = GovernanceEvent(agent_id="a1").to_cloudevent(source="/s", signer=signer)
        ce["data"]["action"] = "tampered"
        assert signer.verify(ce) is False

    def test_tampered_algorithm_fails_verification(self):
        signer = GovernanceEventSigner(GovernanceEventSigner.generate_key())
        ce = GovernanceEvent(agent_id="a1").to_cloudevent(source="/s", signer=signer)
        ce["agtsignaturealg"] = "NONE"
        assert signer.verify(ce) is False

    def test_short_key_rejected(self):
        with pytest.raises(ValueError):
            GovernanceEventSigner(b"tooshort")


class TestStdoutGovernanceSink:
    def test_emits_signed_cloudevent_json_line(self):
        import io
        import json as _json

        stream = io.StringIO()
        signer = GovernanceEventSigner(GovernanceEventSigner.generate_key())
        sink = StdoutGovernanceSink(source="/agent-os/x", signer=signer, stream=stream)

        result = sink.emit([GovernanceEvent(agent_id="a1"), GovernanceEvent(agent_id="a2")])
        assert result == SinkExportResult.SUCCESS

        lines = [ln for ln in stream.getvalue().splitlines() if ln]
        assert len(lines) == 2
        ce = _json.loads(lines[0])
        assert ce["specversion"] == "1.0"
        assert signer.verify(ce) is True


class TestOTLPGovernanceSink:
    def test_no_op_safe_when_otel_absent(self):
        # When the OTel backend is disabled (opentelemetry missing) the sink is
        # a safe no-op that still reports SUCCESS.
        class _DisabledBackend:
            enabled = False

            def write(self, entry):
                pass

            def flush(self):
                pass

        sink = OTLPGovernanceSink(source="/agent-os/x", backend=_DisabledBackend())
        result = sink.emit([GovernanceEvent(agent_id="a1")])
        assert result == SinkExportResult.SUCCESS

    def test_forwards_cloudevent_to_backend(self):
        written = []

        class _CapturingBackend:
            enabled = True

            def write(self, entry):
                written.append(entry)

            def flush(self):
                pass

        sink = OTLPGovernanceSink(source="/agent-os/x", backend=_CapturingBackend())
        result = sink.emit([GovernanceEvent(agent_id="a1", action="run")])
        assert result == SinkExportResult.SUCCESS
        assert len(written) == 1
        assert "cloudevent" in written[0].metadata
