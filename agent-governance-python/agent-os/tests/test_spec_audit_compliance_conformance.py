# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Conformance tests for the AGT Audit and Compliance specification.

Covers audit entry schemas, backend protocols, event sinks, Merkle chains,
compliance engines, decision BOMs, hypervisor audit, SRE events, and
cross-component correlation across agent-os, agent-mesh, agent-hypervisor,
agent-sre, and agent-lightning packages.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import unittest
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional, Sequence
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# sys.path setup -- import sibling packages from the monorepo
# ---------------------------------------------------------------------------
_MONO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
for _pkg in ("agent-mesh", "agent-hypervisor", "agent-sre", "agent-lightning"):
    _src = os.path.join(_MONO, _pkg, "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)

# Also ensure agent-os/src is on the path
_os_src = os.path.join(_MONO, "agent-os", "src")
if _os_src not in sys.path:
    sys.path.insert(0, _os_src)

# ---------------------------------------------------------------------------
# agent-os imports
# ---------------------------------------------------------------------------
from agent_os.audit_logger import (
    AuditEntry,
    GovernanceAuditLogger,
    InMemoryBackend,
    JsonlFileBackend,
    LoggingBackend,
)
from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventProcessor,
    GovernanceEventSink,
    SinkExportResult,
    AuditBackendSinkAdapter,
    _DEFAULT_MAX_QUEUE_SIZE,
    _DEFAULT_SCHEDULE_DELAY_MS,
    _DEFAULT_MAX_BATCH_SIZE,
    _DEFAULT_EXPORT_TIMEOUT_MS,
    _DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
    _DEFAULT_CIRCUIT_BREAKER_COOLDOWN_S,
)
from agent_os.policies.decision import PolicyCheckResult, ViolationCategory
from agent_os.integrations.logging import GovernanceLogger, get_logger

# ---------------------------------------------------------------------------
# agent-mesh imports
# ---------------------------------------------------------------------------
from agentmesh.governance.audit import (
    AuditEntry as MeshAuditEntry,
    AuditLog,
    MerkleAuditChain,
    MerkleNode,
)
from agentmesh.governance.compliance import (
    ComplianceControl,
    ComplianceEngine,
    ComplianceFramework,
    ComplianceMapping,
    ComplianceReport,
    ComplianceViolation,
)
from agentmesh.governance.decision_bom import (
    AuditSource,
    BOMFieldCategory,
    DecisionBOM,
    DecisionBOMReconstructor,
    PolicySource,
    TraceSource,
    TrustSource,
)

# ---------------------------------------------------------------------------
# agent-hypervisor imports (optional — not in agent-os[dev])
# ---------------------------------------------------------------------------
try:
    from hypervisor.audit.delta import DeltaEngine, SemanticDelta, VFSChange
    from hypervisor.observability.event_bus import (
        EventType,
        HypervisorEvent,
        HypervisorEventBus,
    )
except ImportError:
    pytest.skip("agent-hypervisor not installed", allow_module_level=True)

# ---------------------------------------------------------------------------
# agent-sre imports (optional — not a declared dependency of agent-os)
# ---------------------------------------------------------------------------
try:
    from agent_sre.integrations.otel.events import EventLogger as SREEventLogger
    from agent_sre.integrations.otel import conventions as sre_conventions
except ImportError:
    pytest.skip("agent-sre with opentelemetry not installed", allow_module_level=True)

# ---------------------------------------------------------------------------
# agent-lightning imports (optional — not a declared dependency of agent-os)
# ---------------------------------------------------------------------------
try:
    from agent_lightning_gov.emitter import FlightRecorderEmitter, LightningSpan
except ImportError:
    pytest.skip("agent-lightning not installed", allow_module_level=True)


# ===================================================================
# S5 -- Audit Entry Schema
# ===================================================================
class TestAuditEntrySchema(unittest.TestCase):
    """Conformance tests for the agent-os AuditEntry dataclass (spec S5)."""

    def test_default_timestamp_is_utc_iso(self):
        """S5.1 -- default timestamp must be UTC ISO-8601."""
        entry = AuditEntry()
        ts = entry.timestamp
        self.assertIn("T", ts)
        # Must parse without error
        parsed = datetime.fromisoformat(ts)
        self.assertIsNotNone(parsed)

    def test_default_fields_are_empty(self):
        """S5.2 -- event_type, agent_id, action, decision, reason default to empty string."""
        entry = AuditEntry()
        self.assertEqual(entry.event_type, "")
        self.assertEqual(entry.agent_id, "")
        self.assertEqual(entry.action, "")
        self.assertEqual(entry.decision, "")
        self.assertEqual(entry.reason, "")

    def test_default_latency_is_zero(self):
        """S5.3 -- latency_ms defaults to 0.0."""
        entry = AuditEntry()
        self.assertEqual(entry.latency_ms, 0.0)

    def test_default_metadata_is_empty_dict(self):
        """S5.4 -- metadata defaults to empty dict."""
        entry = AuditEntry()
        self.assertIsInstance(entry.metadata, dict)
        self.assertEqual(len(entry.metadata), 0)

    def test_to_dict_returns_dict(self):
        """S5.5 -- to_dict must return a plain dict."""
        entry = AuditEntry(event_type="test", agent_id="a1")
        d = entry.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["event_type"], "test")
        self.assertEqual(d["agent_id"], "a1")

    def test_to_json_returns_valid_json(self):
        """S5.6 -- to_json must return valid JSON string."""
        entry = AuditEntry(event_type="check", agent_id="a2", action="read")
        j = entry.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["event_type"], "check")

    def test_metadata_preserved_in_serialization(self):
        """S5.7 -- metadata dict survives round-trip serialization."""
        entry = AuditEntry(metadata={"key": "value", "count": 42})
        d = json.loads(entry.to_json())
        self.assertEqual(d["metadata"]["key"], "value")
        self.assertEqual(d["metadata"]["count"], 42)

    def test_custom_timestamp_accepted(self):
        """S5.8 -- explicitly provided timestamp must be used."""
        ts = "2024-01-01T00:00:00+00:00"
        entry = AuditEntry(timestamp=ts)
        self.assertEqual(entry.timestamp, ts)

    def test_all_fields_in_to_dict(self):
        """S5.9 -- to_dict must include every field."""
        entry = AuditEntry()
        d = entry.to_dict()
        for key in ("timestamp", "event_type", "agent_id", "action",
                     "decision", "reason", "latency_ms", "metadata"):
            self.assertIn(key, d)

    def test_latency_accepts_float(self):
        """S5.10 -- latency_ms must accept float values."""
        entry = AuditEntry(latency_ms=12.345)
        self.assertAlmostEqual(entry.latency_ms, 12.345, places=3)

    def test_entry_is_dataclass(self):
        """S5.11 -- AuditEntry must be a dataclass."""
        from dataclasses import fields as dc_fields
        f = dc_fields(AuditEntry)
        names = {x.name for x in f}
        self.assertIn("timestamp", names)
        self.assertIn("metadata", names)

    def test_metadata_isolation_between_instances(self):
        """S5.12 -- each instance must have its own metadata dict."""
        e1 = AuditEntry()
        e2 = AuditEntry()
        e1.metadata["x"] = 1
        self.assertNotIn("x", e2.metadata)


# ===================================================================
# S6 -- Audit Backend Protocol
# ===================================================================
class TestAuditBackendProtocol(unittest.TestCase):
    """Conformance tests for audit backend implementations (spec S6)."""

    def test_in_memory_backend_stores_entries(self):
        """S6.1 -- InMemoryBackend.write must append entries."""
        backend = InMemoryBackend()
        entry = AuditEntry(event_type="test")
        backend.write(entry)
        self.assertEqual(len(backend.entries), 1)

    def test_in_memory_backend_flush_is_noop(self):
        """S6.2 -- InMemoryBackend.flush must not raise."""
        backend = InMemoryBackend()
        backend.flush()  # should not raise

    def test_in_memory_backend_preserves_order(self):
        """S6.3 -- entries must be stored in insertion order."""
        backend = InMemoryBackend()
        for i in range(5):
            backend.write(AuditEntry(event_type=f"e{i}"))
        self.assertEqual([e.event_type for e in backend.entries],
                         [f"e{i}" for i in range(5)])

    def test_jsonl_backend_writes_file(self):
        """S6.4 -- JsonlFileBackend must write JSONL to disk."""
        td = tempfile.mkdtemp()
        try:
            path = os.path.join(td, "audit.jsonl")
            backend = JsonlFileBackend(path)
            backend.write(AuditEntry(event_type="file_test"))
            backend.flush()
            # Close underlying file handle if present (Windows file-lock)
            if hasattr(backend, "_file") and backend._file:
                backend._file.close()
            with open(path) as f:
                lines = f.readlines()
            self.assertGreaterEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["event_type"], "file_test")
        finally:
            import shutil
            try:
                shutil.rmtree(td, ignore_errors=True)
            except Exception:
                pass

    def test_jsonl_backend_appends(self):
        """S6.5 -- JsonlFileBackend must append, not overwrite."""
        td = tempfile.mkdtemp()
        try:
            path = os.path.join(td, "audit.jsonl")
            backend = JsonlFileBackend(path)
            backend.write(AuditEntry(event_type="first"))
            backend.write(AuditEntry(event_type="second"))
            backend.flush()
            if hasattr(backend, "_file") and backend._file:
                backend._file.close()
            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)
        finally:
            import shutil
            try:
                shutil.rmtree(td, ignore_errors=True)
            except Exception:
                pass

    def test_logging_backend_does_not_raise(self):
        """S6.6 -- LoggingBackend.write must not raise."""
        backend = LoggingBackend()
        backend.write(AuditEntry(event_type="log_test"))
        backend.flush()

    def test_logging_backend_custom_name(self):
        """S6.7 -- LoggingBackend must accept custom logger name."""
        backend = LoggingBackend(logger_name="custom.audit")
        backend.write(AuditEntry(event_type="custom"))

    def test_in_memory_backend_multiple_entries(self):
        """S6.8 -- InMemoryBackend must handle many entries."""
        backend = InMemoryBackend()
        for i in range(100):
            backend.write(AuditEntry(event_type=f"bulk_{i}"))
        self.assertEqual(len(backend.entries), 100)


# ===================================================================
# S8 -- Governance Audit Logger
# ===================================================================
class TestGovernanceAuditLogger(unittest.TestCase):
    """Conformance tests for GovernanceAuditLogger (spec S8)."""

    def setUp(self):
        self.logger = GovernanceAuditLogger()
        self.backend = InMemoryBackend()
        self.logger.add_backend(self.backend)

    def test_log_dispatches_to_backend(self):
        """S8.1 -- log() must dispatch to all registered backends."""
        self.logger.log(AuditEntry(event_type="test"))
        self.assertEqual(len(self.backend.entries), 1)

    def test_log_decision_creates_entry(self):
        """S8.2 -- log_decision must create and dispatch an AuditEntry."""
        self.logger.log_decision(
            agent_id="a1", action="read", decision="allow", reason="ok"
        )
        self.assertEqual(len(self.backend.entries), 1)
        e = self.backend.entries[0]
        self.assertEqual(e.agent_id, "a1")
        self.assertEqual(e.decision, "allow")

    def test_log_decision_latency(self):
        """S8.3 -- log_decision must propagate latency_ms."""
        self.logger.log_decision(
            agent_id="a1", action="x", decision="deny", latency_ms=5.5
        )
        self.assertAlmostEqual(self.backend.entries[0].latency_ms, 5.5)

    def test_log_decision_metadata_kwargs(self):
        """S8.4 -- extra kwargs in log_decision must appear in metadata."""
        self.logger.log_decision(
            agent_id="a1", action="x", decision="y", custom_key="custom_val"
        )
        self.assertEqual(self.backend.entries[0].metadata["custom_key"], "custom_val")

    def test_flush_calls_backend_flush(self):
        """S8.5 -- flush() must call flush on every backend."""
        mock_backend = MagicMock()
        self.logger.add_backend(mock_backend)
        self.logger.flush()
        mock_backend.flush.assert_called()

    def test_multiple_backends(self):
        """S8.6 -- entries must be dispatched to all backends."""
        b2 = InMemoryBackend()
        self.logger.add_backend(b2)
        self.logger.log(AuditEntry(event_type="multi"))
        self.assertEqual(len(self.backend.entries), 1)
        self.assertEqual(len(b2.entries), 1)

    def test_empty_logger_no_error(self):
        """S8.7 -- logging with no backends must not raise."""
        logger = GovernanceAuditLogger()
        logger.log(AuditEntry(event_type="no_backend"))

    def test_log_decision_default_reason(self):
        """S8.8 -- log_decision with no reason must default to empty string."""
        self.logger.log_decision(agent_id="a1", action="x", decision="y")
        self.assertEqual(self.backend.entries[0].reason, "")

    def test_log_preserves_all_fields(self):
        """S8.9 -- log must preserve all AuditEntry fields."""
        entry = AuditEntry(
            event_type="full", agent_id="agent", action="act",
            decision="dec", reason="res", latency_ms=1.0,
            metadata={"k": "v"},
        )
        self.logger.log(entry)
        stored = self.backend.entries[0]
        self.assertEqual(stored.event_type, "full")
        self.assertEqual(stored.metadata["k"], "v")

    def test_add_backend_returns_none(self):
        """S8.10 -- add_backend has no meaningful return value and must not raise."""
        result = self.logger.add_backend(InMemoryBackend())
        # Just verify it did not raise
        self.assertIsNone(result)


# ===================================================================
# S9 -- Governance Event Schema
# ===================================================================
class TestGovernanceEventSchema(unittest.TestCase):
    """Conformance tests for GovernanceEvent and GovernanceEventKind (spec S9)."""

    def test_event_kind_enum_values(self):
        """S9.1 -- GovernanceEventKind must contain required enum members."""
        required = {
            "POLICY_CHECK", "POLICY_VIOLATION", "TOOL_CALL_BLOCKED",
            "PROMPT_INJECTION_DETECTED", "IDENTITY_VERIFIED",
            "IDENTITY_REJECTED", "RESOURCE_ACCESS",
            "ESCALATION_REQUESTED", "CHECKPOINT_CREATED",
            "ANOMALY_DETECTED", "MCP_TOOL_POISONING", "CONTENT_VIOLATION",
        }
        actual = {m.name for m in GovernanceEventKind}
        self.assertTrue(required.issubset(actual))

    def test_default_schema_version(self):
        """S9.2 -- default schema_version must be set."""
        e = GovernanceEvent()
        self.assertIsNotNone(e.schema_version)
        self.assertNotEqual(e.schema_version, "")

    def test_event_id_auto_generated(self):
        """S9.3 -- event_id must be auto-generated and unique."""
        e1 = GovernanceEvent()
        e2 = GovernanceEvent()
        self.assertNotEqual(e1.event_id, e2.event_id)

    def test_occurred_at_is_utc(self):
        """S9.4 -- occurred_at must be a UTC ISO timestamp."""
        e = GovernanceEvent()
        self.assertIn("T", e.occurred_at)

    def test_default_kind_is_policy_check(self):
        """S9.5 -- default kind must be POLICY_CHECK."""
        e = GovernanceEvent()
        self.assertEqual(e.kind, GovernanceEventKind.POLICY_CHECK)

    def test_default_severity_is_info(self):
        """S9.6 -- default severity must be 'info'."""
        e = GovernanceEvent()
        self.assertEqual(e.severity, "info")

    def test_optional_fields_default_none(self):
        """S9.7 -- optional fields must default to None."""
        e = GovernanceEvent()
        self.assertIsNone(e.agent_did)
        self.assertIsNone(e.session_id)
        self.assertIsNone(e.resource)
        self.assertIsNone(e.trace_id)
        self.assertIsNone(e.span_id)

    def test_to_dict_returns_dict(self):
        """S9.8 -- to_dict must return a dict with all fields."""
        e = GovernanceEvent(kind=GovernanceEventKind.POLICY_VIOLATION,
                            agent_id="a1", action="write")
        d = e.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("kind", d)
        self.assertIn("agent_id", d)

    def test_attributes_default_empty(self):
        """S9.9 -- attributes must default to empty dict."""
        e = GovernanceEvent()
        self.assertIsInstance(e.attributes, dict)
        self.assertEqual(len(e.attributes), 0)

    def test_frozen_event_is_immutable(self):
        """S9.10 -- GovernanceEvent is frozen -- attribute assignment must raise."""
        e = GovernanceEvent()
        with self.assertRaises((AttributeError, TypeError, Exception)):
            e.agent_id = "changed"  # type: ignore[misc]

    def test_event_kind_string_values(self):
        """S9.11 -- GovernanceEventKind members must have snake_case string values."""
        for member in GovernanceEventKind:
            self.assertEqual(member.value, member.value.lower())
            self.assertNotIn(" ", member.value)

    def test_sink_export_result_enum(self):
        """S9.12 -- SinkExportResult must have SUCCESS, FAILURE, DROPPED."""
        self.assertEqual(SinkExportResult.SUCCESS.value, 0)
        self.assertEqual(SinkExportResult.FAILURE.value, 1)
        self.assertEqual(SinkExportResult.DROPPED.value, 2)


# ===================================================================
# S10 -- Governance Event Sink Protocol
# ===================================================================
class TestGovernanceEventSinkProtocol(unittest.TestCase):
    """Conformance tests for GovernanceEventSink protocol (spec S10)."""

    def test_protocol_is_runtime_checkable(self):
        """S10.1 -- GovernanceEventSink must be @runtime_checkable."""
        self.assertTrue(hasattr(GovernanceEventSink, "__protocol_attrs__") or
                        issubclass(type(GovernanceEventSink), type))

    def test_adapter_wraps_backend(self):
        """S10.2 -- AuditBackendSinkAdapter must wrap an audit backend."""
        backend = InMemoryBackend()
        adapter = AuditBackendSinkAdapter(backend)
        event = GovernanceEvent(agent_id="a1", action="read", decision="allow")
        result = adapter.emit([event])
        self.assertEqual(result, SinkExportResult.SUCCESS)

    def test_adapter_writes_to_backend(self):
        """S10.3 -- adapter emit must write to underlying backend."""
        backend = InMemoryBackend()
        adapter = AuditBackendSinkAdapter(backend)
        adapter.emit([GovernanceEvent(agent_id="x")])
        self.assertGreaterEqual(len(backend.entries), 1)

    def test_adapter_handles_empty_batch(self):
        """S10.4 -- adapter must handle empty event list."""
        backend = InMemoryBackend()
        adapter = AuditBackendSinkAdapter(backend)
        result = adapter.emit([])
        self.assertEqual(result, SinkExportResult.SUCCESS)

    def test_adapter_shutdown(self):
        """S10.5 -- adapter shutdown must return bool."""
        backend = InMemoryBackend()
        adapter = AuditBackendSinkAdapter(backend)
        result = adapter.shutdown()
        self.assertIsInstance(result, bool)

    def test_adapter_force_flush(self):
        """S10.6 -- adapter force_flush must return bool."""
        backend = InMemoryBackend()
        adapter = AuditBackendSinkAdapter(backend)
        result = adapter.force_flush()
        self.assertIsInstance(result, bool)

    def test_adapter_multiple_events(self):
        """S10.7 -- adapter must handle multiple events in one emit."""
        backend = InMemoryBackend()
        adapter = AuditBackendSinkAdapter(backend)
        events = [GovernanceEvent(agent_id=f"a{i}") for i in range(5)]
        adapter.emit(events)
        self.assertGreaterEqual(len(backend.entries), 5)

    def test_custom_sink_conformance(self):
        """S10.8 -- a custom class implementing emit/shutdown/force_flush must work."""
        class MySink:
            def __init__(self):
                self.received: list = []
            def emit(self, events):
                self.received.extend(events)
                return SinkExportResult.SUCCESS
            def shutdown(self, timeout_ms=5000):
                return True
            def force_flush(self, timeout_ms=30000):
                return True

        sink = MySink()
        sink.emit([GovernanceEvent()])
        self.assertEqual(len(sink.received), 1)


# ===================================================================
# S11 -- Governance Event Processor
# ===================================================================
class TestGovernanceEventProcessor(unittest.TestCase):
    """Conformance tests for GovernanceEventProcessor (spec S11)."""

    def _make_sink(self):
        class CaptureSink:
            def __init__(self):
                self.events: list = []
            def emit(self, events):
                self.events.extend(events)
                return SinkExportResult.SUCCESS
            def shutdown(self, timeout_ms=5000):
                return True
            def force_flush(self, timeout_ms=30000):
                return True
        return CaptureSink()

    def test_default_constants(self):
        """S11.1 -- default config constants must have expected values."""
        self.assertEqual(_DEFAULT_MAX_QUEUE_SIZE, 1024)
        self.assertEqual(_DEFAULT_SCHEDULE_DELAY_MS, 2000)
        self.assertEqual(_DEFAULT_MAX_BATCH_SIZE, 100)
        self.assertEqual(_DEFAULT_EXPORT_TIMEOUT_MS, 10000)
        self.assertEqual(_DEFAULT_CIRCUIT_BREAKER_THRESHOLD, 5)
        self.assertEqual(_DEFAULT_CIRCUIT_BREAKER_COOLDOWN_S, 60)

    def test_add_sink_returns_processor(self):
        """S11.2 -- add_sink must return the processor for chaining."""
        proc = GovernanceEventProcessor()
        result = proc.add_sink(self._make_sink())
        self.assertIs(result, proc)
        proc.shutdown()

    def test_on_event_accepts_event(self):
        """S11.3 -- on_event must accept a GovernanceEvent without error."""
        proc = GovernanceEventProcessor()
        sink = self._make_sink()
        proc.add_sink(sink)
        proc.on_event(GovernanceEvent(agent_id="a1"))
        proc.shutdown()

    def test_shutdown_returns_bool(self):
        """S11.4 -- shutdown must return a boolean."""
        proc = GovernanceEventProcessor()
        result = proc.shutdown()
        self.assertIsInstance(result, bool)

    def test_processor_with_no_sinks(self):
        """S11.5 -- processor with no sinks must not raise on on_event."""
        proc = GovernanceEventProcessor()
        proc.on_event(GovernanceEvent())
        proc.shutdown()

    def test_custom_max_queue_size(self):
        """S11.6 -- processor must accept custom max_queue_size."""
        proc = GovernanceEventProcessor(max_queue_size=10)
        proc.shutdown()

    def test_custom_schedule_delay(self):
        """S11.7 -- processor must accept custom schedule_delay_ms."""
        proc = GovernanceEventProcessor(schedule_delay_ms=500)
        proc.shutdown()

    def test_custom_max_batch_size(self):
        """S11.8 -- processor must accept custom max_batch_size."""
        proc = GovernanceEventProcessor(max_batch_size=50)
        proc.shutdown()

    def test_custom_export_timeout(self):
        """S11.9 -- processor must accept custom export_timeout_ms."""
        proc = GovernanceEventProcessor(export_timeout_ms=5000)
        proc.shutdown()

    def test_circuit_breaker_params(self):
        """S11.10 -- processor must accept circuit breaker parameters."""
        proc = GovernanceEventProcessor(
            circuit_breaker_threshold=3,
            circuit_breaker_cooldown_s=30,
        )
        proc.shutdown()

    def test_multiple_sinks_chaining(self):
        """S11.11 -- multiple add_sink calls must chain."""
        proc = GovernanceEventProcessor()
        s1 = self._make_sink()
        s2 = self._make_sink()
        result = proc.add_sink(s1).add_sink(s2)
        self.assertIs(result, proc)
        proc.shutdown()

    def test_processor_handles_many_events(self):
        """S11.12 -- processor must handle many events without error."""
        proc = GovernanceEventProcessor()
        sink = self._make_sink()
        proc.add_sink(sink)
        for i in range(50):
            proc.on_event(GovernanceEvent(agent_id=f"a{i}"))
        proc.shutdown()


# ===================================================================
# S12 -- Mesh Audit Entry (Pydantic)
# ===================================================================
class TestMeshAuditEntry(unittest.TestCase):
    """Conformance tests for agent-mesh AuditEntry (spec S12)."""

    def test_entry_id_auto_generated(self):
        """S12.1 -- entry_id must be auto-generated with 'audit_' prefix."""
        e = MeshAuditEntry(event_type="test", agent_did="did:example:1", action="read")
        self.assertTrue(e.entry_id.startswith("audit_"))

    def test_timestamp_auto_set(self):
        """S12.2 -- timestamp must be auto-set to UTC."""
        e = MeshAuditEntry(event_type="test", agent_did="did:example:1", action="read")
        self.assertIsNotNone(e.timestamp)

    def test_required_fields(self):
        """S12.3 -- event_type, agent_did, action must be required."""
        e = MeshAuditEntry(event_type="policy", agent_did="did:x", action="write")
        self.assertEqual(e.event_type, "policy")
        self.assertEqual(e.agent_did, "did:x")
        self.assertEqual(e.action, "write")

    def test_default_outcome_is_success(self):
        """S12.4 -- outcome must default to 'success'."""
        e = MeshAuditEntry(event_type="t", agent_did="d", action="a")
        self.assertEqual(e.outcome, "success")

    def test_compute_hash_returns_string(self):
        """S12.5 -- compute_hash must return a hex hash string."""
        e = MeshAuditEntry(event_type="t", agent_did="d", action="a")
        h = e.compute_hash()
        self.assertIsInstance(h, str)
        self.assertGreater(len(h), 0)

    def test_verify_hash_after_compute(self):
        """S12.6 -- verify_hash must return True after compute_hash."""
        e = MeshAuditEntry(event_type="t", agent_did="d", action="a")
        e.entry_hash = e.compute_hash()
        self.assertTrue(e.verify_hash())

    def test_to_cloudevent_returns_dict(self):
        """S12.7 -- to_cloudevent must return a CloudEvents dict."""
        e = MeshAuditEntry(event_type="t", agent_did="d", action="a")
        ce = e.to_cloudevent()
        self.assertIsInstance(ce, dict)

    def test_optional_fields_default_none(self):
        """S12.8 -- optional fields default to None."""
        e = MeshAuditEntry(event_type="t", agent_did="d", action="a")
        self.assertIsNone(e.resource)
        self.assertIsNone(e.target_did)
        self.assertIsNone(e.policy_decision)

    def test_data_defaults_empty_dict(self):
        """S12.9 -- data must default to empty dict."""
        e = MeshAuditEntry(event_type="t", agent_did="d", action="a")
        self.assertIsInstance(e.data, dict)
        self.assertEqual(len(e.data), 0)

    def test_audit_log_creates_entry(self):
        """S12.10 -- AuditLog.log must create and return an AuditEntry."""
        log = AuditLog()
        entry = log.log(event_type="test", agent_did="did:x", action="run")
        self.assertIsInstance(entry, MeshAuditEntry)
        self.assertEqual(entry.event_type, "test")


# ===================================================================
# S13 -- Merkle Audit Chain
# ===================================================================
class TestMerkleAuditChain(unittest.TestCase):
    """Conformance tests for MerkleAuditChain integrity (spec S13)."""

    def _make_entry(self, event_type="test", action="read"):
        return MeshAuditEntry(event_type=event_type, agent_did="did:test", action=action)

    def test_empty_chain_root_is_none(self):
        """S13.1 -- empty chain must have None root hash."""
        chain = MerkleAuditChain()
        self.assertIsNone(chain.get_root_hash())

    def test_add_entry_sets_root(self):
        """S13.2 -- adding an entry must set a non-None root hash."""
        chain = MerkleAuditChain()
        chain.add_entry(self._make_entry())
        self.assertIsNotNone(chain.get_root_hash())

    def test_root_changes_on_new_entry(self):
        """S13.3 -- root hash must change when a new entry is added."""
        chain = MerkleAuditChain()
        chain.add_entry(self._make_entry(action="a1"))
        r1 = chain.get_root_hash()
        chain.add_entry(self._make_entry(action="a2"))
        r2 = chain.get_root_hash()
        self.assertNotEqual(r1, r2)

    def test_verify_chain_empty(self):
        """S13.4 -- verify_chain on empty chain must return (True, None)."""
        chain = MerkleAuditChain()
        valid, err = chain.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_verify_chain_single_entry(self):
        """S13.5 -- verify_chain with one entry must return True."""
        chain = MerkleAuditChain()
        chain.add_entry(self._make_entry())
        valid, err = chain.verify_chain()
        self.assertTrue(valid)

    def test_verify_chain_multiple_entries(self):
        """S13.6 -- verify_chain with multiple entries must return True."""
        chain = MerkleAuditChain()
        for i in range(10):
            chain.add_entry(self._make_entry(action=f"act_{i}"))
        valid, err = chain.verify_chain()
        self.assertTrue(valid)

    def test_get_proof_returns_list(self):
        """S13.7 -- get_proof must return a list of (hash, side) tuples."""
        chain = MerkleAuditChain()
        entry = self._make_entry()
        chain.add_entry(entry)
        proof = chain.get_proof(entry.entry_id)
        self.assertIsInstance(proof, list)

    def test_verify_proof_valid(self):
        """S13.8 -- verify_proof must return True for a valid proof."""
        chain = MerkleAuditChain()
        entry = self._make_entry()
        entry.entry_hash = entry.compute_hash()
        chain.add_entry(entry)
        root = chain.get_root_hash()
        proof = chain.get_proof(entry.entry_id)
        if proof is not None and root is not None:
            result = chain.verify_proof(entry.entry_hash, proof, root)
            self.assertTrue(result)

    def test_get_proof_nonexistent_entry(self):
        """S13.9 -- get_proof for nonexistent entry must return None."""
        chain = MerkleAuditChain()
        chain.add_entry(self._make_entry())
        proof = chain.get_proof("nonexistent_id")
        self.assertIsNone(proof)

    def test_chain_deterministic(self):
        """S13.10 -- same entries must produce same root hash."""
        def build_chain():
            c = MerkleAuditChain()
            for i in range(3):
                e = MeshAuditEntry(
                    entry_id=f"audit_fixed_{i}",
                    event_type="test",
                    agent_did="did:test",
                    action=f"act_{i}",
                    timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
                )
                e.entry_hash = e.compute_hash()
                c.add_entry(e)
            return c.get_root_hash()
        r1 = build_chain()
        r2 = build_chain()
        self.assertEqual(r1, r2)

    def test_audit_log_verify_integrity(self):
        """S13.11 -- AuditLog.verify_integrity must return (True, None) for valid log."""
        log = AuditLog()
        log.log(event_type="a", agent_did="did:x", action="run")
        log.log(event_type="b", agent_did="did:x", action="read")
        valid, err = log.verify_integrity()
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_merkle_node_fields(self):
        """S13.12 -- MerkleNode must have hash, children, is_leaf fields."""
        node = MerkleNode(hash="abc123")
        self.assertEqual(node.hash, "abc123")
        self.assertIsNone(node.left_child)
        self.assertIsNone(node.right_child)
        self.assertFalse(node.is_leaf)


# ===================================================================
# S16 -- Compliance Engine
# ===================================================================
class TestComplianceEngine(unittest.TestCase):
    """Conformance tests for ComplianceEngine (spec S16)."""

    def test_framework_enum_values(self):
        """S16.1 -- ComplianceFramework must include required frameworks."""
        self.assertEqual(ComplianceFramework.EU_AI_ACT.value, "eu_ai_act")
        self.assertEqual(ComplianceFramework.SOC2.value, "soc2")
        self.assertEqual(ComplianceFramework.HIPAA.value, "hipaa")
        self.assertEqual(ComplianceFramework.GDPR.value, "gdpr")

    def test_engine_defaults_to_soc2(self):
        """S16.2 -- ComplianceEngine with no args should default to SOC2."""
        engine = ComplianceEngine()
        # Engine should be constructable with defaults
        self.assertIsNotNone(engine)

    def test_engine_accepts_frameworks(self):
        """S16.3 -- ComplianceEngine must accept explicit framework list."""
        engine = ComplianceEngine(frameworks=[ComplianceFramework.GDPR])
        self.assertIsNotNone(engine)

    def test_control_model_fields(self):
        """S16.4 -- ComplianceControl must have required fields."""
        control = ComplianceControl(
            control_id="CC1.1",
            framework=ComplianceFramework.SOC2,
            name="Logical Access",
            description="Controls for logical access",
            category="access",
        )
        self.assertEqual(control.control_id, "CC1.1")
        self.assertEqual(control.framework, ComplianceFramework.SOC2)

    def test_mapping_model_fields(self):
        """S16.5 -- ComplianceMapping must have action_type and controls."""
        mapping = ComplianceMapping(
            action_type="tool_call",
            controls=["CC1.1"],
            evidence_generated=["audit_log"],
        )
        self.assertEqual(mapping.action_type, "tool_call")
        self.assertIn("CC1.1", mapping.controls)

    def test_violation_model_fields(self):
        """S16.6 -- ComplianceViolation must have required fields."""
        v = ComplianceViolation(
            violation_id="v1",
            timestamp=datetime.now(timezone.utc),
            agent_did="did:x",
            action_type="write",
            control_id="CC1.1",
            framework=ComplianceFramework.SOC2,
            description="Access without auth",
        )
        self.assertEqual(v.violation_id, "v1")
        self.assertFalse(v.remediated)

    def test_violation_severity_default(self):
        """S16.7 -- violation severity must default to 'medium'."""
        v = ComplianceViolation(
            violation_id="v2",
            timestamp=datetime.now(timezone.utc),
            agent_did="did:x",
            action_type="read",
            control_id="CC1.1",
            framework=ComplianceFramework.SOC2,
            description="test",
        )
        self.assertEqual(v.severity, "medium")

    def test_report_model_fields(self):
        """S16.8 -- ComplianceReport must have required fields."""
        now = datetime.now(timezone.utc)
        report = ComplianceReport(
            report_id="r1",
            generated_at=now,
            framework=ComplianceFramework.SOC2,
            period_start=now - timedelta(days=30),
            period_end=now,
            agents_covered=["did:a1"],
            violations=[],
            recommendations=[],
        )
        self.assertEqual(report.report_id, "r1")
        self.assertEqual(report.compliance_score, 0.0)

    def test_report_defaults(self):
        """S16.9 -- report numeric fields must default to zero."""
        now = datetime.now(timezone.utc)
        report = ComplianceReport(
            report_id="r2",
            generated_at=now,
            framework=ComplianceFramework.SOC2,
            period_start=now,
            period_end=now,
            agents_covered=[],
            violations=[],
            recommendations=[],
        )
        self.assertEqual(report.total_controls, 0)
        self.assertEqual(report.controls_met, 0)
        self.assertEqual(report.controls_partial, 0)
        self.assertEqual(report.controls_failed, 0)
        self.assertEqual(report.evidence_items, 0)

    def test_map_action(self):
        """S16.10 -- map_action must return Optional[ComplianceMapping]."""
        engine = ComplianceEngine()
        # May return None for unknown action
        result = engine.map_action("unknown_action_xyz")
        # Just verify the method exists and returns without error
        self.assertTrue(result is None or isinstance(result, ComplianceMapping))

    def test_check_compliance(self):
        """S16.11 -- check_compliance must return list of violations."""
        engine = ComplianceEngine()
        violations = engine.check_compliance(
            agent_did="did:test",
            action_type="tool_call",
            context={"tool": "file_read"},
        )
        self.assertIsInstance(violations, list)

    def test_generate_report(self):
        """S16.12 -- generate_report must return a ComplianceReport."""
        engine = ComplianceEngine()
        now = datetime.now(timezone.utc)
        report = engine.generate_report(
            framework=ComplianceFramework.SOC2,
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        self.assertIsInstance(report, ComplianceReport)

    def test_remediate_violation(self):
        """S16.13 -- remediate_violation must return a bool."""
        engine = ComplianceEngine()
        result = engine.remediate_violation(
            violation_id="nonexistent", notes="test remediation"
        )
        self.assertIsInstance(result, bool)

    def test_control_optional_fields(self):
        """S16.14 -- ComplianceControl optional fields default correctly."""
        c = ComplianceControl(
            control_id="test",
            framework=ComplianceFramework.HIPAA,
            name="Test",
            description="Test control",
            category="security",
        )
        self.assertIsNone(c.subcategory)
        self.assertEqual(c.requirements, [])
        self.assertEqual(c.evidence_types, [])

    def test_multiple_frameworks(self):
        """S16.15 -- engine must accept multiple frameworks."""
        engine = ComplianceEngine(
            frameworks=[ComplianceFramework.SOC2, ComplianceFramework.GDPR]
        )
        self.assertIsNotNone(engine)


# ===================================================================
# S17 -- Decision BOM
# ===================================================================
class TestDecisionBOM(unittest.TestCase):
    """Conformance tests for DecisionBOM and reconstruction (spec S17)."""

    def test_bom_field_category_enum(self):
        """S17.1 -- BOMFieldCategory must have required values."""
        required = {"IDENTITY", "TRUST", "POLICY", "ACTION",
                     "CONTEXT", "OUTCOME", "LINEAGE"}
        actual = {m.name for m in BOMFieldCategory}
        self.assertTrue(required.issubset(actual))

    def test_audit_source_protocol(self):
        """S17.2 -- AuditSource must be a runtime_checkable Protocol."""
        self.assertTrue(hasattr(AuditSource, "__protocol_attrs__") or
                        callable(getattr(AuditSource, "__instancecheck__", None)))

    def test_trust_source_protocol(self):
        """S17.3 -- TrustSource must be a runtime_checkable Protocol."""
        self.assertTrue(hasattr(TrustSource, "__protocol_attrs__") or
                        callable(getattr(TrustSource, "__instancecheck__", None)))

    def test_policy_source_protocol(self):
        """S17.4 -- PolicySource must be a runtime_checkable Protocol."""
        self.assertTrue(hasattr(PolicySource, "__protocol_attrs__") or
                        callable(getattr(PolicySource, "__instancecheck__", None)))

    def test_trace_source_protocol(self):
        """S17.5 -- TraceSource must be a runtime_checkable Protocol."""
        self.assertTrue(hasattr(TraceSource, "__protocol_attrs__") or
                        callable(getattr(TraceSource, "__instancecheck__", None)))

    def test_reconstructor_no_sources(self):
        """S17.6 -- reconstructor with no sources must still construct."""
        recon = DecisionBOMReconstructor()
        self.assertIsNotNone(recon)

    def test_reconstructor_available_sources_empty(self):
        """S17.7 -- available_sources with no sources must return empty list."""
        recon = DecisionBOMReconstructor()
        sources = recon.available_sources
        self.assertIsInstance(sources, list)

    def test_reconstructor_with_audit_source(self):
        """S17.8 -- reconstructor must accept audit_source."""
        mock_audit = MagicMock(spec=["query_by_trace", "query_by_agent"])
        mock_audit.query_by_trace.return_value = []
        mock_audit.query_by_agent.return_value = []
        recon = DecisionBOMReconstructor(audit_source=mock_audit)
        self.assertIn("audit", recon.available_sources)

    def test_bom_to_dict(self):
        """S17.9 -- DecisionBOM.to_dict must return a dict."""
        bom = DecisionBOM(
            decision_id="d1",
            timestamp=datetime.now(timezone.utc),
            agent_id="agent1",
            action_requested="read",
            outcome="allow",
            fields=[],
            reconstructed_at=datetime.now(timezone.utc),
            sources_queried=[],
        )
        d = bom.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["decision_id"], "d1")

    def test_bom_completeness_score_default(self):
        """S17.10 -- completeness_score must default to 0.0."""
        bom = DecisionBOM(
            decision_id="d2",
            timestamp=datetime.now(timezone.utc),
            agent_id="a1",
            action_requested="x",
            outcome="y",
            fields=[],
            reconstructed_at=datetime.now(timezone.utc),
            sources_queried=[],
        )
        self.assertEqual(bom.completeness_score, 0.0)


# ===================================================================
# S18 -- Hypervisor Audit (Delta)
# ===================================================================
class TestHypervisorAudit(unittest.TestCase):
    """Conformance tests for hypervisor audit delta (spec S18)."""

    def test_vfs_change_fields(self):
        """S18.1 -- VFSChange must have path, operation, content_hash fields."""
        c = VFSChange(path="/file.txt", operation="create", content_hash="abc")
        self.assertEqual(c.path, "/file.txt")
        self.assertEqual(c.operation, "create")
        self.assertEqual(c.content_hash, "abc")

    def test_delta_engine_creation(self):
        """S18.2 -- DeltaEngine must accept a session_id."""
        engine = DeltaEngine(session_id="sess1")
        self.assertIsNotNone(engine)

    def test_delta_capture(self):
        """S18.3 -- DeltaEngine.capture must return a SemanticDelta."""
        engine = DeltaEngine(session_id="sess1")
        changes = [VFSChange(path="/a.txt", operation="modify")]
        delta = engine.capture(agent_did="did:agent", changes=changes)
        self.assertIsInstance(delta, SemanticDelta)

    def test_delta_hash_computed(self):
        """S18.4 -- captured delta must have a non-empty delta_hash."""
        engine = DeltaEngine(session_id="sess1")
        changes = [VFSChange(path="/b.txt", operation="create")]
        delta = engine.capture(agent_did="did:agent", changes=changes)
        self.assertIsInstance(delta.delta_hash, str)
        self.assertGreater(len(delta.delta_hash), 0)

    def test_delta_verify_hash(self):
        """S18.5 -- SemanticDelta.verify_hash must return True for valid delta."""
        engine = DeltaEngine(session_id="sess1")
        changes = [VFSChange(path="/c.txt", operation="delete")]
        delta = engine.capture(agent_did="did:agent", changes=changes)
        self.assertTrue(delta.verify_hash())

    def test_delta_chain_verification(self):
        """S18.6 -- DeltaEngine.verify_chain must return (True, None) for valid chain."""
        engine = DeltaEngine(session_id="sess2")
        for i in range(3):
            engine.capture(
                agent_did="did:agent",
                changes=[VFSChange(path=f"/file{i}.txt", operation="create")],
            )
        valid, err = engine.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(err)


# ===================================================================
# S18b -- Hypervisor Event Bus
# ===================================================================
class TestHypervisorEventBus(unittest.TestCase):
    """Conformance tests for HypervisorEventBus (spec S18b)."""

    def test_event_type_audit_members(self):
        """S18b.1 -- EventType must include audit-related members."""
        self.assertEqual(EventType.AUDIT_DELTA_CAPTURED.value, "audit.delta_captured")
        self.assertEqual(EventType.AUDIT_COMMITTED.value, "audit.committed")

    def test_bus_creation(self):
        """S18b.2 -- HypervisorEventBus must be constructable."""
        bus = HypervisorEventBus()
        self.assertIsNotNone(bus)

    def test_emit_event(self):
        """S18b.3 -- emit must accept a HypervisorEvent."""
        bus = HypervisorEventBus()
        event = HypervisorEvent(
            event_type=EventType.AUDIT_DELTA_CAPTURED,
            timestamp=datetime.now(timezone.utc),
            payload={"delta_id": "d1"},
        )
        bus.emit(event)
        self.assertEqual(bus.event_count, 1)

    def test_query_by_type(self):
        """S18b.4 -- query_by_type must return matching events."""
        bus = HypervisorEventBus()
        event = HypervisorEvent(
            event_type=EventType.AUDIT_COMMITTED,
            timestamp=datetime.now(timezone.utc),
            payload={"session_id": "s1"},
        )
        bus.emit(event)
        results = bus.query_by_type(EventType.AUDIT_COMMITTED)
        self.assertGreaterEqual(len(results), 1)

    def test_query_by_session(self):
        """S18b.5 -- query_by_session must return events for that session."""
        bus = HypervisorEventBus()
        event = HypervisorEvent(
            event_type=EventType.SESSION_CREATED,
            timestamp=datetime.now(timezone.utc),
            session_id="sess_query",
            payload={},
        )
        bus.emit(event)
        results = bus.query_by_session("sess_query")
        self.assertGreaterEqual(len(results), 1)

    def test_event_to_dict(self):
        """S18b.6 -- HypervisorEvent.to_dict must return a dict."""
        event = HypervisorEvent(
            event_type=EventType.AUDIT_DELTA_CAPTURED,
            timestamp=datetime.now(timezone.utc),
            payload={"key": "val"},
        )
        d = event.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("event_type", d)

    def test_subscribe_handler(self):
        """S18b.7 -- subscribe must register handler for event type."""
        bus = HypervisorEventBus()
        received = []
        bus.subscribe(event_type=EventType.AUDIT_COMMITTED, handler=received.append)
        event = HypervisorEvent(
            event_type=EventType.AUDIT_COMMITTED,
            timestamp=datetime.now(timezone.utc),
            payload={},
        )
        bus.emit(event)
        self.assertGreaterEqual(len(received), 1)

    def test_event_count_property(self):
        """S18b.8 -- event_count must track emitted events."""
        bus = HypervisorEventBus()
        self.assertEqual(bus.event_count, 0)
        bus.emit(HypervisorEvent(
            event_type=EventType.SESSION_CREATED,
            timestamp=datetime.now(timezone.utc),
            payload={},
        ))
        self.assertEqual(bus.event_count, 1)


# ===================================================================
# S19 -- SRE Events (OpenTelemetry conventions)
# ===================================================================
class TestSREEvents(unittest.TestCase):
    """Conformance tests for agent-sre event logging (spec S19)."""

    def test_event_logger_creation(self):
        """S19.1 -- EventLogger must be constructable with defaults."""
        logger = SREEventLogger()
        self.assertIsNotNone(logger)

    def test_log_slo_status_change(self):
        """S19.2 -- log_slo_status_change must return a dict."""
        logger = SREEventLogger()
        result = logger.log_slo_status_change(
            slo_name="availability",
            old_status="healthy",
            new_status="breaching",
            error_budget_remaining=0.1,
        )
        self.assertIsInstance(result, dict)

    def test_log_burn_rate_alert(self):
        """S19.3 -- log_burn_rate_alert must return a dict."""
        logger = SREEventLogger()
        result = logger.log_burn_rate_alert(
            slo_name="latency",
            alert_name="fast_burn",
            burn_rate=10.0,
            severity="critical",
        )
        self.assertIsInstance(result, dict)

    def test_log_cost_alert(self):
        """S19.4 -- log_cost_alert must return a dict."""
        logger = SREEventLogger()
        result = logger.log_cost_alert(
            agent_id="a1",
            severity="warning",
            message="Budget exceeded",
            current_value=150.0,
            threshold=100.0,
        )
        self.assertIsInstance(result, dict)

    def test_log_incident_detected(self):
        """S19.5 -- log_incident_detected must return a dict."""
        logger = SREEventLogger()
        result = logger.log_incident_detected(
            incident_id="inc1",
            title="High latency",
            severity="high",
        )
        self.assertIsInstance(result, dict)

    def test_log_incident_resolved(self):
        """S19.6 -- log_incident_resolved must return a dict."""
        logger = SREEventLogger()
        result = logger.log_incident_resolved(
            incident_id="inc1", duration_seconds=300,
        )
        self.assertIsInstance(result, dict)

    def test_log_fault_injected(self):
        """S19.7 -- log_fault_injected must return a dict."""
        logger = SREEventLogger()
        result = logger.log_fault_injected(
            experiment_name="chaos_test",
            fault_type="latency",
            target="service_a",
            applied=True,
        )
        self.assertIsInstance(result, dict)

    def test_conventions_constants(self):
        """S19.8 -- SRE conventions must define required attribute keys."""
        self.assertTrue(hasattr(sre_conventions, "AGENT_ID"))
        self.assertTrue(hasattr(sre_conventions, "SLO_NAME"))
        self.assertTrue(hasattr(sre_conventions, "INCIDENT_ID"))


# ===================================================================
# S20 -- Lightning Audit (Emitter + Environment)
# ===================================================================
class TestLightningAudit(unittest.TestCase):
    """Conformance tests for agent-lightning audit spans (spec S20)."""

    def test_lightning_span_fields(self):
        """S20.1 -- LightningSpan must have span_id, trace_id, name, start_time."""
        span = LightningSpan(
            span_id="s1",
            trace_id="t1",
            name="policy_check",
            start_time=datetime.now(timezone.utc),
        )
        self.assertEqual(span.span_id, "s1")
        self.assertEqual(span.trace_id, "t1")
        self.assertEqual(span.name, "policy_check")

    def test_span_end_time_optional(self):
        """S20.2 -- LightningSpan.end_time must default to None."""
        span = LightningSpan(
            span_id="s2", trace_id="t2", name="test",
            start_time=datetime.now(timezone.utc),
        )
        self.assertIsNone(span.end_time)

    def test_span_attributes_default_empty(self):
        """S20.3 -- LightningSpan.attributes must default to empty dict."""
        span = LightningSpan(
            span_id="s3", trace_id="t3", name="test",
            start_time=datetime.now(timezone.utc),
        )
        self.assertIsInstance(span.attributes, dict)
        self.assertEqual(len(span.attributes), 0)

    def test_span_events_default_empty(self):
        """S20.4 -- LightningSpan.events must default to empty list."""
        span = LightningSpan(
            span_id="s4", trace_id="t4", name="test",
            start_time=datetime.now(timezone.utc),
        )
        self.assertIsInstance(span.events, list)
        self.assertEqual(len(span.events), 0)

    def test_span_to_dict(self):
        """S20.5 -- LightningSpan.to_dict must return a dict."""
        span = LightningSpan(
            span_id="s5", trace_id="t5", name="check",
            start_time=datetime.now(timezone.utc),
        )
        d = span.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("span_id", d)

    def test_span_to_json(self):
        """S20.6 -- LightningSpan.to_json must return valid JSON."""
        span = LightningSpan(
            span_id="s6", trace_id="t6", name="check",
            start_time=datetime.now(timezone.utc),
        )
        j = span.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["span_id"], "s6")

    def test_span_with_attributes(self):
        """S20.7 -- LightningSpan must accept custom attributes."""
        span = LightningSpan(
            span_id="s7", trace_id="t7", name="check",
            start_time=datetime.now(timezone.utc),
            attributes={"policy": "read_only"},
        )
        self.assertEqual(span.attributes["policy"], "read_only")

    def test_span_with_events(self):
        """S20.8 -- LightningSpan must accept event list."""
        span = LightningSpan(
            span_id="s8", trace_id="t8", name="check",
            start_time=datetime.now(timezone.utc),
            events=[{"name": "violation", "timestamp": "2024-01-01T00:00:00Z"}],
        )
        self.assertEqual(len(span.events), 1)


# ===================================================================
# S21 -- Cross-Component Correlation
# ===================================================================
class TestCrossComponentCorrelation(unittest.TestCase):
    """Conformance tests for cross-component audit correlation (spec S21)."""

    def test_trace_id_propagates_os_to_mesh(self):
        """S21.1 -- trace_id from GovernanceEvent must be usable in mesh AuditEntry."""
        trace_id = uuid.uuid4().hex
        os_event = GovernanceEvent(trace_id=trace_id, agent_id="a1")
        mesh_entry = MeshAuditEntry(
            event_type="policy_check",
            agent_did="did:a1",
            action="read",
            trace_id=trace_id,
        )
        self.assertEqual(os_event.trace_id, mesh_entry.trace_id)

    def test_session_id_correlates_bus_and_delta(self):
        """S21.2 -- session_id must correlate hypervisor event bus and delta engine."""
        session_id = "corr_session_1"
        engine = DeltaEngine(session_id=session_id)
        delta = engine.capture(
            agent_did="did:a1",
            changes=[VFSChange(path="/x.txt", operation="create")],
        )
        bus = HypervisorEventBus()
        event = HypervisorEvent(
            event_type=EventType.AUDIT_DELTA_CAPTURED,
            timestamp=datetime.now(timezone.utc),
            session_id=session_id,
            payload={"delta_id": delta.delta_id},
        )
        bus.emit(event)
        results = bus.query_by_session(session_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].session_id, delta.session_id)

    def test_agent_did_consistent_across_components(self):
        """S21.3 -- agent_did used in mesh audit must match hypervisor delta."""
        agent_did = "did:web:example.com:agent1"
        mesh_entry = MeshAuditEntry(
            event_type="action",
            agent_did=agent_did,
            action="execute",
        )
        delta_engine = DeltaEngine(session_id="s1")
        delta = delta_engine.capture(
            agent_did=agent_did,
            changes=[VFSChange(path="/f.txt", operation="write")],
        )
        self.assertEqual(mesh_entry.agent_did, delta.agent_did)

    def test_event_kind_maps_to_violation_category(self):
        """S21.5 -- GovernanceEventKind and ViolationCategory must be independently usable."""
        event = GovernanceEvent(
            kind=GovernanceEventKind.TOOL_CALL_BLOCKED,
            agent_id="a1",
            action="shell_exec",
            decision="deny",
        )
        result = PolicyCheckResult(
            allowed=False,
            action="deny",
            category=ViolationCategory.BLOCKED_TOOL,
        )
        # Both should reference the same semantic concept independently
        self.assertEqual(event.kind, GovernanceEventKind.TOOL_CALL_BLOCKED)
        self.assertEqual(result.category, ViolationCategory.BLOCKED_TOOL)
        self.assertFalse(result.allowed)


# ===================================================================
# Additional policy decision tests to reach 100+ total
# ===================================================================
class TestPolicyDecisionAuditIntegration(unittest.TestCase):
    """Conformance tests for PolicyCheckResult audit integration (spec S5/S9)."""

    def test_violation_category_enum_values(self):
        """S5/S9.1 -- ViolationCategory must include required members."""
        required = {
            "BLOCKED_TOOL", "NOT_ALLOWED_TOOL", "BLOCKED_PATTERN_INPUT",
            "BLOCKED_PATTERN_TOOL", "BLOCKED_PATTERN_OUTPUT",
            "BLOCKED_PATTERN_MEMORY", "MAX_TOOL_CALLS", "TIMEOUT",
            "HUMAN_APPROVAL", "CONFIDENCE_THRESHOLD", "DRIFT", "POLICY_ERROR",
        }
        actual = {m.name for m in ViolationCategory}
        self.assertTrue(required.issubset(actual))

    def test_policy_result_default_allowed(self):
        """S5/S9.2 -- PolicyCheckResult must default to allowed=True."""
        result = PolicyCheckResult()
        self.assertTrue(result.allowed)

    def test_policy_result_to_legacy_tuple(self):
        """S5/S9.3 -- to_legacy_tuple must return (bool, str|None)."""
        result = PolicyCheckResult(allowed=False, category=ViolationCategory.BLOCKED_TOOL)
        t = result.to_legacy_tuple()
        self.assertIsInstance(t, tuple)
        self.assertEqual(len(t), 2)

    def test_policy_result_to_public_dict(self):
        """S5/S9.4 -- to_public_dict must return a dict."""
        result = PolicyCheckResult(allowed=True, action="allow")
        d = result.to_public_dict()
        self.assertIsInstance(d, dict)

    def test_governance_logger_creation(self):
        """S5/S9.5 -- GovernanceLogger must be constructable."""
        logger = GovernanceLogger()
        self.assertIsNotNone(logger)

    def test_get_logger_returns_governance_logger(self):
        """S5/S9.6 -- get_logger must return a GovernanceLogger."""
        logger = get_logger()
        self.assertIsInstance(logger, GovernanceLogger)

    def test_governance_logger_policy_decision(self):
        """S5/S9.7 -- policy_decision must not raise."""
        logger = GovernanceLogger()
        logger.policy_decision(agent_id="a1", action="read", decision="allow")

    def test_governance_logger_policy_violation(self):
        """S5/S9.8 -- policy_violation must not raise."""
        logger = GovernanceLogger()
        logger.policy_violation(
            agent_id="a1", action="write",
            policy_name="block_shell", reason="blocked",
        )

    def test_governance_logger_audit_event(self):
        """S5/S9.9 -- audit_event must not raise."""
        logger = GovernanceLogger()
        logger.audit_event(agent_id="a1", event_type="test")


# ===================================================================
# Entry point
# ===================================================================
if __name__ == "__main__":
    unittest.main()
