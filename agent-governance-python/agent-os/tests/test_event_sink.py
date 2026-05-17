# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for :mod:`agent_os.event_sink`.

Covers:
* SignedGovernanceEvent.build() creates correct CloudEvents fields
* HMAC-SHA256 signature is computed and verified correctly
* Unsigned events have empty signature
* verify_signature() returns False for wrong key
* GovernanceEventCategory produces correct cloud_event_type strings
* StdoutEventSink emits without error
* OtlpEventSink is a safe no-op without opentelemetry
* OtlpEventSink emits when opentelemetry is available
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac_test
import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from agent_os.event_sink import (
    GovernanceEventCategory,
    GovernanceEventSink,
    OtlpEventSink,
    SignedGovernanceEvent,
    StdoutEventSink,
)


def _make_sign_fn(key: bytes):
    """Return a sign_fn closure for use in tests."""
    def sign(canonical: str) -> str:
        return _hmac_test.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return sign


def _make_verify_fn(key: bytes):
    """Return a verify_fn closure for use in tests."""
    def verify(canonical: str, signature: str) -> bool:
        expected = _hmac_test.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return _hmac_test.compare_digest(signature, expected)
    return verify

# Detect whether the OTel SDK Logs API is available
try:
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor

    try:
        from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter as _Exporter
    except ImportError:
        from opentelemetry.sdk._logs.export import InMemoryLogExporter as _Exporter

    _HAS_OTEL_LOGS_SDK = True
except ImportError:
    _HAS_OTEL_LOGS_SDK = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run a coroutine synchronously for tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# GovernanceEventCategory
# ---------------------------------------------------------------------------


class TestGovernanceEventCategory:
    def test_cloud_event_type_policy_decision(self):
        assert (
            GovernanceEventCategory.POLICY_DECISION.cloud_event_type()
            == "ai.agentmesh.policy.decision"
        )

    def test_cloud_event_type_policy_breach(self):
        assert (
            GovernanceEventCategory.POLICY_BREACH.cloud_event_type()
            == "ai.agentmesh.policy.breach"
        )

    def test_cloud_event_type_identity_assertion(self):
        assert (
            GovernanceEventCategory.IDENTITY_ASSERTION.cloud_event_type()
            == "ai.agentmesh.identity.assertion"
        )

    def test_cloud_event_type_tool_invocation(self):
        assert (
            GovernanceEventCategory.TOOL_INVOCATION.cloud_event_type()
            == "ai.agentmesh.tool.invocation"
        )

    def test_cloud_event_type_sandbox_event(self):
        assert (
            GovernanceEventCategory.SANDBOX_EVENT.cloud_event_type()
            == "ai.agentmesh.sandbox.event"
        )

    def test_cloud_event_type_audit_chain(self):
        assert (
            GovernanceEventCategory.AUDIT_CHAIN.cloud_event_type()
            == "ai.agentmesh.audit.chain"
        )

    def test_all_types_are_distinct(self):
        types = [c.cloud_event_type() for c in GovernanceEventCategory]
        assert len(types) == len(set(types))


# ---------------------------------------------------------------------------
# SignedGovernanceEvent.build()
# ---------------------------------------------------------------------------


class TestSignedGovernanceEventBuild:
    def test_specversion_is_1_0(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:agent-1",
        )
        assert evt.specversion == "1.0"

    def test_type_matches_category(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_BREACH,
            source="did:agentmesh:agent-1",
        )
        assert evt.type == "ai.agentmesh.policy.breach"

    def test_source_is_set(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.TOOL_INVOCATION,
            source="did:agentmesh:agent-42",
        )
        assert evt.source == "did:agentmesh:agent-42"

    def test_subject_is_set(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.TOOL_INVOCATION,
            source="did:agentmesh:a",
            subject="tool:file_write",
        )
        assert evt.subject == "tool:file_write"

    def test_data_is_set(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:a",
            data={"decision": "deny", "reason": "blocked"},
        )
        assert evt.data["decision"] == "deny"
        assert evt.data["reason"] == "blocked"

    def test_id_is_uuid(self):
        import uuid
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.AUDIT_CHAIN, source="did:agentmesh:a"
        )
        # Should be a valid UUID string
        uuid.UUID(evt.id)

    def test_time_is_iso8601(self):
        from datetime import datetime, timezone
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.AUDIT_CHAIN, source="did:agentmesh:a"
        )
        # Should parse as a datetime
        dt = datetime.fromisoformat(evt.time)
        assert dt.tzinfo is not None

    def test_datacontenttype(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
        )
        assert evt.datacontenttype == "application/json"

    def test_unsigned_has_empty_signature(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
        )
        assert evt.signature == ""

    def test_signed_has_hex_signature(self):
        key = b"test-signing-key-for-hmac-sha256"
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:a",
            sign_fn=_make_sign_fn(key),
        )
        assert len(evt.signature) == 64
        assert all(c in "0123456789abcdef" for c in evt.signature)

    def test_different_events_have_different_ids(self):
        evt1 = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
        )
        evt2 = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
        )
        assert evt1.id != evt2.id


# ---------------------------------------------------------------------------
# SignedGovernanceEvent.verify_signature()
# ---------------------------------------------------------------------------


class TestSignedGovernanceEventVerify:
    def test_verify_valid_signature(self):
        key = b"test-key-12345678901234567890123"
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.TOOL_INVOCATION,
            source="did:agentmesh:agent-1",
            subject="tool:web_search",
            data={"query": "test"},
            sign_fn=_make_sign_fn(key),
        )
        assert evt.verify_signature(_make_verify_fn(key)) is True

    def test_verify_wrong_key_returns_false(self):
        key = b"correct-key-1234567890123456789"
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.TOOL_INVOCATION,
            source="did:agentmesh:agent-1",
            sign_fn=_make_sign_fn(key),
        )
        wrong = b"wrong-key-bad-key-abcdefghijk123"
        assert evt.verify_signature(_make_verify_fn(wrong)) is False

    def test_verify_unsigned_returns_false(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.AUDIT_CHAIN, source="did:agentmesh:a"
        )
        assert evt.verify_signature(_make_verify_fn(b"any-key")) is False


# ---------------------------------------------------------------------------
# SignedGovernanceEvent serialisation
# ---------------------------------------------------------------------------


class TestSignedGovernanceEventSerialization:
    def test_to_json_is_valid_json(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
        )
        parsed = json.loads(evt.to_json())
        assert parsed["specversion"] == "1.0"
        assert parsed["type"] == "ai.agentmesh.policy.decision"

    def test_to_dict_contains_all_fields(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
        )
        d = evt.to_dict()
        for field in ("specversion", "id", "type", "source", "time",
                      "datacontenttype", "subject", "data", "signature"):
            assert field in d


# ---------------------------------------------------------------------------
# StdoutEventSink
# ---------------------------------------------------------------------------


class TestStdoutEventSink:
    def test_emit_writes_json_to_stdout(self, capsys):
        sink = StdoutEventSink()
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:agent-1",
            subject="tool:file_write",
            data={"decision": "deny"},
        )
        _run(sink.emit(evt))
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["type"] == "ai.agentmesh.policy.decision"
        assert parsed["source"] == "did:agentmesh:agent-1"

    def test_emit_multiple_events(self, capsys):
        sink = StdoutEventSink()
        for _ in range(3):
            evt = SignedGovernanceEvent.build(
                GovernanceEventCategory.AUDIT_CHAIN, source="did:agentmesh:a"
            )
            _run(sink.emit(evt))
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().splitlines() if l]
        assert len(lines) == 3

    def test_stdout_sink_is_a_governance_event_sink(self):
        # Protocol check: StdoutEventSink satisfies GovernanceEventSink
        sink = StdoutEventSink()
        assert hasattr(sink, "emit")
        assert callable(sink.emit)


# ---------------------------------------------------------------------------
# OtlpEventSink — graceful degradation
# ---------------------------------------------------------------------------


class TestOtlpEventSinkGracefulDegradation:
    def test_emit_without_otel_is_noop(self):
        with patch("agent_os.event_sink._HAS_OTEL_LOGS", False):
            sink = OtlpEventSink.__new__(OtlpEventSink)
            sink._enabled = False
            sink._otel_logger = None
            sink._service_name = "test"
            evt = SignedGovernanceEvent.build(
                GovernanceEventCategory.POLICY_DECISION, source="did:agentmesh:a"
            )
            # Must not raise
            _run(sink.emit(evt))

    def test_enabled_false_without_otel(self):
        with patch("agent_os.event_sink._HAS_OTEL_LOGS", False):
            sink = OtlpEventSink.__new__(OtlpEventSink)
            sink._enabled = False
            sink._otel_logger = None
            assert sink.enabled is False


# ---------------------------------------------------------------------------
# OtlpEventSink — with OTel SDK
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_OTEL_LOGS_SDK, reason="opentelemetry Logs SDK not installed")
class TestOtlpEventSinkWithOtel:
    @pytest.fixture(autouse=True)
    def setup(self):
        exporter = _Exporter()
        provider = LoggerProvider()
        provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
        self.exporter = exporter
        self.sink = OtlpEventSink(logger_provider=provider)

    def test_enabled_is_true(self):
        assert self.sink.enabled is True

    def test_emit_creates_log_record(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:agent-1",
            subject="tool:file_write",
            data={"decision": "deny"},
        )
        _run(self.sink.emit(evt))
        records = self.exporter.get_finished_logs()
        assert len(records) == 1

    def test_log_record_attributes(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.TOOL_INVOCATION,
            source="did:agentmesh:agent-1",
            subject="tool:web_search",
        )
        _run(self.sink.emit(evt))
        records = self.exporter.get_finished_logs()
        attrs = dict(records[0].log_record.attributes)
        assert attrs["event.domain"] == "agent_os.governance"
        assert attrs["agt.governance.event.source"] == "did:agentmesh:agent-1"
        assert attrs["agt.governance.event.subject"] == "tool:web_search"
        assert attrs["agt.governance.event.signed"] is False

    def test_signed_event_attribute_is_true(self):
        key = b"test-signing-key-32-bytes-123456"
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.POLICY_DECISION,
            source="did:agentmesh:a",
            sign_fn=_make_sign_fn(key),
        )
        _run(self.sink.emit(evt))
        records = self.exporter.get_finished_logs()
        attrs = dict(records[0].log_record.attributes)
        assert attrs["agt.governance.event.signed"] is True

    def test_body_is_json(self):
        evt = SignedGovernanceEvent.build(
            GovernanceEventCategory.AUDIT_CHAIN,
            source="did:agentmesh:a",
            data={"seq": 42},
        )
        _run(self.sink.emit(evt))
        records = self.exporter.get_finished_logs()
        body = json.loads(records[0].log_record.body)
        assert body["type"] == "ai.agentmesh.audit.chain"
        assert body["data"]["seq"] == 42

    def test_multiple_emits(self):
        for cat in GovernanceEventCategory:
            evt = SignedGovernanceEvent.build(cat, source="did:agentmesh:a")
            _run(self.sink.emit(evt))
        records = self.exporter.get_finished_logs()
        assert len(records) == len(list(GovernanceEventCategory))
