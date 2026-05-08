# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for :class:`OTelLogsBackend`.

Covers:
* LogRecord emission with correct attributes
* AuditEntry metadata promotion to top-level attributes
* Graceful no-op when ``opentelemetry`` is not installed
* Integration with :class:`GovernanceAuditLogger`
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from agent_os.audit_logger import AuditEntry, GovernanceAuditLogger

# Detect whether the OTel SDK Logs API is available
try:
    from opentelemetry._logs import SeverityNumber
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor

    # InMemoryLogExporter was renamed to InMemoryLogRecordExporter;
    # try the new name first, fall back to the old one.
    try:
        from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter as _Exporter
    except ImportError:
        from opentelemetry.sdk._logs.export import InMemoryLogExporter as _Exporter

    _HAS_OTEL_LOGS_SDK = True
except ImportError:
    _HAS_OTEL_LOGS_SDK = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_provider():
    """Create an in-memory LoggerProvider for testing."""
    exporter = _Exporter()
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    return provider, exporter


# ---------------------------------------------------------------------------
# Tests — OTel available
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_OTEL_LOGS_SDK, reason="opentelemetry Logs SDK not installed")
class TestOTelLogsBackend:
    """Verify LogRecord emission when OTel SDK is available."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.provider, self.exporter = _make_provider()

        from agent_os.otel_audit_backend import OTelLogsBackend

        self.backend = OTelLogsBackend(logger_provider=self.provider)
        yield

    def test_enabled_is_true(self):
        assert self.backend.enabled is True

    def test_write_emits_log_record(self):
        entry = AuditEntry(
            event_type="governance_decision",
            agent_id="agent-1",
            action="web_search",
            decision="allow",
            reason="policy matched",
            latency_ms=12.5,
        )
        self.backend.write(entry)

        records = self.exporter.get_finished_logs()
        assert len(records) == 1

        rec = records[0]
        attrs = dict(rec.log_record.attributes)
        assert attrs["agt.agent.id"] == "agent-1"
        assert attrs["agt.audit.event_type"] == "governance_decision"
        assert attrs["agt.audit.action"] == "web_search"
        assert attrs["agt.audit.decision"] == "allow"
        assert attrs["agt.audit.reason"] == "policy matched"
        assert attrs["agt.audit.latency_ms"] == 12.5
        assert attrs["event.domain"] == "agent_os.governance"
        assert attrs["event.name"] == "audit_entry"

    def test_body_is_json(self):
        entry = AuditEntry(
            event_type="governance_decision",
            agent_id="a1",
            action="search",
            decision="deny",
        )
        self.backend.write(entry)

        records = self.exporter.get_finished_logs()
        body = records[0].log_record.body
        parsed = json.loads(body)
        assert parsed["agent_id"] == "a1"
        assert parsed["decision"] == "deny"

    def test_severity_is_info(self):
        entry = AuditEntry(event_type="test", agent_id="a1")
        self.backend.write(entry)

        records = self.exporter.get_finished_logs()
        rec = records[0].log_record
        assert rec.severity_text == "INFO"
        assert rec.severity_number == SeverityNumber.INFO

    def test_metadata_promoted_to_attributes(self):
        entry = AuditEntry(
            event_type="governance_decision",
            agent_id="agent-1",
            action="search",
            decision="allow",
            metadata={"tool_name": "web_search", "risk_score": "0.3"},
        )
        self.backend.write(entry)

        records = self.exporter.get_finished_logs()
        attrs = dict(records[0].log_record.attributes)
        assert attrs["agt.audit.meta.tool_name"] == "web_search"
        assert attrs["agt.audit.meta.risk_score"] == "0.3"

    def test_empty_reason_omitted(self):
        entry = AuditEntry(
            event_type="test",
            agent_id="a1",
            action="x",
            decision="allow",
            reason="",
        )
        self.backend.write(entry)

        records = self.exporter.get_finished_logs()
        attrs = dict(records[0].log_record.attributes)
        assert "agt.audit.reason" not in attrs

    def test_flush_is_noop(self):
        # Should not raise
        self.backend.flush()

    def test_integration_with_governance_audit_logger(self):
        """OTelLogsBackend plugs into GovernanceAuditLogger."""
        audit = GovernanceAuditLogger()
        audit.add_backend(self.backend)
        audit.log_decision(
            agent_id="agent-1",
            action="web_search",
            decision="deny",
            reason="rate limited",
            latency_ms=5.0,
        )
        audit.flush()

        records = self.exporter.get_finished_logs()
        assert len(records) == 1
        attrs = dict(records[0].log_record.attributes)
        assert attrs["agt.audit.decision"] == "deny"

    def test_multiple_entries_all_emitted(self):
        for i in range(5):
            entry = AuditEntry(event_type="test", agent_id=f"a{i}")
            self.backend.write(entry)

        records = self.exporter.get_finished_logs()
        assert len(records) == 5


# ---------------------------------------------------------------------------
# Tests — graceful degradation
# ---------------------------------------------------------------------------


class TestOTelLogsBackendGracefulDegradation:
    """Backend must be a safe no-op without opentelemetry."""

    def test_write_without_otel_is_noop(self):
        # Patch the module-level flag to simulate missing OTel
        with patch("agent_os.otel_audit_backend._HAS_OTEL_LOGS", False):
            from agent_os.otel_audit_backend import OTelLogsBackend

            backend = OTelLogsBackend.__new__(OTelLogsBackend)
            backend._enabled = False
            backend._otel_logger = None
            backend._service_name = "test"

            entry = AuditEntry(event_type="test", agent_id="a1")
            # Should not raise
            backend.write(entry)
            backend.flush()

    def test_enabled_false_without_otel(self):
        with patch("agent_os.otel_audit_backend._HAS_OTEL_LOGS", False):
            from agent_os.otel_audit_backend import OTelLogsBackend

            backend = OTelLogsBackend.__new__(OTelLogsBackend)
            backend._enabled = False
            backend._otel_logger = None
            assert backend.enabled is False
