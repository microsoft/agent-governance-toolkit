# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for OCSF schema conversion and OCSFGovernanceSink."""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest

from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventProcessor,
    SinkExportResult,
)
from agent_os.ocsf import (
    OCSF_CLASS_API_ACTIVITY,
    OCSF_CLASS_AUTHORIZE_SESSION,
    OCSF_CLASS_SECURITY_FINDING,
    OCSF_DISPOSITION_ALLOWED,
    OCSF_DISPOSITION_BLOCKED,
    OCSF_SCHEMA_VERSION,
    OCSF_SEVERITY_CRITICAL,
    OCSF_SEVERITY_INFORMATIONAL,
    OCSF_STATUS_FAILURE,
    OCSF_STATUS_SUCCESS,
    OCSFGovernanceSink,
    cloudevent_to_ocsf,
    governance_event_to_ocsf,
)


class TestCloudEventToOCSF:
    """Tests for converting CloudEvents 1.0 envelopes to OCSF schema."""

    def test_security_finding_policy_violation(self):
        ce = {
            "specversion": "1.0",
            "id": "evt-violation-123",
            "type": "ai.agentos.policy.violation",
            "source": "/agent-os/agent/bot-1",
            "time": "2026-03-15T12:00:00Z",
            "traceid": "trace-abc-999",
            "spanid": "span-111",
            "parentspanid": "span-000",
            "sessionid": "session-xyz",
            "data": {
                "action": "execute_shell",
                "decision": "deny",
                "reason": "Execution of destructive command forbidden",
                "severity": "critical",
                "policy_name": "no-destructive-commands",
                "agent_id": "bot-1",
                "agent_did": "did:mesh:bot-1",
                "resource": "rm -rf /",
            },
        }

        ocsf = cloudevent_to_ocsf(ce)

        assert ocsf["class_uid"] == OCSF_CLASS_SECURITY_FINDING
        assert ocsf["class_name"] == "Security Finding"
        assert ocsf["category_uid"] == 2
        assert ocsf["category_name"] == "Findings"
        assert ocsf["activity_id"] == 1
        assert ocsf["type_uid"] == 200101
        assert ocsf["disposition_id"] == OCSF_DISPOSITION_BLOCKED
        assert ocsf["disposition"] == "Blocked"
        assert ocsf["status_id"] == OCSF_STATUS_FAILURE
        assert ocsf["status"] == "Failure"
        assert ocsf["severity_id"] == OCSF_SEVERITY_CRITICAL
        assert ocsf["severity"] == "Critical"

        # Trace correlation
        assert ocsf["metadata"]["correlation_uid"] == "trace-abc-999"
        assert ocsf["metadata"]["version"] == OCSF_SCHEMA_VERSION
        assert ocsf["observability"]["trace_id"] == "trace-abc-999"
        assert ocsf["observability"]["span_id"] == "span-111"
        assert ocsf["observability"]["parent_span_id"] == "span-000"
        assert ocsf["observability"]["session_id"] == "session-xyz"

        # Finding details
        assert ocsf["finding_info"]["uid"] == "evt-violation-123"
        assert "no-destructive-commands" in ocsf["finding_info"]["title"]
        assert ocsf["policy"]["name"] == "no-destructive-commands"
        assert ocsf["actor"]["user"]["name"] == "bot-1"
        assert ocsf["actor"]["id"] == "did:mesh:bot-1"

    def test_api_activity_policy_check_allowed(self):
        ce = {
            "specversion": "1.0",
            "id": "evt-check-456",
            "type": "ai.agentos.policy.check",
            "source": "/agent-os/agent/bot-2",
            "time": "2026-03-15T12:05:00Z",
            "traceid": "trace-def-888",
            "data": {
                "action": "query_database",
                "decision": "allow",
                "reason": "Access granted by read-only policy",
                "severity": "info",
                "policy_name": "read-only-access",
                "agent_id": "bot-2",
                "resource": "SELECT * FROM users",
            },
        }

        ocsf = cloudevent_to_ocsf(ce)

        assert ocsf["class_uid"] == OCSF_CLASS_API_ACTIVITY
        assert ocsf["class_name"] == "API Activity"
        assert ocsf["category_uid"] == 6
        assert ocsf["category_name"] == "Application Activity"
        assert ocsf["activity_id"] == 99
        assert ocsf["disposition_id"] == OCSF_DISPOSITION_ALLOWED
        assert ocsf["disposition"] == "Allowed"
        assert ocsf["status_id"] == OCSF_STATUS_SUCCESS
        assert ocsf["status"] == "Success"
        assert ocsf["severity_id"] == OCSF_SEVERITY_INFORMATIONAL
        assert ocsf["severity"] == "Informational"

        # API & Trace details
        assert ocsf["api"]["operation"] == "query_database"
        assert ocsf["api"]["service"]["name"] == "agent-os"
        assert ocsf["api"]["request"]["data"] == "SELECT * FROM users"
        assert ocsf["policy"]["name"] == "read-only-access"
        assert ocsf["metadata"]["correlation_uid"] == "trace-def-888"
        assert ocsf["observability"]["trace_id"] == "trace-def-888"

    def test_authorize_session_identity_verified(self):
        ce = {
            "specversion": "1.0",
            "id": "evt-auth-789",
            "type": "ai.agentos.identity.verified",
            "source": "did:mesh:agent-requester",
            "time": "2026-03-15T12:10:00Z",
            "sessionid": "sess-cluster-1",
            "data": {
                "action": "verify_identity",
                "decision": "allow",
                "agent_id": "agent-requester",
                "agent_did": "did:mesh:agent-requester",
                "kind": "identity_verified",
            },
        }

        ocsf = cloudevent_to_ocsf(ce)

        assert ocsf["class_uid"] == OCSF_CLASS_AUTHORIZE_SESSION
        assert ocsf["class_name"] == "Authorize Session"
        assert ocsf["category_uid"] == 3
        assert ocsf["category_name"] == "Identity & Access Management"
        assert ocsf["activity_id"] == 1
        assert ocsf["session"]["uid"] == "sess-cluster-1"
        assert ocsf["disposition_id"] == OCSF_DISPOSITION_ALLOWED

    def test_agentmesh_cloudevent_compatibility(self):
        """Verify CloudEvents formatted per AgentMesh spec convert correctly."""
        ce = {
            "specversion": "1.0",
            "id": "mesh-evt-100",
            "type": "ai.agentmesh.policy.violation",
            "source": "did:mesh:agent-mesh-1",
            "time": "2026-03-15T12:15:00.000Z",
            "subject": "tool:filesystem:read",
            "agentmeshentryhash": "sha256:abc123hash",
            "data": {
                "trace_id": "mesh-trace-123",
                "agent_id": "agent-mesh-1",
                "tool_name": "filesystem:read",
                "violation_reason": "Path traversal attempt",
                "severity": "critical",
                "custom_metric": 42,
            },
        }

        ocsf = cloudevent_to_ocsf(ce)

        assert ocsf["class_uid"] == OCSF_CLASS_SECURITY_FINDING
        assert ocsf["metadata"]["correlation_uid"] == "mesh-trace-123"
        assert ocsf["observability"]["trace_id"] == "mesh-trace-123"
        assert ocsf["status_detail"] == "Path traversal attempt"
        assert ocsf["unmapped"]["agentmeshentryhash"] == "sha256:abc123hash"
        assert ocsf["unmapped"]["custom_metric"] == 42


class TestGovernanceEventToOCSF:
    """Tests for direct GovernanceEvent conversion and .to_ocsf() method."""

    def test_direct_governance_event_to_ocsf(self):
        event = GovernanceEvent(
            agent_id="service-agent-4",
            agent_did="did:mesh:service-agent-4",
            action="read_file",
            resource="/etc/passwd",
            decision="deny",
            reason="Sensitive file access prohibited",
            policy_name="system-integrity",
            kind=GovernanceEventKind.TOOL_CALL_BLOCKED,
            severity="high",
            trace_id="trace-sec-555",
            span_id="span-sec-666",
            session_id="session-sec-777",
            attributes={"client_ip": "10.0.0.1"},
        )

        ocsf = governance_event_to_ocsf(event)

        assert ocsf["class_uid"] == OCSF_CLASS_SECURITY_FINDING
        assert ocsf["disposition"] == "Blocked"
        assert ocsf["observability"]["trace_id"] == "trace-sec-555"
        assert ocsf["observability"]["span_id"] == "span-sec-666"
        assert ocsf["observability"]["session_id"] == "session-sec-777"
        assert ocsf["unmapped"]["client_ip"] == "10.0.0.1"

    def test_governance_event_method_to_ocsf(self):
        event = GovernanceEvent(
            agent_id="calc-agent",
            action="compute",
            decision="allow",
            kind=GovernanceEventKind.POLICY_CHECK,
            trace_id="tr-01",
        )

        ocsf = event.to_ocsf(source="/agent-os/calc")

        assert ocsf["class_uid"] == OCSF_CLASS_API_ACTIVITY
        assert ocsf["api"]["operation"] == "compute"
        assert ocsf["observability"]["trace_id"] == "tr-01"


class TestOCSFGovernanceSink:
    """Tests for OCSFGovernanceSink NDJSON emission and processor integration."""

    def test_emit_writes_ndjson_to_stream(self):
        stream = io.StringIO()
        sink = OCSFGovernanceSink(source="/agent-os/test", stream=stream)

        events = [
            GovernanceEvent(
                agent_id="agent-a",
                action="action-1",
                decision="allow",
                trace_id="trace-1",
                kind=GovernanceEventKind.POLICY_CHECK,
            ),
            GovernanceEvent(
                agent_id="agent-b",
                action="action-2",
                decision="deny",
                reason="Denied by policy",
                trace_id="trace-2",
                kind=GovernanceEventKind.POLICY_VIOLATION,
            ),
        ]

        result = sink.emit(events)
        assert result == SinkExportResult.SUCCESS

        lines = stream.getvalue().strip().split("\n")
        assert len(lines) == 2

        record1 = json.loads(lines[0])
        record2 = json.loads(lines[1])

        assert record1["class_uid"] == OCSF_CLASS_API_ACTIVITY
        assert record1["observability"]["trace_id"] == "trace-1"

        assert record2["class_uid"] == OCSF_CLASS_SECURITY_FINDING
        assert record2["observability"]["trace_id"] == "trace-2"
        assert record2["disposition"] == "Blocked"

    def test_processor_fan_out_with_ocsf_sink(self):
        stream = io.StringIO()
        sink = OCSFGovernanceSink(source="/agent-os", stream=stream)

        processor = GovernanceEventProcessor(schedule_delay_ms=50)
        processor.add_sink(sink)

        event = GovernanceEvent(
            agent_id="fanout-agent",
            action="execute_tool",
            decision="allow",
            trace_id="trace-fanout-123",
            kind=GovernanceEventKind.POLICY_CHECK,
        )

        processor.on_event(event)
        processor.shutdown(timeout_ms=3000)

        lines = stream.getvalue().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["class_uid"] == OCSF_CLASS_API_ACTIVITY
        assert record["observability"]["trace_id"] == "trace-fanout-123"

