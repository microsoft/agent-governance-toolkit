# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for OCSF schema conversion and OCSFGovernanceSink."""

from __future__ import annotations

import io
import json

from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventProcessor,
    SinkExportResult,
)
from agent_os.ocsf import (
    OCSF_CLASS_API_ACTIVITY,
    OCSF_CLASS_AUTHORIZE_SESSION,
    OCSF_CLASS_DETECTION_FINDING,
    OCSF_DISPOSITION_ALLOWED,
    OCSF_DISPOSITION_BLOCKED,
    OCSF_SCHEMA_VERSION,
    OCSF_SEVERITY_CRITICAL,
    OCSF_SEVERITY_INFORMATIONAL,
    OCSF_STATUS_SUCCESS,
    OCSFGovernanceSink,
    cloudevent_to_ocsf,
    governance_event_to_ocsf,
)


class TestCloudEventToOCSF:
    """Tests for converting CloudEvents 1.0 envelopes to OCSF schema."""

    def test_detection_finding_policy_violation(self):
        """Class 2004 (Detection Finding) for policy violations."""
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

        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING
        assert ocsf["class_name"] == "Detection Finding"
        assert ocsf["category_uid"] == 2
        assert ocsf["category_name"] == "Findings"
        assert ocsf["activity_id"] == 1
        assert ocsf["type_uid"] == 200401  # 2004 * 100 + 1
        assert ocsf["disposition_id"] == OCSF_DISPOSITION_BLOCKED
        assert ocsf["disposition"] == "Blocked"
        # Detection Finding (2004) uses its own status enum; default is New (1)
        assert ocsf["status_id"] == 1
        assert ocsf["status"] == "New"
        assert ocsf["severity_id"] == OCSF_SEVERITY_CRITICAL
        assert ocsf["severity"] == "Critical"

        # Trace correlation in metadata
        assert ocsf["metadata"]["correlation_uid"] == "trace-abc-999"
        assert ocsf["metadata"]["version"] == OCSF_SCHEMA_VERSION

        # Trace context forwarded to unmapped._trace (no OCSF observability attr)
        assert ocsf["unmapped"]["_trace"]["trace_id"] == "trace-abc-999"
        assert ocsf["unmapped"]["_trace"]["span_id"] == "span-111"
        assert ocsf["unmapped"]["_trace"]["parent_span_id"] == "span-000"
        assert ocsf["unmapped"]["_trace"]["session_id"] == "session-xyz"

        # Finding details (1.9.x requires finding_info; actor/state not present)
        assert ocsf["finding_info"]["uid"] == "evt-violation-123"
        assert "no-destructive-commands" in ocsf["finding_info"]["title"]
        assert ocsf["policy"]["name"] == "no-destructive-commands"
        assert "actor" not in ocsf

    def test_api_activity_policy_check_allowed(self):
        """Class 6003 (API Activity) for allowed policy checks."""
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

        # API Activity required fields
        assert ocsf["api"]["operation"] == "query_database"
        assert ocsf["api"]["service"]["name"] == "agent-os"
        assert ocsf["api"]["request"]["uid"] == "evt-check-456"
        assert ocsf["api"]["request"]["data"] == "SELECT * FROM users"
        assert "src_endpoint" in ocsf
        assert ocsf["policy"]["name"] == "read-only-access"
        assert ocsf["metadata"]["correlation_uid"] == "trace-def-888"

    def test_authorize_session_identity_verified(self):
        """Class 3003 (Authorize Session) for identity verification events."""
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
        assert ocsf["activity_name"] == "Assign Privileges"
        assert ocsf["type_uid"] == 300301  # 3003 * 100 + 1
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

        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING
        assert ocsf["metadata"]["correlation_uid"] == "mesh-trace-123"
        assert ocsf["status_detail"] == "Path traversal attempt"
        assert ocsf["unmapped"]["agentmeshentryhash"] == "sha256:abc123hash"
        assert ocsf["unmapped"]["custom_metric"] == 42


class TestKindClassificationPerKind:
    """Verify every GovernanceEventKind routes to the correct OCSF class.

    GovernanceEvent.to_cloudevent() does not write ``kind`` into the data
    payload, so classification must recover it from the CloudEvents ``type``
    string.  This test suite exercises each kind in isolation.
    """

    def _make_ce(self, kind: GovernanceEventKind, decision: str = "allow") -> dict:
        event = GovernanceEvent(
            agent_id="test-agent",
            action="test-action",
            decision=decision,
            kind=kind,
        )
        return event.to_cloudevent(source="/test")

    def test_policy_check_is_api_activity(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.POLICY_CHECK))
        assert ocsf["class_uid"] == OCSF_CLASS_API_ACTIVITY

    def test_resource_access_is_api_activity(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.RESOURCE_ACCESS))
        assert ocsf["class_uid"] == OCSF_CLASS_API_ACTIVITY

    def test_checkpoint_created_is_api_activity(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.CHECKPOINT_CREATED))
        assert ocsf["class_uid"] == OCSF_CLASS_API_ACTIVITY

    def test_policy_violation_is_detection_finding(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.POLICY_VIOLATION, "deny"))
        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING

    def test_tool_call_blocked_is_detection_finding(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.TOOL_CALL_BLOCKED, "deny"))
        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING

    def test_prompt_injection_detected_is_detection_finding(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.PROMPT_INJECTION_DETECTED))
        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING

    def test_mcp_tool_poisoning_is_detection_finding(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.MCP_TOOL_POISONING))
        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING

    def test_content_violation_is_detection_finding(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.CONTENT_VIOLATION))
        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING

    def test_anomaly_detected_is_detection_finding(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.ANOMALY_DETECTED))
        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING

    def test_identity_verified_is_authorize_session(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.IDENTITY_VERIFIED))
        assert ocsf["class_uid"] == OCSF_CLASS_AUTHORIZE_SESSION

    def test_identity_rejected_is_authorize_session(self):
        """IDENTITY_REJECTED with decision=deny must still map to 3003, not 2004."""
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.IDENTITY_REJECTED, "deny"))
        assert ocsf["class_uid"] == OCSF_CLASS_AUTHORIZE_SESSION

    def test_escalation_requested_is_authorize_session(self):
        ocsf = cloudevent_to_ocsf(self._make_ce(GovernanceEventKind.ESCALATION_REQUESTED))
        assert ocsf["class_uid"] == OCSF_CLASS_AUTHORIZE_SESSION


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

        assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING
        assert ocsf["disposition"] == "Blocked"
        assert ocsf["unmapped"]["_trace"]["trace_id"] == "trace-sec-555"
        assert ocsf["unmapped"]["_trace"]["span_id"] == "span-sec-666"
        assert ocsf["unmapped"]["_trace"]["session_id"] == "session-sec-777"
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
        assert ocsf["unmapped"]["_trace"]["trace_id"] == "tr-01"


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
        assert record1["unmapped"]["_trace"]["trace_id"] == "trace-1"

        assert record2["class_uid"] == OCSF_CLASS_DETECTION_FINDING
        assert record2["unmapped"]["_trace"]["trace_id"] == "trace-2"
        assert record2["disposition"] == "Blocked"

    def test_per_event_error_does_not_drop_valid_records(self):
        """A bad event in a batch must not suppress the remaining valid records."""
        stream = io.StringIO()
        sink = OCSFGovernanceSink(source="/agent-os/test", stream=stream)

        good_event = GovernanceEvent(
            agent_id="agent-ok",
            action="run",
            decision="allow",
            kind=GovernanceEventKind.POLICY_CHECK,
        )

        # Simulate a malformed event by patching .to_cloudevent to raise
        class _BadEvent(GovernanceEvent):
            def to_cloudevent(self, source=None, *, signer=None):
                raise RuntimeError("intentional serialisation failure")

        bad_event = _BadEvent(
            agent_id="agent-bad",
            action="crash",
            decision="allow",
            kind=GovernanceEventKind.POLICY_CHECK,
        )

        result = sink.emit([bad_event, good_event])
        # Overall result is FAILURE because one event failed
        assert result == SinkExportResult.FAILURE
        # But the good event was still written
        lines = [ln for ln in stream.getvalue().strip().split("\n") if ln]
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["actor"]["user"]["name"] == "agent-ok"

    def test_processor_fan_out_with_ocsf_sink(self):
        stream = io.StringIO()
        sink = OCSFGovernanceSink(source="/agent-os", stream=stream)

        processor = GovernanceEventProcessor(schedule_delay_ms=50)
        processor.add_sink(sink)

        event = GovernanceEvent(
            agent_id="fan-out-agent",
            action="execute_tool",
            decision="allow",
            trace_id="trace-fan-out-123",
            kind=GovernanceEventKind.POLICY_CHECK,
        )

        processor.on_event(event)
        processor.shutdown(timeout_ms=3000)

        lines = stream.getvalue().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["class_uid"] == OCSF_CLASS_API_ACTIVITY
        assert record["unmapped"]["_trace"]["trace_id"] == "trace-fan-out-123"
