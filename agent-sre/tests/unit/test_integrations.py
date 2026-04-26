# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Agent Mesh and Agent OS integrations."""

from agent_sre.incidents.detector import SignalType
from agent_sre.integrations.agent_mesh.bridge import AgentMeshBridge, MeshEvent
from agent_sre.integrations.agent_os.bridge import AgentOSBridge, AuditLogEntry


class TestAgentMeshBridge:
    def test_trust_sli(self) -> None:
        bridge = AgentMeshBridge()
        bridge.trust_sli.record_trust(850, agent_did="did:mesh:abc")
        val = bridge.trust_sli.current_value()
        assert val is not None
        assert abs(val - 0.85) < 0.01

    def test_handshake_sli(self) -> None:
        bridge = AgentMeshBridge()
        bridge.handshake_sli.record_handshake(True)
        bridge.handshake_sli.record_handshake(True)
        bridge.handshake_sli.record_handshake(False)
        val = bridge.handshake_sli.current_value()
        assert val is not None
        assert val < 1.0

    def test_process_trust_revocation(self) -> None:
        bridge = AgentMeshBridge()
        event = MeshEvent(
            event_type="trust_revocation",
            agent_did="did:mesh:bad-agent",
            details={"reason": "malicious behavior"},
        )
        signal = bridge.process_event(event)
        assert signal is not None
        assert signal.signal_type == SignalType.TRUST_REVOCATION

    def test_process_policy_violation(self) -> None:
        bridge = AgentMeshBridge()
        event = MeshEvent(event_type="policy_violation", agent_did="did:mesh:rogue")
        signal = bridge.process_event(event)
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION

    def test_process_irrelevant_event(self) -> None:
        bridge = AgentMeshBridge()
        event = MeshEvent(event_type="agent_registered", agent_did="did:mesh:new")
        signal = bridge.process_event(event)
        assert signal is None

    def test_slis(self) -> None:
        bridge = AgentMeshBridge()
        slis = bridge.slis()
        assert len(slis) == 2

    def test_summary(self) -> None:
        bridge = AgentMeshBridge()
        bridge.process_event(MeshEvent(event_type="trust_revocation", agent_did="x"))
        s = bridge.summary()
        assert s["events_processed"] == 1

    def test_process_credential_rotation(self) -> None:
        bridge = AgentMeshBridge()
        event = MeshEvent(event_type="credential_rotation", agent_did="did:mesh:agent-1")
        signal = bridge.process_event(event)
        assert signal is None  # rotation is informational, not an incident

    def test_process_trust_update(self) -> None:
        bridge = AgentMeshBridge()
        event = MeshEvent(
            event_type="trust_update",
            agent_did="did:mesh:agent-1",
            details={"score": 750},
        )
        signal = bridge.process_event(event)
        assert signal is None
        val = bridge.trust_sli.current_value()
        assert val is not None
        assert abs(val - 0.75) < 0.01

    def test_process_handshake_event(self) -> None:
        bridge = AgentMeshBridge()
        bridge.process_event(MeshEvent(
            event_type="handshake", agent_did="did:mesh:a", details={"success": True},
        ))
        bridge.process_event(MeshEvent(
            event_type="handshake", agent_did="did:mesh:b", details={"success": False},
        ))
        val = bridge.handshake_sli.current_value()
        assert val is not None
        assert val < 1.0  # at least one failure recorded

    def test_agent_trust_cache(self) -> None:
        bridge = AgentMeshBridge()
        assert bridge.get_agent_trust("did:mesh:unknown") is None
        bridge.process_event(MeshEvent(
            event_type="trust_update", agent_did="did:mesh:a", details={"score": 800},
        ))
        assert bridge.get_agent_trust("did:mesh:a") == 800

    def test_trust_revocation_clears_cache(self) -> None:
        bridge = AgentMeshBridge()
        bridge.process_event(MeshEvent(
            event_type="trust_update", agent_did="did:mesh:a", details={"score": 800},
        ))
        bridge.process_event(MeshEvent(event_type="trust_revocation", agent_did="did:mesh:a"))
        assert bridge.get_agent_trust("did:mesh:a") == 0

    def test_events_by_type(self) -> None:
        bridge = AgentMeshBridge()
        bridge.process_event(MeshEvent(event_type="trust_revocation", agent_did="a"))
        bridge.process_event(MeshEvent(event_type="trust_revocation", agent_did="b"))
        bridge.process_event(MeshEvent(event_type="policy_violation", agent_did="c"))
        s = bridge.summary()
        assert s["events_by_type"]["trust_revocation"] == 2
        assert s["events_by_type"]["policy_violation"] == 1


class TestAgentOSBridge:
    def test_blocked_creates_signal(self) -> None:
        bridge = AgentOSBridge()
        entry = AuditLogEntry(
            entry_type="blocked",
            agent_id="bot-1",
            action="write_file",
            policy_name="no-write-policy",
        )
        signal = bridge.process_audit_entry(entry)
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION

    def test_blocked_records_compliance_failure(self) -> None:
        bridge = AgentOSBridge()
        bridge.process_audit_entry(AuditLogEntry(entry_type="blocked", agent_id="bot-1", policy_name="p1"))
        val = bridge.policy_sli.current_value()
        assert val is not None
        assert val == 0.0  # 0 out of 1 compliant

    def test_allowed_records_compliance(self) -> None:
        bridge = AgentOSBridge()
        bridge.process_audit_entry(AuditLogEntry(entry_type="allowed", agent_id="bot-1"))
        val = bridge.policy_sli.current_value()
        assert val is not None
        assert val == 1.0

    def test_warning_no_signal(self) -> None:
        bridge = AgentOSBridge()
        signal = bridge.process_audit_entry(AuditLogEntry(entry_type="warning", agent_id="bot-1"))
        assert signal is None

    def test_slis(self) -> None:
        bridge = AgentOSBridge()
        assert len(bridge.slis()) == 1

    def test_summary(self) -> None:
        bridge = AgentOSBridge()
        bridge.process_audit_entry(AuditLogEntry(entry_type="blocked", agent_id="bot-1", policy_name="p1"))
        bridge.process_audit_entry(AuditLogEntry(entry_type="warning", agent_id="bot-1"))
        s = bridge.summary()
        assert s["events_processed"] == 2
        assert s["blocked_count"] == 1
        assert s["warning_count"] == 1

    def test_policy_review_rejected(self) -> None:
        bridge = AgentOSBridge()
        entry = AuditLogEntry(
            entry_type="policy_review",
            agent_id="bot-risky",
            action="deploy_model",
            details={"review_outcome": "rejected", "reviewer": "human-1"},
        )
        signal = bridge.process_audit_entry(entry)
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION
        assert "Policy review" in signal.message
        assert bridge._policy_review_count == 1

    def test_policy_review_approved(self) -> None:
        bridge = AgentOSBridge()
        entry = AuditLogEntry(
            entry_type="policy_review",
            agent_id="bot-safe",
            action="read_data",
            details={"review_outcome": "approved"},
        )
        signal = bridge.process_audit_entry(entry)
        assert signal is None  # approved reviews don't generate signals
        assert bridge._policy_review_count == 1
        val = bridge.policy_sli.current_value()
        assert val == 1.0

    def test_policy_review_pending(self) -> None:
        bridge = AgentOSBridge()
        entry = AuditLogEntry(
            entry_type="policy_review",
            agent_id="bot-1",
            action="execute",
            details={},  # no review_outcome = pending
        )
        signal = bridge.process_audit_entry(entry)
        assert signal is None  # pending defaults to compliant

    def test_agent_event_tracking(self) -> None:
        bridge = AgentOSBridge()
        bridge.process_audit_entry(AuditLogEntry(entry_type="allowed", agent_id="bot-1"))
        bridge.process_audit_entry(AuditLogEntry(entry_type="blocked", agent_id="bot-1", policy_name="p1"))
        bridge.process_audit_entry(AuditLogEntry(entry_type="allowed", agent_id="bot-2"))
        assert bridge.get_agent_violation_count("bot-1") == 2
        assert bridge.get_agent_violation_count("bot-2") == 1
        assert bridge.get_agent_violation_count("bot-3") == 0

    def test_summary_with_policy_review(self) -> None:
        bridge = AgentOSBridge()
        bridge.process_audit_entry(AuditLogEntry(entry_type="blocked", agent_id="a", policy_name="p1"))
        bridge.process_audit_entry(AuditLogEntry(
            entry_type="policy_review", agent_id="b",
            details={"review_outcome": "rejected"},
        ))
        bridge.process_audit_entry(AuditLogEntry(entry_type="allowed", agent_id="c"))
        s = bridge.summary()
        assert s["policy_review_count"] == 1
        assert s["blocked_count"] == 1
        assert s["agents_seen"] == 3
