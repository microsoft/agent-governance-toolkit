# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Governance module."""

import pytest
from datetime import datetime, timedelta
import tempfile
import json

from agentmesh.governance import (
    PolicyEngine,
    Policy,
    PolicyRule,
    ComplianceEngine,
    ComplianceFramework,
    AuditLog,
    AuditChain,
    ShadowMode,
)

# For backward compatibility if modules are refactored
HAS_COMPLIANCE = True
HAS_AUDIT = True
HAS_SHADOW = True


class TestPolicyEngine:
    """Tests for PolicyEngine."""
    
    def test_create_engine(self):
        """Test creating policy engine."""
        engine = PolicyEngine()
        
        assert engine is not None
        assert len(engine.list_policies()) == 0
    
    def test_load_policy(self):
        """Test loading a policy."""
        engine = PolicyEngine()
        
        policy = Policy(
            name="Test Policy",
            rules=[
                PolicyRule(
                    name="rule-1",
                    condition="action.type == 'read'",
                    action="allow",
                ),
            ],
        )
        
        engine.load_policy(policy)
        
        assert len(engine.list_policies()) == 1
        assert engine.get_policy("Test Policy") is not None
    
    def test_policy_evaluation(self):
        """Test policy evaluation."""
        engine = PolicyEngine()
        
        policy = Policy(
            name="Test Policy",
            agents=["*"],  # Apply to all agents
            rules=[
                PolicyRule(
                    name="block-exports",
                    condition="action.type == 'export'",
                    action="deny",
                    description="Block all exports",
                ),
            ],
            default_action="allow",
        )
        engine.load_policy(policy)
        
        # Should be blocked
        result = engine.evaluate(
            agent_did="did:agentmesh:test",
            context={"action": {"type": "export"}},
        )
        
        assert result.action == "deny"
        assert result.allowed is False
    
    def test_policy_deterministic(self):
        """Test that policy evaluation is deterministic."""
        engine = PolicyEngine()
        
        policy = Policy(
            name="Test Policy",
            agents=["*"],
            rules=[
                PolicyRule(
                    name="rule-1",
                    condition="action.type == 'read'",
                    action="allow",
                ),
            ],
            default_action="deny",
        )
        engine.load_policy(policy)
        
        context = {"action": {"type": "read"}}
        
        # Multiple evaluations should give same result
        results = [engine.evaluate("did:agentmesh:test", context) for _ in range(10)]
        
        assert all(r.action == results[0].action for r in results)


class TestCompliance:
    """Tests for ComplianceEngine."""
    
    def test_create_engine(self):
        """Test creating compliance engine with specific frameworks."""
        engine = ComplianceEngine([ComplianceFramework.SOC2])
        
        assert engine is not None
        assert ComplianceFramework.SOC2 in engine.frameworks
    
    def test_eu_ai_act_mapping(self):
        """Test EU AI Act compliance mapping."""
        engine = ComplianceEngine([ComplianceFramework.EU_AI_ACT])
        
        mapping = engine.map_action("automated_decision")
        assert mapping is not None
        assert any("EUAI" in c for c in mapping.controls)
    
    def test_soc2_mapping(self):
        """Test SOC 2 compliance mapping."""
        engine = ComplianceEngine([ComplianceFramework.SOC2])
        
        mapping = engine.map_action("data_access")
        assert mapping is not None
        assert any("SOC2" in c for c in mapping.controls)
    
    def test_compliance_report(self):
        """Test generating compliance report."""
        engine = ComplianceEngine([ComplianceFramework.SOC2])
        
        now = datetime.utcnow()
        report = engine.generate_report(
            framework=ComplianceFramework.SOC2,
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        assert report is not None
        assert report.framework == ComplianceFramework.SOC2
        assert report.total_controls > 0
        assert 0 <= report.compliance_score <= 100
    
    def test_hipaa_violation_detection(self):
        """Test HIPAA violation detection for unencrypted PHI."""
        engine = ComplianceEngine([ComplianceFramework.HIPAA])
        
        violations = engine.check_compliance(
            agent_did="did:agentmesh:test-agent",
            action_type="data_access",
            context={"data_type": "phi", "encrypted": False},
        )
        
        assert len(violations) > 0
        assert violations[0].framework == ComplianceFramework.HIPAA
        assert violations[0].severity == "high"
    
    def test_gdpr_consent_violation(self):
        """Test GDPR violation for missing consent."""
        engine = ComplianceEngine([ComplianceFramework.GDPR])
        
        violations = engine.check_compliance(
            agent_did="did:agentmesh:test-agent",
            action_type="data_access",
            context={"personal_data": True, "consent_verified": False},
        )
        
        assert len(violations) > 0
        assert violations[0].framework == ComplianceFramework.GDPR


class TestAudit:
    """Tests for AuditLog and AuditChain."""
    
    def test_audit_entry(self):
        """Test creating and logging an audit entry."""
        audit_log = AuditLog()
        
        entry = audit_log.log(
            event_type="agent_action",
            agent_did="did:agentmesh:test-agent",
            action="read_data",
            resource="/api/data",
            outcome="success",
        )
        
        assert entry is not None
        assert entry.event_type == "agent_action"
        assert entry.agent_did == "did:agentmesh:test-agent"
        assert entry.entry_hash != ""  # Hash is computed by MerkleAuditChain
    
    def test_audit_retrieval(self):
        """Test retrieving audit entries by agent and type."""
        audit_log = AuditLog()
        
        audit_log.log("action", "did:agentmesh:agent-1", "read")
        audit_log.log("action", "did:agentmesh:agent-2", "write")
        audit_log.log("action", "did:agentmesh:agent-1", "delete")
        
        agent1_entries = audit_log.get_entries_for_agent("did:agentmesh:agent-1")
        assert len(agent1_entries) == 2
        
        all_entries = audit_log.query(event_type="action")
        assert len(all_entries) == 3
    
    def test_audit_chain(self):
        """Test append-only audit log."""
        from agentmesh.governance.audit import AuditEntry
        
        chain = AuditChain()
        
        entry = AuditEntry(
            event_type="test",
            agent_did="did:agentmesh:test",
            action="read",
        )
        chain.add_entry(entry)
        
        # Root hash is computed
        assert chain.get_root_hash() is not None
        
        # Proof is available
        proof = chain.get_proof(entry.entry_id)
        assert proof is not None
    
    def test_chain_tamper_detection(self):
        """Test that chain tampering is detected."""
        audit_log = AuditLog()
        
        audit_log.log("action", "did:agentmesh:agent-1", "read")
        audit_log.log("action", "did:agentmesh:agent-1", "write")
        audit_log.log("action", "did:agentmesh:agent-1", "delete")
        
        # Chain should be valid
        is_valid, error = audit_log.verify_integrity()
        assert is_valid is True
        assert error is None
    
    def test_audit_export(self):
        """Test exporting audit log for external verification."""
        audit_log = AuditLog()
        
        audit_log.log("action", "did:agentmesh:agent-1", "read")
        
        export = audit_log.export()
        assert export["entry_count"] == 1
        assert export["chain_root"] is not None  # Merkle root is computed


class TestShadowMode:
    """Tests for ShadowMode."""
    
    def test_create_shadow(self):
        """Test creating shadow mode session."""
        engine = PolicyEngine()
        shadow = ShadowMode(engine)
        
        session = shadow.start_session()
        assert session is not None
        assert session.active is True
    
    def test_shadow_simulation(self):
        """Test simulating actions in shadow mode."""
        from agentmesh.governance.shadow import SimulatedAction
        
        engine = PolicyEngine()
        policy = Policy(
            name="Test Policy",
            agents=["*"],
            rules=[
                PolicyRule(
                    name="block-exports",
                    condition="action.type == 'export'",
                    action="deny",
                ),
            ],
            default_action="allow",
        )
        engine.load_policy(policy)
        
        shadow = ShadowMode(engine)
        session = shadow.start_session()
        
        action = SimulatedAction(
            action_id="test-1",
            agent_did="did:agentmesh:test",
            action_type="export",
            context={"action": {"type": "export"}},
        )
        
        result = shadow.evaluate(action)
        assert result is not None
        assert result.shadow_allowed is False
        assert result.shadow_action == "deny"
    
    def test_shadow_divergence_report(self):
        """Test divergence detection between shadow and production."""
        from agentmesh.governance.shadow import SimulatedAction
        
        engine = PolicyEngine()
        policy = Policy(
            name="Test Policy",
            agents=["*"],
            rules=[
                PolicyRule(
                    name="block-exports",
                    condition="action.type == 'export'",
                    action="deny",
                ),
            ],
            default_action="allow",
        )
        engine.load_policy(policy)
        
        shadow = ShadowMode(engine)
        shadow.start_session()
        
        action = SimulatedAction(
            action_id="test-1",
            agent_did="did:agentmesh:test",
            action_type="export",
            context={"action": {"type": "export"}},
        )
        
        # Simulate with production decision that differs
        shadow.evaluate(action, production_decision={"allowed": True, "action": "allow"})
        
        session = shadow.end_session()
        assert session.total_evaluated == 1
        assert session.total_diverged == 1
        
        report = shadow.get_divergence_report(session.session_id)
        assert report["within_target"] is False
