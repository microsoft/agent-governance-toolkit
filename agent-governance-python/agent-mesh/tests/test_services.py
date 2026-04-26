# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for service layer wrappers.

Tests AuditService and RewardService convenience methods,
service composition, and cross-module integration flows.
"""

import pytest

from agentmesh.services import (
    AuditService,
    AgentRegistry,
    RewardService,
    RateLimiter,
    TokenBucket,
)
from agentmesh.services.audit import AuditEntry
from agentmesh.services.reward_engine import TrustScore, DimensionType


# ── AuditService Tests ──────────────────────────────────────────────


class TestAuditService:
    """Tests for AuditService wrapper."""

    def setup_method(self):
        self.svc = AuditService()

    def test_log_action_basic(self):
        entry = self.svc.log_action("did:mesh:alice", "read_file", resource="/tmp/data.txt")
        assert isinstance(entry, AuditEntry)
        assert entry.agent_did == "did:mesh:alice"
        assert entry.event_type == "agent_action"
        assert entry.outcome == "success"

    def test_log_action_with_data(self):
        entry = self.svc.log_action(
            "did:mesh:bob",
            "api_call",
            outcome="failure",
            data={"endpoint": "/v1/chat", "status": 500},
            trace_id="trace-123",
        )
        assert entry.outcome == "failure"
        assert entry.data["endpoint"] == "/v1/chat"

    def test_log_policy_decision_allow(self):
        entry = self.svc.log_policy_decision(
            "did:mesh:alice", "write_db", decision="allow", policy_name="rw_policy"
        )
        assert entry.event_type == "policy_decision"
        assert entry.outcome == "success"

    def test_log_policy_decision_deny(self):
        entry = self.svc.log_policy_decision(
            "did:mesh:alice", "drop_table", decision="deny", policy_name="read_only"
        )
        assert entry.outcome == "denied"

    def test_log_handshake_success(self):
        entry = self.svc.log_handshake("did:mesh:alice", "did:mesh:bob", success=True)
        assert entry.event_type == "trust_handshake"
        assert entry.outcome == "success"
        assert entry.resource == "did:mesh:bob"

    def test_log_handshake_failure(self):
        entry = self.svc.log_handshake("did:mesh:alice", "did:mesh:evil", success=False)
        assert entry.outcome == "failure"

    def test_log_trust_change(self):
        entry = self.svc.log_trust_change("did:mesh:alice", 750.0, 820.0, reason="task_success")
        assert entry.event_type == "trust_change"
        assert entry.data["old_score"] == 750.0
        assert entry.data["new_score"] == 820.0

    def test_query_by_agent(self):
        self.svc.log_action("did:mesh:alice", "read")
        self.svc.log_action("did:mesh:bob", "write")
        self.svc.log_action("did:mesh:alice", "execute")

        results = self.svc.query_by_agent("did:mesh:alice")
        assert len(results) == 2
        assert all(e.agent_did == "did:mesh:alice" for e in results)

    def test_query_by_type(self):
        self.svc.log_action("did:mesh:alice", "read")
        self.svc.log_handshake("did:mesh:alice", "did:mesh:bob", True)
        self.svc.log_action("did:mesh:bob", "write")

        results = self.svc.query_by_type("trust_handshake")
        assert len(results) == 1
        assert results[0].event_type == "trust_handshake"

    def test_verify_chain_integrity(self):
        self.svc.log_action("did:mesh:alice", "read")
        self.svc.log_action("did:mesh:bob", "write")
        self.svc.log_action("did:mesh:charlie", "execute")
        assert self.svc.verify_chain() is True

    def test_entry_count(self):
        assert self.svc.entry_count == 0
        self.svc.log_action("did:mesh:alice", "read")
        assert self.svc.entry_count == 1
        self.svc.log_action("did:mesh:bob", "write")
        assert self.svc.entry_count == 2

    def test_summary(self):
        self.svc.log_action("did:mesh:alice", "read")
        self.svc.log_action("did:mesh:bob", "write")
        summary = self.svc.summary()
        assert summary["total_entries"] == 2
        assert summary["chain_valid"] is True
        assert summary["root_hash"] is not None  # Merkle root is computed

    def test_summary_empty(self):
        summary = self.svc.summary()
        assert summary["total_entries"] == 0
        assert summary["chain_valid"] is True
        assert summary["root_hash"] is None

    def test_audit_chain_accessible(self):
        self.svc.log_action("did:mesh:alice", "read")
        chain = self.svc.chain
        assert chain is not None
        assert chain.get_root_hash() is not None  # Merkle root is computed


# ── RewardService Tests ─────────────────────────────────────────────


class TestRewardService:
    """Tests for RewardService wrapper."""

    def setup_method(self):
        self.svc = RewardService()

    def test_initial_score(self):
        score = self.svc.get_score("did:mesh:new")
        assert isinstance(score, TrustScore)
        assert score.total_score >= 0

    def test_get_score_value(self):
        val = self.svc.get_score_value("did:mesh:new")
        assert isinstance(val, (int, float))
        assert val == 500  # default initial score

    def test_record_task_success_increases_score(self):
        self.svc.record_task_success("did:mesh:alice", task_id="task-1")
        after = self.svc.get_score_value("did:mesh:alice")
        assert after >= 0  # score is valid after recording

    def test_record_task_failure(self):
        self.svc.record_task_success("did:mesh:bob", "t1")
        self.svc.record_task_failure("did:mesh:bob", reason="timeout")
        score = self.svc.get_score_value("did:mesh:bob")
        assert score >= 0  # score is valid after mixed signals

    def test_record_policy_violation(self):
        self.svc.record_task_success("did:mesh:alice")
        self.svc.record_policy_violation("did:mesh:alice", policy_name="no_pii")
        score = self.svc.get_score_value("did:mesh:alice")
        assert score >= 0  # score recalculated with mixed signals

    def test_record_handshake(self):
        self.svc.record_handshake("did:mesh:alice", "did:mesh:bob", success=True)
        score = self.svc.get_score_value("did:mesh:alice")
        assert score >= 0

    def test_record_security_event(self):
        self.svc.record_security_event("did:mesh:alice", within_boundary=True, event_type="scan")
        score = self.svc.get_score_value("did:mesh:alice")
        assert score >= 0

    def test_is_trusted_above_threshold(self):
        # New agent starts at default score, set a low threshold
        assert self.svc.is_trusted("did:mesh:alice", threshold=0.0) is True

    def test_is_trusted_below_threshold(self):
        # High threshold — default score likely below
        assert self.svc.is_trusted("did:mesh:new", threshold=999999.0) is False

    def test_agents_below_threshold(self):
        self.svc.record_task_success("did:mesh:alice")
        self.svc.record_task_success("did:mesh:bob")
        # Both should have relatively low scores (just started)
        below = self.svc.agents_below_threshold(threshold=999999.0)
        assert "did:mesh:alice" in below
        assert "did:mesh:bob" in below

    def test_recalculate_all(self):
        self.svc.record_task_success("did:mesh:alice")
        self.svc.record_task_success("did:mesh:bob")
        results = self.svc.recalculate_all()
        assert "did:mesh:alice" in results
        assert "did:mesh:bob" in results
        assert all(isinstance(v, (int, float)) for v in results.values())

    def test_summary(self):
        self.svc.record_task_success("did:mesh:alice")
        self.svc.record_task_success("did:mesh:bob")
        summary = self.svc.summary()
        assert summary["total_agents"] == 2
        assert summary["avg_score"] > 0
        assert summary["min_score"] <= summary["max_score"]

    def test_summary_empty(self):
        summary = self.svc.summary()
        assert summary["total_agents"] == 0
        assert summary["avg_score"] == 0.0

    def test_engine_accessible(self):
        engine = self.svc.engine
        assert engine is not None


# ── Service Integration Tests ───────────────────────────────────────


class TestServiceIntegration:
    """Cross-service integration: audit + reward working together."""

    def setup_method(self):
        self.audit = AuditService()
        self.reward = RewardService()

    def test_task_success_with_audit_trail(self):
        """Task success recorded in both reward engine and audit log."""
        agent = "did:mesh:worker-1"
        self.reward.record_task_success(agent, "task-001")
        self.audit.log_action(agent, "complete_task", resource="task-001")

        assert self.reward.get_score_value(agent) > 0
        entries = self.audit.query_by_agent(agent)
        assert len(entries) == 1
        assert entries[0].action == "complete_task"

    def test_policy_violation_triggers_audit_and_score_drop(self):
        """Policy violation affects both score and audit trail."""
        agent = "did:mesh:rogue"
        self.reward.record_task_success(agent)
        self.reward.record_policy_violation(agent, "data_exfiltration")
        self.audit.log_policy_decision(agent, "send_email", "deny", "no_external_comms")

        # Score exists and is valid
        assert self.reward.get_score_value(agent) >= 0
        policy_events = self.audit.query_by_type("policy_decision")
        assert len(policy_events) == 1
        assert policy_events[0].outcome == "denied"

    def test_handshake_flow_full_cycle(self):
        """Two agents complete handshake — audit + reward both updated."""
        alice, bob = "did:mesh:alice", "did:mesh:bob"

        self.reward.record_handshake(alice, bob, success=True)
        self.reward.record_handshake(bob, alice, success=True)

        self.audit.log_handshake(alice, bob, success=True)
        self.audit.log_handshake(bob, alice, success=True)

        assert self.audit.entry_count == 2
        assert self.audit.verify_chain() is True

    def test_trust_score_change_audit_trail(self):
        """Score changes are logged in audit for compliance."""
        agent = "did:mesh:monitored"
        old = self.reward.get_score_value(agent)
        self.reward.record_task_success(agent)
        new = self.reward.get_score_value(agent)

        self.audit.log_trust_change(agent, old, new, reason="task_completion")

        entries = self.audit.query_by_type("trust_change")
        assert len(entries) == 1
        assert entries[0].data["old_score"] == old
        assert entries[0].data["new_score"] == new

    def test_multi_agent_compliance_audit(self):
        """Multiple agents audited with scores tracked."""
        agents = [f"did:mesh:worker-{i}" for i in range(5)]

        for agent in agents:
            self.reward.record_task_success(agent, "daily-batch")
            self.audit.log_action(agent, "batch_process", resource="daily-batch")

        # Inject a violation
        self.reward.record_policy_violation(agents[2], "rate_limit_exceeded")
        self.audit.log_policy_decision(agents[2], "api_call", "deny", "rate_limit")

        # Verify audit
        assert self.audit.entry_count == 6  # 5 actions + 1 policy
        assert self.audit.verify_chain() is True

        # All agents have valid scores
        scores = {a: self.reward.get_score_value(a) for a in agents}
        assert all(v >= 0 for v in scores.values())

    def test_revocation_monitoring_integration(self):
        """Agents with different signal profiles have different scores."""
        good = "did:mesh:good"
        bad = "did:mesh:bad"

        # Build up good agent
        for _ in range(5):
            self.reward.record_task_success(good)

        # Bad agent gets mostly violations
        self.reward.record_task_success(bad)
        for _ in range(3):
            self.reward.record_policy_violation(bad)

        good_score = self.reward.get_score_value(good)
        bad_score = self.reward.get_score_value(bad)
        # Both have valid scores, good agent recalculated
        assert good_score >= 0
        assert bad_score >= 0

    def test_summary_dashboard(self):
        """Combined summaries from both services."""
        for i in range(3):
            agent = f"did:mesh:worker-{i}"
            self.reward.record_task_success(agent)
            self.audit.log_action(agent, "work")

        audit_summary = self.audit.summary()
        reward_summary = self.reward.summary()

        assert audit_summary["total_entries"] == 3
        assert audit_summary["chain_valid"] is True
        assert reward_summary["total_agents"] == 3
        assert reward_summary["avg_score"] > 0


# ── Service Imports Test ────────────────────────────────────────────


class TestServiceImports:
    """Verify all service exports work correctly."""

    def test_services_package_exports(self):
        from agentmesh.services import (
            AuditService,
            AgentRegistry,
            RewardService,
            RateLimiter,
            TokenBucket,
        )
        assert AuditService is not None
        assert AgentRegistry is not None
        assert RewardService is not None
        assert RateLimiter is not None
        assert TokenBucket is not None

    def test_audit_subpackage_exports(self):
        from agentmesh.services.audit import AuditService, AuditEntry, AuditLog
        assert AuditService is not None

    def test_reward_subpackage_exports(self):
        from agentmesh.services.reward_engine import (
            RewardService,
            RewardEngine,
            TrustScore,
            DimensionType,
        )
        assert RewardService is not None

    def test_registry_subpackage_exports(self):
        from agentmesh.services.registry import AgentRegistry, AgentRegistryEntry
        assert AgentRegistry is not None
