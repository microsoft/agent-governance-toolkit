# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Shapley-value fault attribution, quarantine, and liability ledger."""

from datetime import UTC, datetime, timedelta

import pytest

from hypervisor.liability.attribution import (
    CausalAttributor,
)
from hypervisor.liability.ledger import (
    LedgerEntryType,
    LiabilityLedger,
)
from hypervisor.liability.quarantine import (
    QuarantineManager,
    QuarantineReason,
)

# ── Fault Logging Tests ────────────────────────────────────


class TestCausalAttribution:
    def test_basic_attribution(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [
                {"action_id": "act1", "step_id": "s1", "success": True},
            ],
            "agent-b": [
                {"action_id": "act2", "step_id": "s2", "success": False},
            ],
        }
        result = attributor.attribute(
            saga_id="saga-1",
            session_id="sess-1",
            agent_actions=actions,
            failure_step_id="s2",
            failure_agent_did="agent-b",
        )
        assert result.root_cause_agent == "agent-b"
        assert len(result.attributions) == 2
        # Direct cause agent should have higher liability
        agent_b_score = result.get_liability("agent-b")
        agent_a_score = result.get_liability("agent-a")
        assert agent_b_score > agent_a_score

    def test_single_agent_gets_full_liability(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [
                {"action_id": "act1", "step_id": "s1", "success": False},
            ],
        }
        result = attributor.attribute(
            saga_id="saga-1",
            session_id="sess-1",
            agent_actions=actions,
            failure_step_id="s1",
            failure_agent_did="agent-a",
        )
        assert result.get_liability("agent-a") == 1.0

    def test_risk_weights_affect_attribution(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [
                {"action_id": "high-risk", "step_id": "s1", "success": True},
            ],
            "agent-b": [
                {"action_id": "low-risk", "step_id": "s2", "success": False},
            ],
        }
        result = attributor.attribute(
            saga_id="saga-1",
            session_id="sess-1",
            agent_actions=actions,
            failure_step_id="s2",
            failure_agent_did="agent-b",
            risk_weights={"high-risk": 0.95, "low-risk": 0.1},
        )
        assert len(result.attributions) == 2

    def test_multiple_failures(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [
                {"action_id": "act1", "step_id": "s1", "success": False},
            ],
            "agent-b": [
                {"action_id": "act2", "step_id": "s2", "success": False},
            ],
            "agent-c": [
                {"action_id": "act3", "step_id": "s3", "success": True},
            ],
        }
        result = attributor.attribute(
            saga_id="saga-1",
            session_id="sess-1",
            agent_actions=actions,
            failure_step_id="s2",
            failure_agent_did="agent-b",
        )
        # All agents should have some liability
        total = sum(a.liability_score for a in result.attributions)
        assert abs(total - 1.0) < 0.01

    def test_attribution_history(self):
        attributor = CausalAttributor()
        actions = {"a": [{"action_id": "x", "step_id": "s1", "success": False}]}
        attributor.attribute("saga-1", "sess-1", actions, "s1", "a")
        attributor.attribute("saga-2", "sess-1", actions, "s1", "a")
        assert len(attributor.attribution_history) == 2

    def test_agents_involved(self):
        attributor = CausalAttributor()
        actions = {
            "agent-a": [{"action_id": "x", "step_id": "s1", "success": True}],
            "agent-b": [{"action_id": "y", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s2", "agent-b")
        assert set(result.agents_involved) == {"agent-a", "agent-b"}


# ── Quarantine Tests ────────────────────────────────────────────


class TestQuarantine:
    def test_quarantine_agent(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.RING_BREACH, details="breach")
        assert mgr.is_quarantined("a1", "s1")
        assert mgr.get_active_quarantine("a1", "s1") is record
        assert record.reason == QuarantineReason.RING_BREACH
        # Isolation is scoped to the session it was issued in.
        assert not mgr.is_quarantined("a1", "other-session")

    def test_release_quarantine(self):
        mgr = QuarantineManager()
        mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        released = mgr.release("a1", "s1")
        assert released is not None
        assert released.released_at is not None
        assert not mgr.is_quarantined("a1", "s1")
        # Releasing again is a no-op.
        assert mgr.release("a1", "s1") is None

    def test_quarantine_escalation(self):
        mgr = QuarantineManager()
        mgr.quarantine("a1", "s1", QuarantineReason.RATE_LIMIT_EXCEEDED)
        mgr.quarantine("a1", "s1", QuarantineReason.LIABILITY_VIOLATION)
        # Re-quarantine supersedes the prior record: only one active, newest reason.
        assert mgr.quarantine_count == 1
        active = mgr.get_active_quarantine("a1", "s1")
        assert active.reason == QuarantineReason.LIABILITY_VIOLATION
        assert len(mgr.get_history(agent_did="a1")) == 2

    def test_quarantine_with_forensic_data(self):
        mgr = QuarantineManager()
        forensic = {"drift_score": 0.82, "action_id": "send-email"}
        record = mgr.quarantine(
            "a1", "s1", QuarantineReason.BEHAVIORAL_DRIFT, forensic_data=forensic
        )
        assert record.forensic_data == forensic

    def test_tick_expires_quarantines(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL, duration_seconds=300)
        assert mgr.is_quarantined("a1", "s1")
        # Force the record past its expiry, then tick.
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        expired = mgr.tick()
        assert record in expired
        assert not mgr.is_quarantined("a1", "s1")
        assert mgr.quarantine_count == 0

    def test_active_quarantines_property(self):
        mgr = QuarantineManager()
        mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        mgr.quarantine("a2", "s1", QuarantineReason.MANUAL)
        assert mgr.quarantine_count == 2
        assert {r.agent_did for r in mgr.active_quarantines} == {"a1", "a2"}
        mgr.release("a1", "s1")
        assert mgr.quarantine_count == 1

    def test_quarantine_history(self):
        mgr = QuarantineManager()
        mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        mgr.quarantine("a1", "s2", QuarantineReason.RING_BREACH)
        history = mgr.get_history(agent_did="a1")
        assert len(history) == 2

    def test_duration_tracking(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        assert record.duration_seconds >= 0

    def test_not_quarantined_after_release(self):
        mgr = QuarantineManager()
        mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        mgr.release("a1", "s1")
        assert not mgr.is_quarantined("a1", "s1")


# ── Liability Ledger Tests ──────────────────────────────────────


class TestLiabilityLedger:
    def test_record_entry(self):
        ledger = LiabilityLedger()
        entry = ledger.record(
            agent_did="agent-a",
            entry_type=LedgerEntryType.SLASH_RECEIVED,
            session_id="sess-1",
            severity=0.8,
            details="Behavioral drift",
        )
        assert entry.agent_did == "agent-a"
        assert ledger.total_entries == 1

    def test_agent_history(self):
        ledger = LiabilityLedger()
        ledger.record("a1", LedgerEntryType.CLEAN_SESSION, "s1")
        ledger.record("a1", LedgerEntryType.SLASH_RECEIVED, "s2", severity=0.5)
        ledger.record("a2", LedgerEntryType.CLEAN_SESSION, "s1")

        history = ledger.get_agent_history("a1")
        assert len(history) == 2

    def test_risk_profile_clean_agent(self):
        ledger = LiabilityLedger()
        for i in range(5):
            ledger.record("a1", LedgerEntryType.CLEAN_SESSION, f"s{i}")

        profile = ledger.compute_risk_profile("a1")
        assert profile.risk_score == 0.0
        assert profile.recommendation == "admit"

    def test_risk_profile_risky_agent(self):
        ledger = LiabilityLedger()
        for i in range(5):
            ledger.record("a1", LedgerEntryType.SLASH_RECEIVED, f"s{i}", severity=0.9)
        profile = ledger.compute_risk_profile("a1")
        assert profile.slash_count == 5
        assert profile.risk_score > ledger.DENY_THRESHOLD
        assert profile.recommendation == "deny"

    def test_risk_profile_probation(self):
        ledger = LiabilityLedger()
        # Two moderate slashes accumulate into the probation band.
        ledger.record("a1", LedgerEntryType.SLASH_RECEIVED, "s1", severity=0.7)
        ledger.record("a1", LedgerEntryType.SLASH_RECEIVED, "s2", severity=0.7)
        profile = ledger.compute_risk_profile("a1")
        assert profile.recommendation == "probation"
        admitted, reason = ledger.should_admit("a1")
        assert admitted  # probation is admitted-but-flagged
        assert reason == "probation"

    def test_should_admit_clean(self):
        ledger = LiabilityLedger()
        ledger.record("a1", LedgerEntryType.CLEAN_SESSION, "s1")
        admitted, reason = ledger.should_admit("a1")
        assert admitted

    def test_should_deny_risky(self):
        ledger = LiabilityLedger()
        for i in range(10):
            ledger.record("a1", LedgerEntryType.SLASH_RECEIVED, f"s{i}", severity=0.9)

        admitted, reason = ledger.should_admit("a1")
        assert not admitted
        assert reason == "deny"

    def test_unknown_agent_admitted(self):
        ledger = LiabilityLedger()
        admitted, reason = ledger.should_admit("unknown")
        assert admitted

    def test_tracked_agents(self):
        ledger = LiabilityLedger()
        ledger.record("a1", LedgerEntryType.CLEAN_SESSION, "s1")
        ledger.record("a2", LedgerEntryType.CLEAN_SESSION, "s1")
        assert set(ledger.tracked_agents) == {"a1", "a2"}

    def test_quarantine_affects_risk(self):
        ledger = LiabilityLedger()
        ledger.record("a1", LedgerEntryType.QUARANTINE_ENTERED, "s1", severity=0.5)
        profile = ledger.compute_risk_profile("a1")
        assert profile.quarantine_count == 1
        assert profile.risk_score > 0.0
