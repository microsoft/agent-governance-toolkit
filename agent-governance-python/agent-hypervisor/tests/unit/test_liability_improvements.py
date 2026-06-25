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
    @pytest.mark.skip("Feature not available in Public Preview")
    def test_quarantine_agent(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_release_quarantine(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_quarantine_escalation(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_quarantine_with_forensic_data(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_tick_expires_quarantines(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_active_quarantines_property(self):
        pass

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
        # Public Preview: no risk scoring, always admits
        assert profile.risk_score == 0.0
        assert profile.recommendation == "admit"

    def test_risk_profile_probation(self):
        ledger = LiabilityLedger()
        ledger.record("a1", LedgerEntryType.SLASH_RECEIVED, "s1", severity=0.7)
        ledger.record("a1", LedgerEntryType.CLEAN_SESSION, "s2")
        ledger.record("a1", LedgerEntryType.CLEAN_SESSION, "s3")

        profile = ledger.compute_risk_profile("a1")
        assert profile.recommendation in ("admit", "probation")

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
        # Public Preview: always admits
        assert admitted
        assert reason == "admit"

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
        # Public Preview: no risk scoring, always admits
        assert profile.quarantine_count == 0
        assert profile.risk_score == 0.0
        assert profile.recommendation == "admit"


# ── Causal Attribution Distribution (BUG 2 fix) ─────────────────


class TestCausalAttributionDistribution:
    def test_risk_weights_distribute_liability(self):
        """risk_weights keyed by agent DID override the causal split and are
        normalized across participants (no longer 100% to the direct cause)."""
        attributor = CausalAttributor()
        actions = {
            "did:a": [{"action_id": "act1", "step_id": "s1", "success": True}],
            "did:b": [{"action_id": "act2", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute(
            "saga-1",
            "sess-1",
            actions,
            failure_step_id="s2",
            failure_agent_did="did:b",
            risk_weights={"did:a": 0.5, "did:b": 0.5},
        )
        assert abs(result.get_liability("did:a") - 0.5) < 1e-9
        assert abs(result.get_liability("did:b") - 0.5) < 1e-9

    def test_risk_weights_proportional(self):
        attributor = CausalAttributor()
        actions = {
            "did:a": [{"action_id": "act1", "step_id": "s1", "success": False}],
            "did:b": [{"action_id": "act2", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute(
            "saga-1",
            "sess-1",
            actions,
            failure_step_id="s2",
            failure_agent_did="did:b",
            risk_weights={"did:a": 3.0, "did:b": 1.0},
        )
        assert abs(result.get_liability("did:a") - 0.75) < 1e-9
        assert abs(result.get_liability("did:b") - 0.25) < 1e-9

    def test_multiple_failed_agents_share_liability(self):
        """Without weights, two failed agents on the chain share liability;
        the direct cause keeps the larger share but not 100%."""
        attributor = CausalAttributor()
        actions = {
            "agent-a": [{"action_id": "act1", "step_id": "s1", "success": False}],
            "agent-b": [{"action_id": "act2", "step_id": "s2", "success": False}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s2", "agent-b")
        a = result.get_liability("agent-a")
        b = result.get_liability("agent-b")
        assert a > 0.0
        assert b > a
        assert b < 1.0
        assert abs((a + b) - 1.0) < 1e-9

    def test_post_failure_cascade_excluded(self):
        """Agents that fail after the root failure are cascade effects, not
        causes, so the direct cause gets full liability."""
        attributor = CausalAttributor()
        actions = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": False}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
            "c": [{"action_id": "c1", "step_id": "s3", "success": False}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s1", "a")
        assert result.get_liability("a") == 1.0
        assert result.get_liability("b") == 0.0
        assert result.get_liability("c") == 0.0
        assert result.causal_chain_length == 1

    def test_causal_chain_length_counts_failures(self):
        """causal_chain_length is the number of FAILED actions on the chain (the
        causal contributors), not the count of all preceding actions."""
        attributor = CausalAttributor()
        actions = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": False}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
            "c": [{"action_id": "c1", "step_id": "s3", "success": True}],
        }
        # Chain is s1, s2 (up to the failure at s2); both a and b failed -> 2.
        result = attributor.attribute("saga-1", "sess-1", actions, "s2", "b")
        assert result.causal_chain_length == 2

    def test_causal_chain_length_ignores_successful_prep(self):
        """Successful pre-failure actions do not inflate causal_chain_length."""
        attributor = CausalAttributor()
        actions = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": True}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
            "c": [{"action_id": "c1", "step_id": "s3", "success": True}],
        }
        result = attributor.attribute("saga-1", "sess-1", actions, "s2", "b")
        # Only b failed on the chain -> 1, even though s1 precedes it.
        assert result.causal_chain_length == 1

    def test_attribution_is_insertion_order_independent(self):
        """Regression: liability must not depend on agent_actions dict order.
        Same facts (a failed at s1, b failed at s2, failure at b) inserted in
        both orders must give identical scores."""
        ab = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": False}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
        }
        ba = {
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
            "a": [{"action_id": "a1", "step_id": "s1", "success": False}],
        }
        ra = CausalAttributor().attribute("sg", "ss", ab, "s2", "b")
        rb = CausalAttributor().attribute("sg", "ss", ba, "s2", "b")
        assert ra.get_liability("a") == rb.get_liability("a")
        assert ra.get_liability("b") == rb.get_liability("b")
        assert ra.causal_chain_length == rb.causal_chain_length

    def test_post_failure_action_of_multiaction_agent_excluded(self):
        """Regression: an agent that succeeds upstream then fails AFTER the root
        failure step is a cascade victim, not a cause. Ordering by step_id must
        exclude its post-failure action."""
        actions = {
            # a: ok at s1, then fails at s3 (after b's root failure at s2)
            "a": [
                {"action_id": "a1", "step_id": "s1", "success": True},
                {"action_id": "a3", "step_id": "s3", "success": False},
            ],
            "b": [{"action_id": "b2", "step_id": "s2", "success": False}],
        }
        result = CausalAttributor().attribute("sg", "ss", actions, "s2", "b")
        assert result.get_liability("a") == 0.0
        assert result.get_liability("b") == 1.0

    def test_partial_risk_weights_fall_back_to_causal(self):
        """Regression: a partial risk_weights map (not covering every agent) must
        NOT silently zero the omitted failed agents. It falls back to the causal
        split instead of treating the partial map as a complete override."""
        actions = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": False}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
            "c": [{"action_id": "c1", "step_id": "s3", "success": False}],
        }
        # Only 'a' is weighted; b and c are omitted.
        result = CausalAttributor().attribute(
            "sg", "ss", actions, "s3", "c", risk_weights={"a": 1.0}
        )
        # c (direct cause) and b (upstream failure) must retain liability.
        assert result.get_liability("c") > 0.0
        assert result.get_liability("b") > 0.0

    def test_full_risk_weights_override_causal(self):
        """Full-coverage weights override the causal split (BUGS.md contract):
        a gets 0.5 even though its action succeeded (causal contribution 0)."""
        actions = {
            "a": [{"action_id": "a1", "step_id": "s1", "success": True}],
            "b": [{"action_id": "b1", "step_id": "s2", "success": False}],
        }
        result = CausalAttributor().attribute(
            "sg", "ss", actions, "s2", "b", risk_weights={"a": 0.5, "b": 0.5}
        )
        assert abs(result.get_liability("a") - 0.5) < 1e-9
        assert abs(result.get_liability("b") - 0.5) < 1e-9


# ── Quarantine Enforcement (BUG 1 fix) ──────────────────────────


class TestQuarantineEnforcement:
    def test_quarantine_is_recorded_and_enforced(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("did:bad", "s", QuarantineReason.RING_BREACH)
        assert record.is_active
        assert mgr.is_quarantined("did:bad", "s")
        assert mgr.quarantine_count == 1
        assert record in mgr.active_quarantines
        assert mgr.get_active_quarantine("did:bad", "s") is record

    def test_unrelated_agent_not_quarantined(self):
        mgr = QuarantineManager()
        mgr.quarantine("did:bad", "s", QuarantineReason.MANUAL)
        assert not mgr.is_quarantined("did:other", "s")
        assert not mgr.is_quarantined("did:bad", "other-session")

    def test_release_clears_quarantine(self):
        mgr = QuarantineManager()
        mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        released = mgr.release("a1", "s1")
        assert released is not None
        assert not released.is_active
        assert released.released_at is not None
        assert not mgr.is_quarantined("a1", "s1")
        assert mgr.quarantine_count == 0

    def test_release_unknown_returns_none(self):
        mgr = QuarantineManager()
        assert mgr.release("nobody", "s1") is None

    def test_default_expiry_applied(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        assert record.expires_at is not None
        delta = (record.expires_at - record.entered_at).total_seconds()
        assert abs(delta - QuarantineManager.DEFAULT_QUARANTINE_SECONDS) < 1.0

    def test_custom_duration(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL, duration_seconds=42)
        delta = (record.expires_at - record.entered_at).total_seconds()
        assert abs(delta - 42) < 1.0

    def test_tick_expires_quarantine(self):
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL, duration_seconds=100)
        assert mgr.is_quarantined("a1", "s1")
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        # Expiry is observed lazily before tick...
        assert not mgr.is_quarantined("a1", "s1")
        expired = mgr.tick()
        assert record in expired
        assert not record.is_active
        assert mgr.quarantine_count == 0

    def test_forensic_data_persisted(self):
        mgr = QuarantineManager()
        record = mgr.quarantine(
            "a1", "s1", QuarantineReason.CASCADE_SLASH, forensic_data={"score": 0.9}
        )
        assert record.forensic_data == {"score": 0.9}

    def test_requarantine_supersedes_prior_active(self):
        """Re-quarantining the same (agent, session) supersedes the prior active
        record, so there is at most one active quarantine per key; history is
        retained, and a single release() fully clears it."""
        mgr = QuarantineManager()
        first = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL)
        second = mgr.quarantine("a1", "s1", QuarantineReason.RING_BREACH)
        assert mgr.quarantine_count == 1
        assert not first.is_active
        assert second.is_active
        assert mgr.get_active_quarantine("a1", "s1") is second
        assert len(mgr.get_history(agent_did="a1")) == 2  # both retained
        released = mgr.release("a1", "s1")
        assert released is second
        assert not mgr.is_quarantined("a1", "s1")
        assert mgr.quarantine_count == 0

    def test_release_does_not_touch_expired_records(self):
        """Regression: release() must not 'release' an already-expired record
        (is_quarantined already reports False); doing so would stamp a late
        released_at and overstate duration_seconds vs tick()'s expires_at clamp."""
        mgr = QuarantineManager()
        record = mgr.quarantine("a1", "s1", QuarantineReason.MANUAL, duration_seconds=100)
        record.entered_at = datetime.now(UTC) - timedelta(seconds=50)
        record.expires_at = datetime.now(UTC) - timedelta(seconds=10)
        assert not mgr.is_quarantined("a1", "s1")
        assert mgr.release("a1", "s1") is None
        assert record.released_at is None
