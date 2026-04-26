# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Reputation Engine."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.reputation import ReputationEngine, ReputationHistory, TrustScore, TrustTier, SlashEvent


class TestTrustTier:
    """Tests for TrustScore.get_tier() classmethod."""

    def test_verified_partner_at_900(self):
        assert TrustScore.get_tier(900) == TrustTier.VERIFIED_PARTNER

    def test_verified_partner_at_1000(self):
        assert TrustScore.get_tier(1000) == TrustTier.VERIFIED_PARTNER

    def test_trusted_at_700(self):
        assert TrustScore.get_tier(700) == TrustTier.TRUSTED

    def test_trusted_at_899(self):
        assert TrustScore.get_tier(899) == TrustTier.TRUSTED

    def test_standard_at_500(self):
        assert TrustScore.get_tier(500) == TrustTier.STANDARD

    def test_standard_at_699(self):
        assert TrustScore.get_tier(699) == TrustTier.STANDARD

    def test_probationary_at_300(self):
        assert TrustScore.get_tier(300) == TrustTier.PROBATIONARY

    def test_probationary_at_499(self):
        assert TrustScore.get_tier(499) == TrustTier.PROBATIONARY

    def test_untrusted_at_299(self):
        assert TrustScore.get_tier(299) == TrustTier.UNTRUSTED

    def test_untrusted_at_zero(self):
        assert TrustScore.get_tier(0) == TrustTier.UNTRUSTED


class TestTrustScoreMeetsThreshold:
    """Tests for TrustScore.meets_threshold()."""

    def test_meets_when_equal(self):
        ts = TrustScore(
            agent_did="did:nexus:a", total_score=500, tier=TrustTier.STANDARD,
            base_score=400, behavioral_modifier=100, capability_modifier=0,
        )
        assert ts.meets_threshold(500) is True

    def test_meets_when_above(self):
        ts = TrustScore(
            agent_did="did:nexus:a", total_score=700, tier=TrustTier.TRUSTED,
            base_score=600, behavioral_modifier=100, capability_modifier=0,
        )
        assert ts.meets_threshold(500) is True

    def test_fails_when_below(self):
        ts = TrustScore(
            agent_did="did:nexus:a", total_score=300, tier=TrustTier.PROBATIONARY,
            base_score=300, behavioral_modifier=0, capability_modifier=0,
        )
        assert ts.meets_threshold(500) is False


class TestReputationHistory:
    """Tests for ReputationHistory properties."""

    def test_success_rate_with_tasks(self):
        h = ReputationHistory(
            agent_did="did:nexus:a", successful_tasks=8, failed_tasks=2, total_tasks=10,
        )
        assert h.success_rate == pytest.approx(0.8)

    def test_success_rate_no_tasks(self):
        h = ReputationHistory(agent_did="did:nexus:a")
        assert h.success_rate == 0.0

    def test_dispute_win_rate_with_disputes(self):
        h = ReputationHistory(
            agent_did="did:nexus:a", disputes_won=3, disputes_lost=1,
        )
        assert h.dispute_win_rate == pytest.approx(0.75)

    def test_dispute_win_rate_no_disputes(self):
        h = ReputationHistory(agent_did="did:nexus:a")
        assert h.dispute_win_rate == 0.5  # neutral default


class TestCalculateTrustScore:
    """Tests for ReputationEngine.calculate_trust_score()."""

    def test_unknown_verification_gives_low_base(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score("unknown", history)
        assert score.base_score == 100

    def test_registered_verification(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score("registered", history)
        assert score.base_score == 400

    def test_verified_verification(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score("verified", history)
        assert score.base_score == 650

    def test_verified_partner_verification(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score("verified_partner", history)
        assert score.base_score == 800

    def test_successful_tasks_increase_score(self, reputation_engine):
        history = ReputationHistory(
            agent_did="did:nexus:a", successful_tasks=50, total_tasks=50,
        )
        score = reputation_engine.calculate_trust_score("registered", history)
        assert score.behavioral_modifier > 0

    def test_failed_tasks_decrease_score(self, reputation_engine):
        history = ReputationHistory(
            agent_did="did:nexus:a", failed_tasks=10, total_tasks=10,
        )
        score = reputation_engine.calculate_trust_score("registered", history)
        assert score.behavioral_modifier < 0

    def test_disputes_lost_reduce_score(self, reputation_engine):
        history = ReputationHistory(
            agent_did="did:nexus:a", disputes_lost=3,
        )
        score = reputation_engine.calculate_trust_score("registered", history)
        assert score.behavioral_modifier < 0

    def test_capability_modifier_idempotency(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score(
            "registered", history, capabilities={"idempotency": True},
        )
        assert score.capability_modifier >= 20

    def test_capability_modifier_reversibility_full(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score(
            "registered", history, capabilities={"reversibility": "full"},
        )
        assert score.capability_modifier >= 50

    def test_privacy_ephemeral_boost(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score(
            "registered", history, privacy={"retention_policy": "ephemeral"},
        )
        assert score.capability_modifier >= 30

    def test_score_clamped_to_0_1000(self, reputation_engine):
        # Very bad history
        history = ReputationHistory(
            agent_did="did:nexus:a", failed_tasks=100, total_tasks=100,
            disputes_lost=10, times_slashed=10,
        )
        score = reputation_engine.calculate_trust_score("unknown", history)
        assert 0 <= score.total_score <= 1000

    def test_score_has_correct_tier(self, reputation_engine):
        history = ReputationHistory(agent_did="did:nexus:a")
        score = reputation_engine.calculate_trust_score("verified_partner", history)
        assert score.tier == TrustScore.get_tier(score.total_score)


class TestRecordTaskOutcome:
    """Tests for ReputationEngine.record_task_outcome()."""

    def test_success_increments(self, reputation_engine):
        h = reputation_engine.record_task_outcome("did:nexus:a", "success")
        assert h.successful_tasks == 1
        assert h.total_tasks == 1

    def test_failure_increments(self, reputation_engine):
        h = reputation_engine.record_task_outcome("did:nexus:a", "failure")
        assert h.failed_tasks == 1
        assert h.total_tasks == 1

    def test_partial_increments_both(self, reputation_engine):
        h = reputation_engine.record_task_outcome("did:nexus:a", "partial")
        assert h.successful_tasks == 0.5
        assert h.failed_tasks == 0.5
        assert h.total_tasks == 1

    def test_multiple_outcomes_accumulate(self, reputation_engine):
        reputation_engine.record_task_outcome("did:nexus:a", "success")
        reputation_engine.record_task_outcome("did:nexus:a", "success")
        h = reputation_engine.record_task_outcome("did:nexus:a", "failure")
        assert h.successful_tasks == 2
        assert h.failed_tasks == 1
        assert h.total_tasks == 3


class TestRecordDisputeOutcome:
    """Tests for ReputationEngine.record_dispute_outcome()."""

    def test_won_increments(self, reputation_engine):
        h = reputation_engine.record_dispute_outcome("did:nexus:a", "won")
        assert h.disputes_won == 1

    def test_lost_increments(self, reputation_engine):
        h = reputation_engine.record_dispute_outcome("did:nexus:a", "lost")
        assert h.disputes_lost == 1


class TestSlashReputation:
    """Tests for ReputationEngine.slash_reputation()."""

    def test_critical_slash_penalty(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="fraud", severity="critical",
        )
        assert event.score_reduction == 200

    def test_high_slash_penalty(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="hallucination", severity="high",
        )
        assert event.score_reduction == 100

    def test_medium_slash_penalty(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="timeout", severity="medium",
        )
        assert event.score_reduction == 50

    def test_low_slash_penalty(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="policy_violation", severity="low",
        )
        assert event.score_reduction == 25

    def test_slash_updates_history(self, reputation_engine):
        reputation_engine.slash_reputation("did:nexus:a", reason="fraud", severity="critical")
        h = reputation_engine._get_or_create_history("did:nexus:a")
        assert h.times_slashed == 1
        assert h.total_slash_amount == 200

    def test_slash_with_evidence(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="fraud", severity="high",
            evidence_hash="ev_hash_123", trace_id="trace_456",
        )
        assert event.evidence_hash == "ev_hash_123"
        assert event.trace_id == "trace_456"

    def test_slash_broadcast_flag(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="fraud", severity="high", broadcast=False,
        )
        assert event.broadcast_to_network is False
        assert event.broadcast_at is None

    def test_slash_score_after_not_negative(self, reputation_engine):
        event = reputation_engine.slash_reputation(
            "did:nexus:a", reason="fraud", severity="critical",
        )
        assert event.score_after >= 0


class TestCheckTrustThreshold:
    """Tests for ReputationEngine.check_trust_threshold()."""

    def test_new_agent_below_default_threshold(self, reputation_engine):
        meets, score = reputation_engine.check_trust_threshold("did:nexus:new")
        assert score.total_score == 400  # registered base
        assert meets is False  # 400 < 500

    def test_custom_threshold(self, reputation_engine):
        meets, score = reputation_engine.check_trust_threshold("did:nexus:a", required_score=300)
        assert meets is True  # 400 >= 300


class TestLeaderboard:
    """Tests for ReputationEngine.get_leaderboard()."""

    def test_empty_leaderboard(self, reputation_engine):
        assert reputation_engine.get_leaderboard() == []

    def test_leaderboard_sorted_descending(self, reputation_engine):
        # Populate cache via check_trust_threshold
        reputation_engine.check_trust_threshold("did:nexus:a")
        reputation_engine.check_trust_threshold("did:nexus:b")
        board = reputation_engine.get_leaderboard()
        assert len(board) == 2
        for i in range(len(board) - 1):
            assert board[i].total_score >= board[i + 1].total_score

    def test_leaderboard_limit(self, reputation_engine):
        for i in range(5):
            reputation_engine.check_trust_threshold(f"did:nexus:agent-{i}")
        board = reputation_engine.get_leaderboard(limit=3)
        assert len(board) == 3


class TestSlashHistory:
    """Tests for ReputationEngine.get_slash_history()."""

    def test_empty_history(self, reputation_engine):
        assert reputation_engine.get_slash_history() == []

    def test_filter_by_agent(self, reputation_engine):
        reputation_engine.slash_reputation("did:nexus:a", reason="fraud", severity="high")
        reputation_engine.slash_reputation("did:nexus:b", reason="timeout", severity="low")
        events = reputation_engine.get_slash_history(agent_did="did:nexus:a")
        assert len(events) == 1
        assert events[0].agent_did == "did:nexus:a"

    def test_filter_by_since(self, reputation_engine):
        reputation_engine.slash_reputation("did:nexus:a", reason="fraud", severity="high")
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        events = reputation_engine.get_slash_history(since=future)
        assert len(events) == 0
