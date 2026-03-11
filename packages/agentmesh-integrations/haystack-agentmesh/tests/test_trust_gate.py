"""Tests for TrustGate component."""

import time

import pytest

from haystack_agentmesh.trust_gate import AgentTrustRecord, TrustGate


class TestTrustGate:

    def test_default_score_is_review(self):
        """A brand-new agent with default score 0.5 lands in review zone."""
        gate = TrustGate()
        result = gate.run(agent_id="new-agent")
        assert result["action"] == "review"
        assert result["trusted"] is False
        assert 0.0 <= result["score"] <= 1.0

    def test_high_trust_passes(self):
        gate = TrustGate()
        # Boost score above pass_threshold (0.7)
        for _ in range(5):
            gate.record_success("agent-a")
        result = gate.run(agent_id="agent-a")
        assert result["action"] == "pass"
        assert result["trusted"] is True

    def test_low_trust_blocks(self):
        gate = TrustGate()
        # Penalise below review_threshold (0.4)
        for _ in range(3):
            gate.record_failure("agent-b")
        result = gate.run(agent_id="agent-b")
        assert result["action"] == "block"
        assert result["trusted"] is False

    def test_record_success_increases_score(self):
        gate = TrustGate(reward=0.1)
        initial = gate.get_score("a")
        gate.record_success("a")
        assert gate.get_score("a") == pytest.approx(initial + 0.1)

    def test_record_failure_decreases_score(self):
        gate = TrustGate(penalty=0.1)
        initial = gate.get_score("a")
        gate.record_failure("a")
        assert gate.get_score("a") == pytest.approx(initial - 0.1)

    def test_score_clamped_at_one(self):
        gate = TrustGate(reward=0.9)
        gate.record_success("a")
        gate.record_success("a")
        assert gate.get_score("a") <= 1.0

    def test_score_clamped_at_zero(self):
        gate = TrustGate(penalty=0.9)
        gate.record_failure("a")
        gate.record_failure("a")
        assert gate.get_score("a") >= 0.0

    def test_decay_reduces_score(self):
        gate = TrustGate(decay_rate=0.5)
        rec = gate._get_record("a")
        rec.last_update = time.time() - 7200  # 2 hours ago
        gate.apply_decay("a")
        assert gate.get_score("a") < 0.5

    def test_custom_min_score_override(self):
        gate = TrustGate()
        # Default score 0.5 should pass if min_score is set to 0.3
        result = gate.run(agent_id="c", min_score=0.3)
        assert result["action"] == "pass"
        assert result["trusted"] is True

    def test_independent_agent_scores(self):
        gate = TrustGate()
        gate.record_success("x")
        gate.record_failure("y")
        assert gate.get_score("x") > gate.get_score("y")
