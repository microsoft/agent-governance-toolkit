"""Tests for langgraph_trust.gate — TrustGate and TrustScoreTracker."""

import threading

from langgraph_trust.gate import TrustGate, TrustScoreTracker
from langgraph_trust.identity import AgentIdentityManager
from langgraph_trust.state import TrustVerdict


# ── TrustScoreTracker ──────────────────────────────────────────────────


class TestTrustScoreTracker:
    def test_default_score(self):
        tracker = TrustScoreTracker(default_score=0.6)
        assert tracker.get_score("alice") == 0.6

    def test_record_success_increases(self):
        tracker = TrustScoreTracker()
        score = tracker.record_success("alice", delta=0.05)
        assert score == 0.55

    def test_record_failure_decreases(self):
        tracker = TrustScoreTracker()
        score = tracker.record_failure("alice", severity=0.2)
        assert score == 0.3

    def test_score_capped_at_1(self):
        tracker = TrustScoreTracker(default_score=0.99)
        score = tracker.record_success("alice", delta=0.1)
        assert score == 1.0

    def test_score_floored_at_0(self):
        tracker = TrustScoreTracker(default_score=0.05)
        score = tracker.record_failure("alice", severity=0.5)
        assert score == 0.0

    def test_set_score(self):
        tracker = TrustScoreTracker()
        tracker.set_score("bob", 0.9)
        assert tracker.get_score("bob") == 0.9

    def test_history_recorded(self):
        tracker = TrustScoreTracker()
        tracker.record_success("alice")
        tracker.record_failure("alice", severity=0.05)
        assert len(tracker.history) == 2
        assert tracker.history[0]["action"] == "success"
        assert tracker.history[1]["action"] == "failure"

    def test_thread_safety(self):
        tracker = TrustScoreTracker()
        errors = []

        def bump():
            try:
                for _ in range(100):
                    tracker.record_success("shared")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=bump) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert tracker.get_score("shared") <= 1.0

    def test_multiple_agents_independent(self):
        tracker = TrustScoreTracker()
        tracker.record_success("alice")
        tracker.record_failure("bob", severity=0.3)
        assert tracker.get_score("alice") == 0.51
        assert tracker.get_score("bob") == 0.2


# ── TrustGate ──────────────────────────────────────────────────────────


class TestTrustGate:
    def test_pass_above_threshold(self):
        tracker = TrustScoreTracker()
        tracker.set_score("agent-a", 0.8)
        gate = TrustGate(min_score=0.5, tracker=tracker, agent_name="agent-a")
        result = gate({})
        assert result["trust_result"]["verdict"] == "pass"
        assert result["trust_result"]["score"] == 0.8

    def test_fail_below_threshold(self):
        tracker = TrustScoreTracker()
        tracker.set_score("agent-a", 0.3)
        gate = TrustGate(min_score=0.5, tracker=tracker, agent_name="agent-a")
        result = gate({})
        assert result["trust_result"]["verdict"] == "fail"
        assert "below minimum" in result["trust_result"]["reason"]

    def test_agent_from_state(self):
        tracker = TrustScoreTracker()
        tracker.set_score("dynamic-agent", 0.9)
        gate = TrustGate(min_score=0.5, tracker=tracker)
        result = gate({"trust_agent": "dynamic-agent"})
        assert result["trust_result"]["verdict"] == "pass"

    def test_review_threshold(self):
        tracker = TrustScoreTracker()
        tracker.set_score("agent-b", 0.65)
        gate = TrustGate(
            min_score=0.5, review_threshold=0.7,
            tracker=tracker, agent_name="agent-b",
        )
        result = gate({})
        assert result["trust_result"]["verdict"] == "review"

    def test_capability_check_pass(self):
        tracker = TrustScoreTracker()
        tracker.set_score("agent-c", 0.9)
        idm = AgentIdentityManager()
        idm.create_identity("agent-c", capabilities=["summarize", "translate"])
        gate = TrustGate(
            min_score=0.5, tracker=tracker,
            identity_manager=idm, agent_name="agent-c",
            required_capabilities=["summarize"],
        )
        result = gate({})
        assert result["trust_result"]["verdict"] == "pass"

    def test_capability_check_fail(self):
        tracker = TrustScoreTracker()
        tracker.set_score("agent-c", 0.9)
        idm = AgentIdentityManager()
        idm.create_identity("agent-c", capabilities=["summarize"])
        gate = TrustGate(
            min_score=0.5, tracker=tracker,
            identity_manager=idm, agent_name="agent-c",
            required_capabilities=["code_exec"],
        )
        result = gate({})
        assert result["trust_result"]["verdict"] == "fail"
        assert "code_exec" in result["trust_result"]["policy_violations"]

    def test_missing_identity_fails(self):
        tracker = TrustScoreTracker()
        idm = AgentIdentityManager()
        gate = TrustGate(
            min_score=0.5, tracker=tracker,
            identity_manager=idm, agent_name="ghost",
            required_capabilities=["anything"],
        )
        result = gate({})
        assert result["trust_result"]["verdict"] == "fail"
        assert "identity_missing" in result["trust_result"]["policy_violations"]

    def test_wildcard_capability(self):
        tracker = TrustScoreTracker()
        tracker.set_score("admin", 0.9)
        idm = AgentIdentityManager()
        idm.create_identity("admin", capabilities=["*"])
        gate = TrustGate(
            min_score=0.5, tracker=tracker,
            identity_manager=idm, agent_name="admin",
            required_capabilities=["anything", "everything"],
        )
        result = gate({})
        assert result["trust_result"]["verdict"] == "pass"

    def test_default_tracker_created(self):
        gate = TrustGate(min_score=0.5, agent_name="test")
        result = gate({})
        # Default score 0.5 == min_score → should pass
        assert result["trust_result"]["verdict"] == "pass"
