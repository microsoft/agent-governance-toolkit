# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the template AgentMesh trust integration.

These tests run without any target framework SDK installed. They validate
the governance logic in isolation — the same pattern used by crewai-agentmesh,
openai-agents-agentmesh, and langchain-agentmesh.
"""

from template_agentmesh import AgentProfile, ActionGuard, ActionResult, TrustTracker


# ── AgentProfile ──


class TestAgentProfile:
    def test_has_capability(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", capabilities=["read", "write"])
        assert agent.has_capability("read")
        assert not agent.has_capability("delete")

    def test_has_all_capabilities(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", capabilities=["read", "write"])
        assert agent.has_all_capabilities(["read", "write"])
        assert not agent.has_all_capabilities(["read", "delete"])

    def test_has_any_capability(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", capabilities=["read"])
        assert agent.has_any_capability(["read", "write"])
        assert not agent.has_any_capability(["delete", "admin"])

    def test_default_values(self):
        agent = AgentProfile(did="did:mesh:a1", name="A")
        assert agent.trust_score == 500
        assert agent.status == "active"
        assert agent.capabilities == []
        assert agent.metadata == {}


# ── ActionGuard ──


class TestActionGuard:
    def test_allow_above_threshold(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=700)
        guard = ActionGuard(min_trust_score=500)
        result = guard.check(agent, "search")
        assert result.allowed
        assert result.agent_did == "did:mesh:a1"
        assert result.action == "search"
        assert result.trust_score == 700

    def test_block_below_threshold(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=300)
        guard = ActionGuard(min_trust_score=500)
        result = guard.check(agent, "search")
        assert not result.allowed
        assert "below threshold" in result.reason

    def test_sensitive_action_elevated_threshold(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=600)
        guard = ActionGuard(
            min_trust_score=500,
            sensitive_actions={"delete_record": 800},
        )
        assert guard.check(agent, "search").allowed
        assert not guard.check(agent, "delete_record").allowed

    def test_blocked_action_always_denied(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=1000)
        guard = ActionGuard(blocked_actions=["drop_table"])
        result = guard.check(agent, "drop_table")
        assert not result.allowed
        assert "blocked by policy" in result.reason

    def test_suspended_agent_denied(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=900, status="suspended")
        guard = ActionGuard(min_trust_score=500)
        result = guard.check(agent, "search")
        assert not result.allowed
        assert "suspended" in result.reason

    def test_revoked_agent_denied(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=900, status="revoked")
        guard = ActionGuard(min_trust_score=500)
        result = guard.check(agent, "search")
        assert not result.allowed
        assert "revoked" in result.reason

    def test_capability_required_and_present(self):
        agent = AgentProfile(
            did="did:mesh:a1", name="A",
            capabilities=["read", "write"], trust_score=700,
        )
        guard = ActionGuard(min_trust_score=500)
        assert guard.check(agent, "query", required_capabilities=["read"]).allowed

    def test_capability_required_but_missing(self):
        agent = AgentProfile(
            did="did:mesh:a1", name="A",
            capabilities=["read"], trust_score=700,
        )
        guard = ActionGuard(min_trust_score=500)
        result = guard.check(agent, "query", required_capabilities=["write"])
        assert not result.allowed
        assert "Missing capabilities" in result.reason
        assert "write" in result.reason

    def test_no_capabilities_required(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=700)
        guard = ActionGuard(min_trust_score=500)
        assert guard.check(agent, "search").allowed

    def test_exact_threshold_allowed(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        guard = ActionGuard(min_trust_score=500)
        assert guard.check(agent, "search").allowed

    def test_one_below_threshold_denied(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=499)
        guard = ActionGuard(min_trust_score=500)
        assert not guard.check(agent, "search").allowed

    def test_check_order_blocked_before_status(self):
        """Blocked actions are checked before status."""
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=900, status="suspended")
        guard = ActionGuard(min_trust_score=500, blocked_actions=["danger"])
        result = guard.check(agent, "danger")
        assert "blocked by policy" in result.reason  # not "suspended"

    def test_default_guard_values(self):
        guard = ActionGuard()
        assert guard.min_trust_score == 500
        assert guard.sensitive_actions == {}
        assert guard.blocked_actions == []


# ── TrustTracker ──


class TestTrustTracker:
    def test_record_success_increases_score(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        tracker = TrustTracker(reward=10, penalty=50)
        new_score = tracker.record_success(agent, "search")
        assert new_score == 510
        assert agent.trust_score == 510

    def test_record_failure_decreases_score(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        tracker = TrustTracker(reward=10, penalty=50)
        new_score = tracker.record_failure(agent, "search")
        assert new_score == 450
        assert agent.trust_score == 450

    def test_score_clamped_at_max(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=995)
        tracker = TrustTracker(reward=10)
        tracker.record_success(agent, "search")
        assert agent.trust_score == 1000

    def test_score_clamped_at_min(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=20)
        tracker = TrustTracker(penalty=50)
        tracker.record_failure(agent, "search")
        assert agent.trust_score == 0

    def test_history_records_all_events(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        tracker = TrustTracker(reward=10, penalty=50)
        tracker.record_success(agent, "search")
        tracker.record_failure(agent, "deploy")

        history = tracker.get_history()
        assert len(history) == 2
        assert history[0]["outcome"] == "success"
        assert history[0]["action"] == "search"
        assert history[1]["outcome"] == "failure"
        assert history[1]["action"] == "deploy"

    def test_history_filtered_by_did(self):
        a1 = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        a2 = AgentProfile(did="did:mesh:a2", name="B", trust_score=500)
        tracker = TrustTracker()
        tracker.record_success(a1, "search")
        tracker.record_success(a2, "search")
        tracker.record_failure(a1, "deploy")

        a1_history = tracker.get_history("did:mesh:a1")
        assert len(a1_history) == 2

        a2_history = tracker.get_history("did:mesh:a2")
        assert len(a2_history) == 1

    def test_history_records_timestamps(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        tracker = TrustTracker()
        tracker.record_success(agent, "search")
        history = tracker.get_history()
        assert "timestamp" in history[0]
        assert isinstance(history[0]["timestamp"], float)

    def test_history_records_new_score(self):
        agent = AgentProfile(did="did:mesh:a1", name="A", trust_score=500)
        tracker = TrustTracker(reward=10)
        tracker.record_success(agent, "search")
        assert tracker.get_history()[0]["new_score"] == 510


# ── ActionResult ──


class TestActionResult:
    def test_to_dict(self):
        result = ActionResult(
            allowed=True,
            agent_did="did:mesh:a1",
            action="search",
            trust_score=700,
        )
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["agent_did"] == "did:mesh:a1"
        assert d["action"] == "search"
        assert d["trust_score"] == 700
        assert "timestamp" in d

    def test_denied_result_includes_reason(self):
        result = ActionResult(
            allowed=False,
            agent_did="did:mesh:a1",
            action="delete",
            reason="Trust too low",
            trust_score=300,
        )
        d = result.to_dict()
        assert d["allowed"] is False
        assert d["reason"] == "Trust too low"

    def test_default_values(self):
        result = ActionResult(allowed=True, agent_did="did:mesh:a1", action="x")
        assert result.reason == ""
        assert result.trust_score == 0
        assert isinstance(result.timestamp, float)


# ── Integration: Full Lifecycle ──


class TestFullLifecycle:
    """End-to-end test: create agents, gate actions, track outcomes."""

    def test_complete_workflow(self):
        # Set up agents
        researcher = AgentProfile(
            did="did:mesh:researcher",
            name="Researcher",
            capabilities=["search", "analyze"],
            trust_score=700,
        )
        writer = AgentProfile(
            did="did:mesh:writer",
            name="Writer",
            capabilities=["write", "edit"],
            trust_score=600,
        )

        # Set up guard
        guard = ActionGuard(
            min_trust_score=500,
            sensitive_actions={"publish": 800},
            blocked_actions=["delete_all"],
        )

        # Researcher can search
        assert guard.check(researcher, "search", ["search"]).allowed

        # Writer cannot publish (trust 600 < 800)
        result = guard.check(writer, "publish")
        assert not result.allowed

        # Track outcomes
        tracker = TrustTracker(reward=10, penalty=50)
        tracker.record_success(researcher, "search")
        tracker.record_success(writer, "write")
        tracker.record_success(writer, "write")

        # Writer's trust increased: 600 + 10 + 10 = 620
        assert writer.trust_score == 620

        # Still cannot publish (620 < 800)
        assert not guard.check(writer, "publish").allowed

        # Blocked action denied even with max trust
        researcher.trust_score = 1000
        assert not guard.check(researcher, "delete_all").allowed
