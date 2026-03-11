"""
Tests for CrewAI AgentMesh trust integration.

No real CrewAI dependency — tests the trust layer directly.
"""

import pytest

from crewai_agentmesh import (
    AgentProfile,
    CapabilityGate,
    TaskAssignment,
    TrustedCrew,
    TrustTracker,
)


# =============================================================================
# AgentProfile
# =============================================================================


class TestAgentProfile:
    def test_basic(self):
        a = AgentProfile(did="did:mesh:a", name="Alice")
        assert a.did == "did:mesh:a"
        assert a.trust_score == 500
        assert a.is_active

    def test_capabilities(self):
        a = AgentProfile(did="d", name="A", capabilities=["search", "write"])
        assert a.has_capability("search")
        assert not a.has_capability("admin")
        assert a.has_all_capabilities(["search", "write"])
        assert not a.has_all_capabilities(["search", "admin"])
        assert a.has_any_capability(["admin", "write"])
        assert not a.has_any_capability(["admin", "exec"])

    def test_status(self):
        a = AgentProfile(did="d", name="A", status="suspended")
        assert not a.is_active

    def test_to_dict(self):
        a = AgentProfile(did="d", name="A", trust_score=800, role="researcher")
        d = a.to_dict()
        assert d["did"] == "d"
        assert d["trust_score"] == 800
        assert d["role"] == "researcher"


# =============================================================================
# CapabilityGate
# =============================================================================


class TestCapabilityGate:
    def test_no_requirements(self):
        g = CapabilityGate()
        a = AgentProfile(did="d", name="A")
        ok, _ = g.check(a, [])
        assert ok

    def test_all_required_present(self):
        g = CapabilityGate(require_all=True)
        a = AgentProfile(did="d", name="A", capabilities=["search", "write"])
        ok, _ = g.check(a, ["search", "write"])
        assert ok

    def test_missing_capability(self):
        g = CapabilityGate(require_all=True)
        a = AgentProfile(did="d", name="A", capabilities=["search"])
        ok, reason = g.check(a, ["search", "admin"])
        assert not ok
        assert "Missing" in reason

    def test_any_mode(self):
        g = CapabilityGate(require_all=False)
        a = AgentProfile(did="d", name="A", capabilities=["search"])
        ok, _ = g.check(a, ["admin", "search"])
        assert ok

    def test_any_mode_none_match(self):
        g = CapabilityGate(require_all=False)
        a = AgentProfile(did="d", name="A", capabilities=["search"])
        ok, _ = g.check(a, ["admin", "exec"])
        assert not ok

    def test_inactive_agent(self):
        g = CapabilityGate()
        a = AgentProfile(did="d", name="A", capabilities=["search"], status="revoked")
        ok, reason = g.check(a, ["search"])
        assert not ok
        assert "revoked" in reason


# =============================================================================
# TrustTracker
# =============================================================================


class TestTrustTracker:
    def test_success_reward(self):
        t = TrustTracker(success_reward=20)
        a = AgentProfile(did="d", name="A", trust_score=500)
        new_score = t.record_success(a, "task1")
        assert new_score == 520
        assert a.trust_score == 520

    def test_failure_penalty(self):
        t = TrustTracker(failure_penalty=100)
        a = AgentProfile(did="d", name="A", trust_score=500)
        new_score = t.record_failure(a, "task1", "timeout")
        assert new_score == 400
        assert a.trust_score == 400

    def test_min_score(self):
        t = TrustTracker(failure_penalty=200, min_score=0)
        a = AgentProfile(did="d", name="A", trust_score=100)
        t.record_failure(a)
        assert a.trust_score == 0

    def test_max_score(self):
        t = TrustTracker(success_reward=50, max_score=1000)
        a = AgentProfile(did="d", name="A", trust_score=980)
        t.record_success(a)
        assert a.trust_score == 1000

    def test_history(self):
        t = TrustTracker()
        a = AgentProfile(did="d1", name="A")
        b = AgentProfile(did="d2", name="B")
        t.record_success(a)
        t.record_failure(b)
        assert len(t.get_history()) == 2
        assert len(t.get_history(did="d1")) == 1
        assert t.get_history(did="d1")[0]["event"] == "success"


# =============================================================================
# TrustedCrew
# =============================================================================


class TestTrustedCrew:
    def _make_crew(self):
        agents = [
            AgentProfile(did="d1", name="Researcher", capabilities=["research", "analysis"], trust_score=800),
            AgentProfile(did="d2", name="Writer", capabilities=["writing", "editing"], trust_score=700),
            AgentProfile(did="d3", name="Coder", capabilities=["coding", "testing"], trust_score=300),
            AgentProfile(did="d4", name="Suspended", capabilities=["research"], trust_score=900, status="suspended"),
        ]
        return TrustedCrew(agents=agents, min_trust_score=500)

    def test_agents_property(self):
        crew = self._make_crew()
        assert len(crew.agents) == 4

    def test_active_agents(self):
        crew = self._make_crew()
        assert len(crew.active_agents) == 3

    def test_trusted_agents(self):
        crew = self._make_crew()
        assert len(crew.trusted_agents) == 2  # Researcher + Writer (Coder too low, Suspended inactive)

    def test_select_by_capability(self):
        crew = self._make_crew()
        selected = crew.select_for_task(required_capabilities=["research"])
        assert len(selected) == 1
        assert selected[0].name == "Researcher"

    def test_select_by_trust(self):
        crew = self._make_crew()
        selected = crew.select_for_task(min_trust=600)
        assert len(selected) == 2  # Researcher (800) + Writer (700)

    def test_select_sorted_by_trust(self):
        crew = self._make_crew()
        selected = crew.select_for_task()
        assert selected[0].trust_score >= selected[-1].trust_score

    def test_select_no_match(self):
        crew = self._make_crew()
        selected = crew.select_for_task(required_capabilities=["admin"])
        assert len(selected) == 0

    def test_select_excludes_low_trust(self):
        crew = self._make_crew()
        selected = crew.select_for_task(required_capabilities=["coding"])
        assert len(selected) == 0  # Coder has trust 300, min is 500

    def test_select_excludes_suspended(self):
        crew = self._make_crew()
        selected = crew.select_for_task(required_capabilities=["research"], min_trust=0)
        # Researcher (active, 800) matches. Suspended (900) is inactive.
        assert len(selected) == 1
        assert selected[0].name == "Researcher"

    def test_assign_task_allowed(self):
        crew = self._make_crew()
        a = crew.assign_task("d1", "Analyze data", ["research"])
        assert a.allowed
        assert a.trust_sufficient
        assert a.capability_match

    def test_assign_task_low_trust(self):
        crew = self._make_crew()
        a = crew.assign_task("d3", "Write code", ["coding"])
        assert not a.allowed
        assert not a.trust_sufficient
        assert "Trust score" in a.reason

    def test_assign_task_missing_capability(self):
        crew = self._make_crew()
        a = crew.assign_task("d1", "Write code", ["coding"])
        assert not a.allowed
        assert not a.capability_match

    def test_assign_task_unknown_agent(self):
        crew = self._make_crew()
        a = crew.assign_task("did:mesh:unknown", "Task")
        assert not a.allowed
        assert "not found" in a.reason

    def test_add_remove_agent(self):
        crew = TrustedCrew()
        crew.add_agent(AgentProfile(did="d1", name="A"))
        assert len(crew.agents) == 1
        assert crew.remove_agent("d1")
        assert len(crew.agents) == 0
        assert not crew.remove_agent("d1")  # not found

    def test_get_agent(self):
        crew = self._make_crew()
        a = crew.get_agent("d1")
        assert a is not None
        assert a.name == "Researcher"
        assert crew.get_agent("nonexistent") is None

    def test_record_task_result(self):
        crew = self._make_crew()
        new_score = crew.record_task_result("d1", success=True, task_description="analysis")
        assert new_score is not None
        assert new_score > 800  # Rewarded

        new_score = crew.record_task_result("d2", success=False, task_description="writing", reason="timeout")
        assert new_score is not None
        assert new_score < 700  # Penalized

        assert crew.record_task_result("nonexistent", success=True) is None

    def test_stats(self):
        crew = self._make_crew()
        crew.assign_task("d1", "Task 1", ["research"])
        crew.assign_task("d3", "Task 2", ["coding"])  # denied (low trust)
        stats = crew.get_stats()
        assert stats["total_agents"] == 4
        assert stats["active_agents"] == 3
        assert stats["trusted_agents"] == 2
        assert stats["total_assignments"] == 2
        assert stats["allowed_assignments"] == 1
        assert stats["denied_assignments"] == 1


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_full_crew_lifecycle(self):
        """Simulate a full crew run: select → assign → execute → track trust."""
        crew = TrustedCrew(
            agents=[
                AgentProfile(did="d1", name="Researcher", capabilities=["research"], trust_score=600),
                AgentProfile(did="d2", name="Writer", capabilities=["writing"], trust_score=600),
            ],
            min_trust_score=500,
        )

        # Select for research task
        selected = crew.select_for_task(required_capabilities=["research"])
        assert len(selected) == 1

        # Assign
        assignment = crew.assign_task("d1", "Analyze market trends", ["research"])
        assert assignment.allowed

        # Execute (success)
        crew.record_task_result("d1", success=True, task_description="Analyze market trends")
        assert crew.get_agent("d1").trust_score > 600

        # Assign writing task to researcher (should fail)
        assignment = crew.assign_task("d1", "Write report", ["writing"])
        assert not assignment.allowed

        # Writer fails a task
        crew.record_task_result("d2", success=False, task_description="Draft blog", reason="poor quality")
        assert crew.get_agent("d2").trust_score < 600

        # After many failures, writer might drop below threshold
        for _ in range(5):
            crew.record_task_result("d2", success=False)
        assert crew.get_agent("d2").trust_score < 500
        assert len(crew.trusted_agents) == 1  # Only researcher

    def test_imports(self):
        from crewai_agentmesh import AgentProfile, TrustedCrew, TrustTracker, CapabilityGate, TaskAssignment
        assert all(cls is not None for cls in [AgentProfile, TrustedCrew, TrustTracker, CapabilityGate, TaskAssignment])
