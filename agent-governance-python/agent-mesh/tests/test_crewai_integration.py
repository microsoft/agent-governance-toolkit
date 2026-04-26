# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Tests for CrewAI trust-aware agent and crew wrappers."""

import pytest

from agentmesh.exceptions import TrustViolationError
from agentmesh.integrations.crewai import (
    InMemoryTrustStore,
    TrustAwareAgent,
    TrustAwareCrew,
)


# ── Helpers ─────────────────────────────────────────────────────────


def _make_agent(
    did: str = "did:mesh:agent1",
    score: int = 600,
    min_score: int = 500,
    store: InMemoryTrustStore | None = None,
) -> TrustAwareAgent:
    """Create a TrustAwareAgent with a pre-configured trust store."""
    if store is None:
        store = InMemoryTrustStore(default_score=score)
    return TrustAwareAgent(
        agent_did=did,
        min_trust_score=min_score,
        trust_store=store,
    )


# ── TrustAwareAgent: verify_peer ───────────────────────────────────


class TestTrustAwareAgentVerifyPeer:
    def test_verify_peer_above_threshold(self):
        store = InMemoryTrustStore(default_score=700)
        agent = _make_agent(store=store, min_score=500)
        assert agent.verify_peer("did:mesh:peer1") is True

    def test_verify_peer_below_threshold(self):
        store = InMemoryTrustStore(default_score=300)
        agent = _make_agent(store=store, min_score=500)
        assert agent.verify_peer("did:mesh:peer1") is False

    def test_verify_peer_at_threshold(self):
        store = InMemoryTrustStore(default_score=500)
        agent = _make_agent(store=store, min_score=500)
        assert agent.verify_peer("did:mesh:peer1") is True


# ── TrustAwareAgent: delegation ────────────────────────────────────


class TestTrustAwareAgentDelegation:
    def test_delegate_blocked_for_low_trust_peer(self):
        store = InMemoryTrustStore(default_score=300)
        agent = _make_agent(store=store, min_score=500)
        with pytest.raises(TrustViolationError, match="below required"):
            agent.delegate_with_trust("Do research", "did:mesh:untrusted")

    def test_delegate_allowed_for_high_trust_peer(self):
        store = InMemoryTrustStore(default_score=800)
        agent = _make_agent(store=store, min_score=500)
        result = agent.delegate_with_trust("Do research", "did:mesh:trusted")
        assert result["status"] == "delegated"
        assert result["to"] == "did:mesh:trusted"

    def test_delegate_records_interaction_on_success(self):
        store = InMemoryTrustStore(default_score=800)
        agent = _make_agent(store=store, min_score=500)
        agent.delegate_with_trust("task", "did:mesh:peer")
        report = agent.get_trust_report()
        assert report["total_interactions"] == 1
        assert report["successes"] == 1

    def test_delegate_records_interaction_on_failure(self):
        store = InMemoryTrustStore(default_score=300)
        agent = _make_agent(store=store, min_score=500)
        with pytest.raises(TrustViolationError):
            agent.delegate_with_trust("task", "did:mesh:peer")
        report = agent.get_trust_report()
        assert report["total_interactions"] == 1
        assert report["failures"] == 1


# ── TrustAwareAgent: execute_with_trust ────────────────────────────


class TestTrustAwareAgentExecute:
    def test_execute_succeeds_with_sufficient_trust(self):
        agent = _make_agent(score=700, min_score=500)
        result = agent.execute_with_trust("Summarize document")
        assert result["status"] == "executed"

    def test_execute_blocked_with_low_trust(self):
        agent = _make_agent(score=300, min_score=500)
        with pytest.raises(TrustViolationError, match="below required"):
            agent.execute_with_trust("Summarize document")


# ── TrustAwareAgent: trust report ──────────────────────────────────


class TestTrustAwareAgentReport:
    def test_trust_report_structure(self):
        agent = _make_agent(score=700, min_score=500)
        report = agent.get_trust_report()
        assert report["agent_did"] == "did:mesh:agent1"
        assert report["current_score"] == 700
        assert report["min_trust_score"] == 500
        assert report["total_interactions"] == 0

    def test_trust_report_after_interactions(self):
        store = InMemoryTrustStore(default_score=800)
        agent = _make_agent(store=store, min_score=500)
        agent.delegate_with_trust("task1", "did:mesh:peer")
        agent.execute_with_trust("task2")
        report = agent.get_trust_report()
        assert report["total_interactions"] == 2
        assert report["successes"] == 2
        assert len(report["interactions"]) == 2


# ── TrustAwareCrew: verify_crew_trust ──────────────────────────────


class TestTrustAwareCrewVerify:
    def test_verify_all_trusted(self):
        store = InMemoryTrustStore(default_score=700)
        agents = [
            _make_agent(did="did:mesh:a1", store=store),
            _make_agent(did="did:mesh:a2", store=store),
        ]
        crew = TrustAwareCrew(agents=agents, tasks=[], min_trust_score=500)
        report = crew.verify_crew_trust()
        assert report["all_trusted"] is True
        assert report["agents"]["did:mesh:a1"]["trusted"] is True
        assert report["agents"]["did:mesh:a2"]["trusted"] is True

    def test_verify_with_untrusted_agent(self):
        store = InMemoryTrustStore(default_score=700)
        low_store = InMemoryTrustStore(default_score=300)
        agents = [
            _make_agent(did="did:mesh:a1", store=store),
            _make_agent(did="did:mesh:a2", store=low_store),
        ]
        crew = TrustAwareCrew(agents=agents, tasks=[], min_trust_score=500)
        report = crew.verify_crew_trust()
        assert report["all_trusted"] is False
        assert report["agents"]["did:mesh:a2"]["trusted"] is False


# ── TrustAwareCrew: kickoff ────────────────────────────────────────


class TestTrustAwareCrewKickoff:
    def test_kickoff_succeeds_with_all_trusted(self):
        store = InMemoryTrustStore(default_score=700)
        agents = [
            _make_agent(did="did:mesh:a1", store=store),
            _make_agent(did="did:mesh:a2", store=store),
        ]
        crew = TrustAwareCrew(agents=agents, tasks=[], min_trust_score=500)
        result = crew.kickoff()
        assert "trust_report" in result
        assert "result" in result
        assert result["trust_report"]["all_trusted"] is True

    def test_kickoff_blocked_with_untrusted_agent(self):
        store = InMemoryTrustStore(default_score=700)
        low_store = InMemoryTrustStore(default_score=300)
        agents = [
            _make_agent(did="did:mesh:a1", store=store),
            _make_agent(did="did:mesh:a2", store=low_store),
        ]
        crew = TrustAwareCrew(agents=agents, tasks=[], min_trust_score=500)
        with pytest.raises(TrustViolationError, match="trust verification failed"):
            crew.kickoff()


# ── Graceful behavior without crewai ───────────────────────────────


class TestCrewAINotInstalled:
    def test_agent_works_without_crewai(self):
        """TrustAwareAgent should work for trust ops even without crewai."""
        agent = _make_agent(score=700)
        assert agent.crewai_agent is None
        assert agent.verify_peer("did:mesh:peer") is True

    def test_execute_without_crewai_returns_stub(self):
        agent = _make_agent(score=700)
        result = agent.execute_with_trust("some task")
        assert result["status"] == "executed"
        assert result["agent"] == "did:mesh:agent1"

    def test_crew_kickoff_without_crewai(self):
        store = InMemoryTrustStore(default_score=700)
        agents = [_make_agent(did="did:mesh:a1", store=store)]
        crew = TrustAwareCrew(agents=agents, tasks=[], min_trust_score=500)
        result = crew.kickoff()
        assert result["result"]["status"] == "trust_verified"

    def test_import_succeeds_without_crewai(self):
        """Package import should not fail when crewai is not installed."""
        from agentmesh.integrations.crewai import (  # noqa: F401
            TrustAwareAgent,
            TrustAwareCrew,
            InMemoryTrustStore,
        )
