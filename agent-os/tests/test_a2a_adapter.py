# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for A2A governance adapter (Agent-OS side).

No external dependencies — uses plain dicts to simulate JSON-RPC payloads.

Run with: python -m pytest tests/test_a2a_adapter.py -v --tb=short
"""

import time

import pytest

from agent_os.integrations.a2a_adapter import (
    A2AGovernanceAdapter,
    A2AEvaluation,
    A2APolicy,
)


def _make_task(
    skill="search",
    did="did:mesh:agent-a",
    score=500,
    text="Find weather",
):
    """Create a minimal A2A task dict."""
    return {
        "id": "task-001",
        "skill_id": skill,
        "status": {"state": "submitted"},
        "x-agentmesh-trust": {
            "source_did": did,
            "source_trust_score": score,
        },
        "messages": [
            {"role": "user", "parts": [{"text": text}]},
        ],
    }


# =============================================================================
# Policy
# =============================================================================


class TestA2APolicy:
    def test_defaults(self):
        p = A2APolicy()
        assert p.min_trust_score == 0
        assert p.max_requests_per_minute == 100

    def test_custom(self):
        p = A2APolicy(blocked_skills=["admin"], min_trust_score=300)
        assert "admin" in p.blocked_skills


# =============================================================================
# Adapter: skill filtering
# =============================================================================


class TestSkillFiltering:
    def test_allow_any_skill(self):
        a = A2AGovernanceAdapter()
        assert a.evaluate_task(_make_task()).allowed

    def test_blocked_skill(self):
        a = A2AGovernanceAdapter(blocked_skills=["admin"])
        r = a.evaluate_task(_make_task(skill="admin"))
        assert not r.allowed
        assert "blocked" in r.reason

    def test_allowed_list_accepts(self):
        a = A2AGovernanceAdapter(allowed_skills=["search", "translate"])
        assert a.evaluate_task(_make_task(skill="search")).allowed

    def test_allowed_list_rejects(self):
        a = A2AGovernanceAdapter(allowed_skills=["search", "translate"])
        r = a.evaluate_task(_make_task(skill="exec"))
        assert not r.allowed
        assert "allowed list" in r.reason


# =============================================================================
# Adapter: trust score
# =============================================================================


class TestTrustScore:
    def test_sufficient_score(self):
        a = A2AGovernanceAdapter(min_trust_score=300)
        assert a.evaluate_task(_make_task(score=500)).allowed

    def test_insufficient_score(self):
        a = A2AGovernanceAdapter(min_trust_score=600)
        r = a.evaluate_task(_make_task(score=400))
        assert not r.allowed
        assert "Trust score" in r.reason


# =============================================================================
# Adapter: content filtering
# =============================================================================


class TestContentFiltering:
    def test_clean_content(self):
        a = A2AGovernanceAdapter(blocked_patterns=["DROP TABLE"])
        assert a.evaluate_task(_make_task(text="Hello world")).allowed

    def test_blocked_content(self):
        a = A2AGovernanceAdapter(blocked_patterns=["DROP TABLE"])
        r = a.evaluate_task(_make_task(text="DROP TABLE users"))
        assert not r.allowed
        assert "blocked pattern" in r.reason

    def test_case_insensitive(self):
        a = A2AGovernanceAdapter(blocked_patterns=["rm -rf"])
        r = a.evaluate_task(_make_task(text="RM -RF /"))
        assert not r.allowed


# =============================================================================
# Adapter: trust metadata
# =============================================================================


class TestTrustMetadata:
    def test_require_did(self):
        p = A2APolicy(require_trust_metadata=True)
        a = A2AGovernanceAdapter(policy=p)
        r = a.evaluate_task(_make_task(did=""))
        assert not r.allowed
        assert "DID" in r.reason

    def test_did_not_required(self):
        a = A2AGovernanceAdapter()
        assert a.evaluate_task(_make_task(did="")).allowed


# =============================================================================
# Adapter: rate limiting
# =============================================================================


class TestRateLimiting:
    def test_within_limit(self):
        a = A2AGovernanceAdapter(max_requests_per_minute=5)
        for _ in range(5):
            assert a.evaluate_task(_make_task()).allowed

    def test_exceeds_limit(self):
        a = A2AGovernanceAdapter(max_requests_per_minute=3)
        for _ in range(3):
            assert a.evaluate_task(_make_task()).allowed
        r = a.evaluate_task(_make_task())
        assert not r.allowed
        assert "Rate limit" in r.reason

    def test_per_agent_tracking(self):
        a = A2AGovernanceAdapter(max_requests_per_minute=2)
        assert a.evaluate_task(_make_task(did="did:mesh:a")).allowed
        assert a.evaluate_task(_make_task(did="did:mesh:a")).allowed
        assert not a.evaluate_task(_make_task(did="did:mesh:a")).allowed
        # Different agent still allowed
        assert a.evaluate_task(_make_task(did="did:mesh:b")).allowed


# =============================================================================
# Evaluation result
# =============================================================================


class TestEvaluation:
    def test_to_dict(self):
        e = A2AEvaluation(allowed=True, reason="ok", source_did="did:mesh:x")
        d = e.to_dict()
        assert d["allowed"] is True
        assert d["source_did"] == "did:mesh:x"

    def test_evaluation_log(self):
        a = A2AGovernanceAdapter()
        a.evaluate_task(_make_task())
        a.evaluate_task(_make_task())
        assert len(a.get_evaluations()) == 2

    def test_stats(self):
        a = A2AGovernanceAdapter(min_trust_score=500)
        a.evaluate_task(_make_task(score=600))  # allowed
        a.evaluate_task(_make_task(score=300))  # denied
        stats = a.get_stats()
        assert stats["total"] == 2
        assert stats["allowed"] == 1
        assert stats["denied"] == 1


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_full_evaluation_chain(self):
        """Multiple policies applied in sequence."""
        a = A2AGovernanceAdapter(
            allowed_skills=["search", "translate"],
            blocked_patterns=["SECRET"],
            min_trust_score=200,
            max_requests_per_minute=10,
        )

        # Allowed
        assert a.evaluate_task(_make_task(skill="search", score=500, text="Hello")).allowed

        # Skill blocked
        assert not a.evaluate_task(_make_task(skill="admin", score=500)).allowed

        # Low trust
        assert not a.evaluate_task(_make_task(skill="search", score=100)).allowed

        # Bad content
        assert not a.evaluate_task(
            _make_task(skill="search", score=500, text="find SECRET key")
        ).allowed

        stats = a.get_stats()
        assert stats["total"] == 4
        assert stats["allowed"] == 1
        assert stats["denied"] == 3
