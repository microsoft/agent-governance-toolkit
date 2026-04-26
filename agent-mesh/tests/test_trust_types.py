# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for shared trust and identity types (agentmesh.trust_types)."""
from __future__ import annotations

import pytest

from agentmesh.trust_types import (
    AgentProfile,
    TrustRecord,
    TrustScore,
    TrustTracker,
)


# ---------------------------------------------------------------------------
# TrustScore
# ---------------------------------------------------------------------------

class TestTrustScore:
    def test_basic_creation(self) -> None:
        ts = TrustScore(score=0.8, source="test")
        assert ts.score == 0.8
        assert ts.confidence == 1.0
        assert ts.source == "test"

    def test_clamping_high(self) -> None:
        ts = TrustScore(score=1.5)
        assert ts.score == 1.0

    def test_clamping_low(self) -> None:
        ts = TrustScore(score=-0.3)
        assert ts.score == 0.0

    def test_confidence_clamping(self) -> None:
        ts = TrustScore(score=0.5, confidence=2.0)
        assert ts.confidence == 1.0
        ts2 = TrustScore(score=0.5, confidence=-1.0)
        assert ts2.confidence == 0.0

    def test_is_trusted_above_threshold(self) -> None:
        assert TrustScore(score=0.7).is_trusted is True

    def test_is_trusted_at_threshold(self) -> None:
        assert TrustScore(score=0.5).is_trusted is True

    def test_is_trusted_below_threshold(self) -> None:
        assert TrustScore(score=0.3).is_trusted is False

    def test_to_dict(self) -> None:
        ts = TrustScore(score=0.9, confidence=0.8, source="eval", timestamp="2025-01-01")
        d = ts.to_dict()
        assert d == {
            "score": 0.9,
            "confidence": 0.8,
            "source": "eval",
            "timestamp": "2025-01-01",
        }


# ---------------------------------------------------------------------------
# AgentProfile
# ---------------------------------------------------------------------------

class TestAgentProfile:
    def test_basic_creation(self) -> None:
        profile = AgentProfile(agent_id="a1")
        assert profile.agent_id == "a1"
        assert profile.trust_score == 0.5
        assert profile.capabilities == []

    def test_has_capability_present(self) -> None:
        profile = AgentProfile(agent_id="a1", capabilities=["read", "write"])
        assert profile.has_capability("read") is True
        assert profile.has_capability("write") is True

    def test_has_capability_absent(self) -> None:
        profile = AgentProfile(agent_id="a1", capabilities=["read"])
        assert profile.has_capability("delete") is False

    def test_has_capability_wildcard(self) -> None:
        profile = AgentProfile(agent_id="a1", capabilities=["*"])
        assert profile.has_capability("anything") is True

    def test_metadata_field(self) -> None:
        profile = AgentProfile(agent_id="a1", metadata={"team": "platform"})
        assert profile.metadata["team"] == "platform"


# ---------------------------------------------------------------------------
# TrustRecord
# ---------------------------------------------------------------------------

class TestTrustRecord:
    def test_creation(self) -> None:
        record = TrustRecord(
            agent_id="a1",
            peer_id="a2",
            action="handshake",
            success=True,
            trust_delta=0.01,
        )
        assert record.agent_id == "a1"
        assert record.peer_id == "a2"
        assert record.action == "handshake"
        assert record.success is True
        assert record.trust_delta == 0.01

    def test_defaults(self) -> None:
        record = TrustRecord(agent_id="a1", peer_id="a2", action="test", success=False)
        assert record.trust_delta == 0.0
        assert record.timestamp == ""
        assert record.details == ""


# ---------------------------------------------------------------------------
# TrustTracker
# ---------------------------------------------------------------------------

class TestTrustTracker:
    def test_initial_score(self) -> None:
        tracker = TrustTracker(initial_score=0.6)
        assert tracker.get_score("unknown-agent") == 0.6

    def test_default_initial_score(self) -> None:
        tracker = TrustTracker()
        assert tracker.get_score("any") == 0.5

    def test_reward_increases_score(self) -> None:
        tracker = TrustTracker(initial_score=0.5, reward=0.1)
        new_score = tracker.record_interaction("a1", "a2", "task", success=True)
        assert new_score == pytest.approx(0.6)
        assert tracker.get_score("a1") == pytest.approx(0.6)

    def test_penalty_decreases_score(self) -> None:
        tracker = TrustTracker(initial_score=0.5, penalty=0.2)
        new_score = tracker.record_interaction("a1", "a2", "task", success=False)
        assert new_score == pytest.approx(0.3)

    def test_score_clamped_to_max(self) -> None:
        tracker = TrustTracker(initial_score=0.95, reward=0.1, max_score=1.0)
        new_score = tracker.record_interaction("a1", "a2", "task", success=True)
        assert new_score == 1.0

    def test_score_clamped_to_min(self) -> None:
        tracker = TrustTracker(initial_score=0.02, penalty=0.1, min_score=0.0)
        new_score = tracker.record_interaction("a1", "a2", "task", success=False)
        assert new_score == 0.0

    def test_history_all(self) -> None:
        tracker = TrustTracker()
        tracker.record_interaction("a1", "a2", "task1", success=True)
        tracker.record_interaction("b1", "b2", "task2", success=False)
        history = tracker.get_history()
        assert len(history) == 2

    def test_history_filtered(self) -> None:
        tracker = TrustTracker()
        tracker.record_interaction("a1", "a2", "task1", success=True)
        tracker.record_interaction("b1", "b2", "task2", success=False)
        tracker.record_interaction("a1", "a3", "task3", success=True)
        a1_history = tracker.get_history("a1")
        assert len(a1_history) == 2
        assert all(r.agent_id == "a1" for r in a1_history)

    def test_reset(self) -> None:
        tracker = TrustTracker(initial_score=0.5, reward=0.1)
        tracker.record_interaction("a1", "a2", "task", success=True)
        assert tracker.get_score("a1") == pytest.approx(0.6)
        tracker.reset("a1")
        assert tracker.get_score("a1") == 0.5  # back to initial

    def test_reset_nonexistent_agent(self) -> None:
        tracker = TrustTracker()
        tracker.reset("nonexistent")  # Should not raise
        assert tracker.get_score("nonexistent") == 0.5
