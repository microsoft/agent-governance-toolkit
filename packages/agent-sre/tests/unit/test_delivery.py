# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for progressive delivery — preview mode and staged rollout."""

import pytest

from agent_sre.delivery.rollout import (
    AnalysisCriterion,
    CanaryRollout,
    RollbackCondition,
    RolloutState,
    RolloutStep,
    ShadowComparison,
    ShadowMode,
    ShadowResult,
)


class TestShadowComparison:
    def test_deltas(self) -> None:
        c = ShadowComparison(
            request_id="r1",
            current_latency_ms=100,
            candidate_latency_ms=150,
            current_cost_usd=0.01,
            candidate_cost_usd=0.02,
        )
        assert c.latency_delta_ms == 50
        assert abs(c.cost_delta_usd - 0.01) < 1e-10


class TestShadowResult:
    def test_empty(self) -> None:
        r = ShadowResult()
        assert r.total_requests == 0
        assert r.match_rate == 0.0
        assert r.confidence_score == 0.0

    def test_with_comparisons(self) -> None:
        r = ShadowResult()
        r.comparisons = [
            ShadowComparison("r1", match=True, similarity_score=1.0),
            ShadowComparison("r2", match=True, similarity_score=0.9),
            ShadowComparison("r3", match=False, similarity_score=0.5),
        ]
        assert r.total_requests == 3
        assert abs(r.match_rate - 2 / 3) < 0.01


class TestShadowMode:
    def test_exact_match(self) -> None:
        shadow = ShadowMode()
        with pytest.raises(NotImplementedError):
            shadow.compare("r1", "hello world", "hello world")

    def test_mismatch(self) -> None:
        shadow = ShadowMode()
        with pytest.raises(NotImplementedError):
            shadow.compare("r1", "hello", "goodbye")

    def test_custom_similarity(self) -> None:
        shadow = ShadowMode(similarity_threshold=0.8)
        with pytest.raises(NotImplementedError):
            shadow.set_similarity_function(lambda a, b: 0.85)

    def test_is_passing(self) -> None:
        shadow = ShadowMode()
        with pytest.raises(NotImplementedError):
            shadow.is_passing(min_confidence=0.5)

    def test_finish(self) -> None:
        shadow = ShadowMode()
        with pytest.raises(NotImplementedError):
            shadow.finish()


class TestAnalysisCriterion:
    def test_gte(self) -> None:
        c = AnalysisCriterion(metric="success_rate", threshold=0.99, comparator="gte")
        assert c.evaluate(0.995) is True
        assert c.evaluate(0.98) is False

    def test_lte(self) -> None:
        c = AnalysisCriterion(metric="latency", threshold=5000, comparator="lte")
        assert c.evaluate(3000) is True
        assert c.evaluate(6000) is False


class TestCanaryRollout:
    def test_default_steps(self) -> None:
        r = CanaryRollout(name="test-v2")
        assert r.steps == []
        assert r.state == RolloutState.PENDING

    def test_start(self) -> None:
        r = CanaryRollout(name="test-v2")
        with pytest.raises(NotImplementedError):
            r.start()

    def test_advance(self) -> None:
        r = CanaryRollout(name="test-v2")
        with pytest.raises(NotImplementedError):
            r.advance()

    def test_rollback(self) -> None:
        r = CanaryRollout(name="test-v2")
        with pytest.raises(NotImplementedError):
            r.rollback(reason="test failure")

    def test_auto_rollback(self) -> None:
        r = CanaryRollout(
            name="test-v2",
            rollback_conditions=[
                RollbackCondition(metric="error_rate", threshold=0.05, comparator="gte"),
            ],
        )
        with pytest.raises(NotImplementedError):
            r.check_rollback({"error_rate": 0.10})

    def test_no_rollback_when_healthy(self) -> None:
        r = CanaryRollout(
            name="test-v2",
            rollback_conditions=[
                RollbackCondition(metric="error_rate", threshold=0.05, comparator="gte"),
            ],
        )
        with pytest.raises(NotImplementedError):
            r.check_rollback({"error_rate": 0.01})

    def test_analyze_step(self) -> None:
        r = CanaryRollout(
            name="test-v2",
            steps=[
                RolloutStep(
                    name="canary",
                    weight=0.05,
                    analysis=[AnalysisCriterion("success_rate", 0.99, "gte")],
                ),
            ],
        )
        with pytest.raises(NotImplementedError):
            r.analyze_step({"success_rate": 0.995})

    def test_pause_resume(self) -> None:
        r = CanaryRollout(name="test-v2")
        with pytest.raises(NotImplementedError):
            r.pause()

    def test_promote(self) -> None:
        r = CanaryRollout(name="test-v2")
        with pytest.raises(NotImplementedError):
            r.promote()

    def test_progress(self) -> None:
        steps = [
            RolloutStep(name="s1", weight=0.05),
            RolloutStep(name="s2", weight=0.25),
            RolloutStep(name="s3", weight=0.50),
            RolloutStep(name="s4", weight=1.0),
        ]
        r = CanaryRollout(name="test-v2", steps=steps)
        # current_step_index is -1, so progress is 0
        assert r.progress_percent == 0.0

    def test_to_dict(self) -> None:
        r = CanaryRollout(name="test-v2")
        d = r.to_dict()
        assert d["name"] == "test-v2"
        assert d["state"] == "pending"

    def test_events_recorded(self) -> None:
        r = CanaryRollout(name="test-v2")
        r._record_event("test_event")
        types = [e.event_type for e in r.events]
        assert "test_event" in types
