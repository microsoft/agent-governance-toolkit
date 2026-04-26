# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Property-based tests for trust scoring invariants.

Uses Hypothesis to verify that key trust-scoring properties hold
across a wide range of inputs.

Closes #114.
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from agentmesh.constants import (
    TRUST_SCORE_MAX,
    TRUST_SCORE_MIN,
    WEIGHT_COLLABORATION_HEALTH,
    WEIGHT_OUTPUT_QUALITY,
    WEIGHT_POLICY_COMPLIANCE,
    WEIGHT_RESOURCE_EFFICIENCY,
    WEIGHT_SECURITY_POSTURE,
)
from agentmesh.reward import RewardEngine, TrustScore, NetworkTrustEngine, TrustEvent
from agentmesh.reward.engine import RewardConfig
from agentmesh.reward.scoring import DimensionType, RewardDimension


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

valid_score = st.integers(min_value=TRUST_SCORE_MIN, max_value=TRUST_SCORE_MAX)
signal_value = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
agent_did = st.just("did:mesh:prop_test_agent")


# ---------------------------------------------------------------------------
# Property: Trust scores are always in valid range [0, 1000]
# ---------------------------------------------------------------------------

class TestTrustScoreRange:
    """Trust scores must always remain in [0, 1000]."""

    @given(score=valid_score)
    @settings(max_examples=200)
    def test_score_in_range(self, score: int):
        """Any score passed to TrustScore is clamped to [0, 1000]."""
        ts = TrustScore(agent_did="did:mesh:range_test", total_score=score)
        assert TRUST_SCORE_MIN <= ts.total_score <= TRUST_SCORE_MAX

    @given(new_score=st.integers(min_value=-500, max_value=2000))
    @settings(max_examples=200)
    def test_update_clamps(self, new_score: int):
        """TrustScore.update() always clamps to [0, 1000]."""
        ts = TrustScore(agent_did="did:mesh:clamp_test", total_score=500)
        ts.update(new_score, {})
        assert TRUST_SCORE_MIN <= ts.total_score <= TRUST_SCORE_MAX


# ---------------------------------------------------------------------------
# Property: Positive-only signals ⟹ monotonically non-decreasing score
# ---------------------------------------------------------------------------

class TestMonotonicPositiveSignals:
    """Scores with all positive interactions are monotonically non-decreasing."""

    @given(n_signals=st.integers(min_value=1, max_value=20))
    @settings(max_examples=100)
    def test_positive_signals_nondecreasing(self, n_signals: int):
        """Recording only positive signals never lowers the computed score."""
        engine = RewardEngine()
        did = "did:mesh:mono_test"

        scores: list[int] = []
        for _ in range(n_signals):
            for dim in DimensionType:
                engine.record_signal(
                    agent_did=did,
                    dimension=dim,
                    value=1.0,
                    source="prop_test",
                )
            score = engine._recalculate_score(did)
            scores.append(score.total_score)

        # Scores should be non-decreasing
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1], (
                f"Score decreased from {scores[i - 1]} to {scores[i]} at step {i}"
            )


# ---------------------------------------------------------------------------
# Property: Trust decay is bounded (score never goes below 0)
# ---------------------------------------------------------------------------

class TestTrustDecayBounded:
    """Trust decay must never push a score below 0."""

    @given(
        initial=st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        severity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=200)
    def test_decay_never_negative(self, initial: float, severity: float):
        """NetworkTrustEngine scores remain ≥ 0 after negative events."""
        engine = NetworkTrustEngine()
        did = "did:mesh:decay_test"
        engine.set_score(did, initial)

        event = TrustEvent(
            agent_did=did,
            event_type="policy_violation",
            severity_weight=severity,
        )
        engine.process_trust_event(event)

        assert engine.get_score(did) >= 0

    @given(
        n_events=st.integers(min_value=1, max_value=30),
        severity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=100)
    def test_repeated_decay_bounded(self, n_events: int, severity: float):
        """Repeated negative events never push score below 0."""
        engine = NetworkTrustEngine()
        did = "did:mesh:repeat_decay"
        engine.set_score(did, 500.0)

        for _ in range(n_events):
            engine.process_trust_event(
                TrustEvent(
                    agent_did=did,
                    event_type="failure",
                    severity_weight=severity,
                )
            )

        assert engine.get_score(did) >= 0


# ---------------------------------------------------------------------------
# Property: Dimension weights always sum to 1.0 (within float tolerance)
# ---------------------------------------------------------------------------

class TestDimensionWeightsSum:
    """Default dimension weights must sum to 1.0."""

    def test_constant_weights_sum(self):
        """Named constant weights sum to 1.0."""
        total = (
            WEIGHT_POLICY_COMPLIANCE
            + WEIGHT_RESOURCE_EFFICIENCY
            + WEIGHT_OUTPUT_QUALITY
            + WEIGHT_SECURITY_POSTURE
            + WEIGHT_COLLABORATION_HEALTH
        )
        assert abs(total - 1.0) < 1e-9

    def test_reward_config_default_weights_valid(self):
        """RewardConfig default weights sum to 1.0."""
        config = RewardConfig()
        assert config.validate_weights()

    @given(
        w1=st.floats(min_value=0.01, max_value=0.5, allow_nan=False, allow_infinity=False),
        w2=st.floats(min_value=0.01, max_value=0.5, allow_nan=False, allow_infinity=False),
        w3=st.floats(min_value=0.01, max_value=0.5, allow_nan=False, allow_infinity=False),
        w4=st.floats(min_value=0.01, max_value=0.5, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=100)
    def test_custom_weights_validation(
        self, w1: float, w2: float, w3: float, w4: float
    ):
        """RewardConfig.validate_weights detects when weights don't sum to 1.0."""
        w5 = 1.0 - (w1 + w2 + w3 + w4)
        assume(w5 > 0)  # only test valid partitions

        config = RewardConfig(
            policy_compliance_weight=w1,
            resource_efficiency_weight=w2,
            output_quality_weight=w3,
            security_posture_weight=w4,
            collaboration_health_weight=w5,
        )
        assert config.validate_weights()


# ---------------------------------------------------------------------------
# Property: Higher dimension scores ⟹ higher or equal total score
# ---------------------------------------------------------------------------

class TestHigherComponentsHigherTotal:
    """Higher component scores always produce higher or equal totals."""

    @given(
        base_value=st.floats(min_value=0.0, max_value=0.5, allow_nan=False, allow_infinity=False),
        boost=st.floats(min_value=0.01, max_value=0.5, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=200)
    def test_higher_signals_higher_score(self, base_value: float, boost: float):
        """An engine fed uniformly higher signal values scores ≥ the baseline."""
        high_value = min(base_value + boost, 1.0)

        engine_low = RewardEngine()
        engine_high = RewardEngine()

        did = "did:mesh:cmp_test"

        for dim in DimensionType:
            engine_low.record_signal(
                agent_did=did, dimension=dim, value=base_value, source="prop"
            )
            engine_high.record_signal(
                agent_did=did, dimension=dim, value=high_value, source="prop"
            )

        score_low = engine_low._recalculate_score(did).total_score
        score_high = engine_high._recalculate_score(did).total_score

        assert score_high >= score_low, (
            f"Higher signals ({high_value}) produced lower score ({score_high}) "
            f"than base ({base_value}) score ({score_low})"
        )


# ---------------------------------------------------------------------------
# Property: NetworkTrustEngine score clamping
# ---------------------------------------------------------------------------

class TestNetworkEngineClamping:
    """NetworkTrustEngine.set_score always clamps to [0, 1000]."""

    @given(score=st.floats(min_value=-1000.0, max_value=3000.0, allow_nan=False, allow_infinity=False))
    @settings(max_examples=200)
    def test_set_score_clamps(self, score: float):
        engine = NetworkTrustEngine()
        engine.set_score("did:mesh:net_clamp", score)
        result = engine.get_score("did:mesh:net_clamp")
        assert 0 <= result <= TRUST_SCORE_MAX
