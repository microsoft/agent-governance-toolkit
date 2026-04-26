# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import pytest

from agent_marketplace.usage_trust import (
    UsageSignals,
    UsageTrustAdjustment,
    UsageTrustScorer,
)


# ---------------------------------------------------------------------------
# UsageSignals
# ---------------------------------------------------------------------------


class TestUsageSignals:
    def test_error_rate_zero_invocations(self) -> None:
        s = UsageSignals("p", "1.0", total_invocations=0, error_count=5)
        assert s.error_rate == 0.0

    def test_error_rate_calculation(self) -> None:
        s = UsageSignals("p", "1.0", total_invocations=1000, error_count=10)
        assert s.error_rate == pytest.approx(0.01)

    def test_is_stale_true(self) -> None:
        s = UsageSignals("p", "1.0", days_since_update=200)
        assert s.is_stale is True

    def test_is_stale_false(self) -> None:
        s = UsageSignals("p", "1.0", days_since_update=90)
        assert s.is_stale is False

    def test_is_stale_boundary(self) -> None:
        s = UsageSignals("p", "1.0", days_since_update=180)
        assert s.is_stale is False


# ---------------------------------------------------------------------------
# UsageTrustScorer
# ---------------------------------------------------------------------------


class TestUsageTrustScorer:
    def test_high_adoption_adjustment(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals("p", "1.0", daily_active_users=2000)
        adjustments = scorer.compute_adjustments(signals)
        adoption = [a for a in adjustments if a.signal_name == "daily_active_users"]
        assert len(adoption) == 1
        assert adoption[0].adjustment == 100

    def test_excellent_reliability_bonus(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals(
            "p", "1.0", total_invocations=10000, error_count=0,
        )
        adjustments = scorer.compute_adjustments(signals)
        reliability = [a for a in adjustments if a.signal_name == "error_rate"]
        assert len(reliability) == 1
        assert reliability[0].adjustment == 75

    def test_poor_reliability_penalty(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals(
            "p", "1.0", total_invocations=1000, error_count=200,
        )
        adjustments = scorer.compute_adjustments(signals)
        reliability = [a for a in adjustments if a.signal_name == "error_rate"]
        assert len(reliability) == 1
        assert reliability[0].adjustment == -100

    def test_incident_penalty(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals("p", "1.0", incident_count=3)
        adjustments = scorer.compute_adjustments(signals)
        incidents = [a for a in adjustments if a.signal_name == "incident_count"]
        assert len(incidents) == 1
        assert incidents[0].adjustment == -150

    def test_staleness_penalty(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals("p", "1.0", days_since_update=365)
        adjustments = scorer.compute_adjustments(signals)
        stale = [a for a in adjustments if a.signal_name == "days_since_update"]
        assert len(stale) == 1
        assert stale[0].adjustment == -50

    def test_total_adjustment_capping_positive(self) -> None:
        scorer = UsageTrustScorer(max_adjustment=200)
        signals = UsageSignals(
            "p", "1.0",
            daily_active_users=5000,
            total_invocations=100000,
            error_count=0,
            adoption_trend=0.5,
        )
        total = scorer.compute_total_adjustment(signals)
        assert total <= 200

    def test_total_adjustment_capping_negative(self) -> None:
        scorer = UsageTrustScorer(max_adjustment=200)
        signals = UsageSignals(
            "p", "1.0",
            incident_count=10,
            days_since_update=400,
            adoption_trend=-0.5,
        )
        total = scorer.compute_total_adjustment(signals)
        assert total >= -200

    def test_no_adjustments_for_minimal_signals(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals("p", "1.0")
        adjustments = scorer.compute_adjustments(signals)
        assert len(adjustments) == 0

    def test_growing_adoption_bonus(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals("p", "1.0", adoption_trend=0.3)
        adjustments = scorer.compute_adjustments(signals)
        trend = [a for a in adjustments if a.signal_name == "adoption_trend"]
        assert len(trend) == 1
        assert trend[0].adjustment == 25

    def test_declining_adoption_penalty(self) -> None:
        scorer = UsageTrustScorer()
        signals = UsageSignals("p", "1.0", adoption_trend=-0.5)
        adjustments = scorer.compute_adjustments(signals)
        trend = [a for a in adjustments if a.signal_name == "adoption_trend"]
        assert len(trend) == 1
        assert trend[0].adjustment == -25