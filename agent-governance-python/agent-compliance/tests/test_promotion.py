# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Agent Lifecycle Promotion Gates module."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure agent_compliance is importable
_COMPLIANCE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_COMPLIANCE_ROOT / "src"))

from agent_compliance.promotion import (
    MaturityLevel,
    PromotionChecker,
    PromotionGate,
    PromotionReport,
    PromotionResult,
    _DEFAULT_GATES,
    _test_coverage_check,
    _security_scan_check,
    _slo_compliance_check,
    _trust_score_check,
    _peer_review_check,
    _error_budget_check,
    _observability_check,
    _documentation_check,
    _change_control_check,
)


# ── Helper: a "passing" context for all built-in gates ────────

def _full_pass_context(**overrides) -> dict:
    """Return a context dict that satisfies every built-in gate."""
    ctx = {
        "test_coverage": 95.0,
        "critical_vulns": 0,
        "slo_compliance_pct": 99.9,
        "slo_compliance_days": 30,
        "trust_score": 0.95,
        "peer_reviews": 5,
        "error_budget_remaining_pct": 50.0,
        "has_metrics": True,
        "has_logging": True,
        "has_readme": True,
        "has_api_docs": True,
        "has_approved_change_request": True,
    }
    ctx.update(overrides)
    return ctx


# ── Individual gate checks ────────────────────────────────────


class TestTestCoverageGate:
    def test_passes_above_threshold(self):
        ok, reason = _test_coverage_check({"test_coverage": 85})
        assert ok is True

    def test_fails_below_threshold(self):
        ok, reason = _test_coverage_check({"test_coverage": 50})
        assert ok is False
        assert "50" in reason

    def test_custom_threshold(self):
        ok, _ = _test_coverage_check({"test_coverage": 90, "test_coverage_threshold": 95})
        assert ok is False


class TestSecurityScanGate:
    def test_passes_zero_vulns(self):
        ok, _ = _security_scan_check({"critical_vulns": 0})
        assert ok is True

    def test_fails_with_vulns(self):
        ok, reason = _security_scan_check({"critical_vulns": 3})
        assert ok is False
        assert "3" in reason

    def test_fails_when_missing(self):
        ok, reason = _security_scan_check({})
        assert ok is False
        assert "not provided" in reason


class TestSLOComplianceGate:
    def test_passes_when_meeting_targets(self):
        ok, _ = _slo_compliance_check({
            "slo_compliance_pct": 99.5,
            "slo_compliance_days": 14,
        })
        assert ok is True

    def test_fails_low_pct(self):
        ok, reason = _slo_compliance_check({
            "slo_compliance_pct": 95.0,
            "slo_compliance_days": 14,
        })
        assert ok is False
        assert "compliance" in reason

    def test_fails_short_window(self):
        ok, reason = _slo_compliance_check({
            "slo_compliance_pct": 99.5,
            "slo_compliance_days": 3,
        })
        assert ok is False
        assert "window" in reason


class TestTrustScoreGate:
    def test_passes_above(self):
        ok, _ = _trust_score_check({"trust_score": 0.8})
        assert ok is True

    def test_fails_below(self):
        ok, _ = _trust_score_check({"trust_score": 0.5})
        assert ok is False


class TestPeerReviewGate:
    def test_passes_enough(self):
        ok, _ = _peer_review_check({"peer_reviews": 3})
        assert ok is True

    def test_fails_not_enough(self):
        ok, _ = _peer_review_check({"peer_reviews": 1})
        assert ok is False


class TestErrorBudgetGate:
    def test_passes_above(self):
        ok, _ = _error_budget_check({"error_budget_remaining_pct": 30})
        assert ok is True

    def test_fails_below(self):
        ok, _ = _error_budget_check({"error_budget_remaining_pct": 5})
        assert ok is False


class TestObservabilityGate:
    def test_passes_both(self):
        ok, _ = _observability_check({"has_metrics": True, "has_logging": True})
        assert ok is True

    def test_fails_no_metrics(self):
        ok, reason = _observability_check({"has_metrics": False, "has_logging": True})
        assert ok is False
        assert "metrics" in reason

    def test_fails_no_logging(self):
        ok, reason = _observability_check({"has_metrics": True, "has_logging": False})
        assert ok is False
        assert "logging" in reason


class TestDocumentationGate:
    def test_passes_all_docs(self):
        ok, _ = _documentation_check({"has_readme": True, "has_api_docs": True})
        assert ok is True

    def test_fails_no_readme(self):
        ok, reason = _documentation_check({"has_readme": False, "has_api_docs": True})
        assert ok is False
        assert "README" in reason

    def test_fails_no_api_docs(self):
        ok, reason = _documentation_check({"has_readme": True, "has_api_docs": False})
        assert ok is False
        assert "API" in reason


class TestChangeControlGate:
    def test_passes_approved(self):
        ok, _ = _change_control_check({"has_approved_change_request": True})
        assert ok is True

    def test_fails_not_approved(self):
        ok, _ = _change_control_check({"has_approved_change_request": False})
        assert ok is False


# ── PromotionChecker ──────────────────────────────────────────


class TestPromotionChecker:
    def test_default_gates_registered(self):
        checker = PromotionChecker()
        assert len(checker._gates) == len(_DEFAULT_GATES)

    def test_register_custom_gate(self):
        checker = PromotionChecker(gates=[])
        gate = PromotionGate(
            name="custom",
            check_fn=lambda ctx: (True, "ok"),
            required_for={MaturityLevel.BETA},
        )
        checker.register_gate(gate)
        assert len(checker._gates) == 1

    def test_full_pass_experimental_to_beta(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            _full_pass_context(),
        )
        assert report.overall_passed is True
        assert report.blockers == []
        assert len(report.gates) > 0

    def test_full_pass_beta_to_stable(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.BETA,
            MaturityLevel.STABLE,
            _full_pass_context(),
        )
        assert report.overall_passed is True
        assert report.blockers == []

    def test_fail_blocks_promotion(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            _full_pass_context(test_coverage=30),
        )
        assert report.overall_passed is False
        assert "test_coverage_gate" in report.blockers

    def test_multiple_blockers(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            _full_pass_context(test_coverage=30, critical_vulns=5),
        )
        assert report.overall_passed is False
        assert "test_coverage_gate" in report.blockers
        assert "security_scan_gate" in report.blockers

    def test_warning_gate_does_not_block(self):
        warning_gate = PromotionGate(
            name="warn_only",
            check_fn=lambda ctx: (False, "advisory only"),
            required_for={MaturityLevel.BETA},
            severity="warning",
        )
        checker = PromotionChecker(gates=[warning_gate])
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            {},
        )
        assert report.overall_passed is True
        assert report.blockers == []
        assert report.gates[0].passed is False

    def test_gate_exception_treated_as_failure(self):
        def bad_gate(ctx):
            raise RuntimeError("boom")

        gate = PromotionGate(
            name="exploding",
            check_fn=bad_gate,
            required_for={MaturityLevel.BETA},
        )
        checker = PromotionChecker(gates=[gate])
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            {},
        )
        assert report.overall_passed is False
        assert "exploding" in report.blockers
        assert "exception" in report.gates[0].reason.lower()

    def test_deprecation_always_allowed(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.STABLE,
            MaturityLevel.DEPRECATED,
            {},
        )
        # No gates required for DEPRECATED, so should pass
        assert report.overall_passed is True

    def test_same_level_raises(self):
        checker = PromotionChecker()
        with pytest.raises(ValueError, match="same"):
            checker.check_promotion(
                "agent-1",
                MaturityLevel.BETA,
                MaturityLevel.BETA,
                {},
            )

    def test_demotion_raises(self):
        checker = PromotionChecker()
        with pytest.raises(ValueError, match="demote"):
            checker.check_promotion(
                "agent-1",
                MaturityLevel.STABLE,
                MaturityLevel.BETA,
                {},
            )

    def test_report_attributes(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            _full_pass_context(),
        )
        assert report.agent_id == "agent-1"
        assert report.current_level == MaturityLevel.EXPERIMENTAL
        assert report.target_level == MaturityLevel.BETA

    def test_only_target_level_gates_evaluated(self):
        """Gates not required_for the target level should be skipped."""
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.BETA,
            _full_pass_context(),
        )
        gate_names = {g.gate_name for g in report.gates}
        # SLO, error_budget, change_control are STABLE-only
        assert "slo_compliance_gate" not in gate_names
        assert "error_budget_gate" not in gate_names
        assert "change_control_gate" not in gate_names

    def test_stable_includes_all_gates(self):
        checker = PromotionChecker()
        report = checker.check_promotion(
            "agent-1",
            MaturityLevel.BETA,
            MaturityLevel.STABLE,
            _full_pass_context(),
        )
        gate_names = {g.gate_name for g in report.gates}
        assert "slo_compliance_gate" in gate_names
        assert "error_budget_gate" in gate_names
        assert "change_control_gate" in gate_names
