# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agent reliability certification."""

from __future__ import annotations

from agent_sre.certification import (
    CertificationEvaluator,
    CertificationResult,
    CertificationTier,
    Criterion,
    CriterionResult,
)

# ---------------------------------------------------------------------------
# Evidence fixtures
# ---------------------------------------------------------------------------

BRONZE_EVIDENCE = {
    "has_slo": True,
    "has_tests": True,
    "has_cost_tracking": True,
    "has_error_handling": True,
}

SILVER_EVIDENCE = {
    **BRONZE_EVIDENCE,
    "slo_compliance": 0.97,
    "chaos_tested": True,
    "incident_count_30d": 3,
    "has_observability": True,
}

GOLD_EVIDENCE = {
    **SILVER_EVIDENCE,
    "slo_compliance": 0.995,
    "error_budget_managed": True,
    "has_canary": True,
    "has_postmortem": True,
}


# ---------------------------------------------------------------------------
# CriterionResult
# ---------------------------------------------------------------------------

class TestCriterionResult:
    def test_to_dict(self):
        cr = CriterionResult(name="test", passed=True, required=True, message="ok")
        d = cr.to_dict()
        assert d["name"] == "test"
        assert d["passed"] is True


# ---------------------------------------------------------------------------
# CertificationResult
# ---------------------------------------------------------------------------

class TestCertificationResult:
    def test_passed_counts(self):
        results = [
            CriterionResult("a", True, True),
            CriterionResult("b", False, True),
            CriterionResult("c", True, False),
        ]
        cert = CertificationResult(
            tier=CertificationTier.BRONZE,
            passed=False,
            criteria_results=results,
        )
        assert cert.required_passed == 1
        assert cert.required_total == 2
        assert cert.optional_passed == 1

    def test_failures(self):
        results = [
            CriterionResult("a", True, True),
            CriterionResult("b", False, True, "Required not met"),
            CriterionResult("c", False, False, "Advisory"),
        ]
        cert = CertificationResult(
            tier=CertificationTier.BRONZE,
            passed=False,
            criteria_results=results,
        )
        failures = cert.failures
        assert len(failures) == 1
        assert failures[0].name == "b"

    def test_to_dict(self):
        cert = CertificationResult(
            tier=CertificationTier.SILVER,
            passed=True,
            agent_id="agent-1",
            certificate_id="abc123",
        )
        d = cert.to_dict()
        assert d["tier"] == "silver"
        assert d["passed"] is True
        assert d["agent_id"] == "agent-1"
        assert d["certificate_id"] == "abc123"


# ---------------------------------------------------------------------------
# CertificationEvaluator — tier criteria
# ---------------------------------------------------------------------------

class TestEvaluatorCriteria:
    def test_default_criteria_count(self):
        ev = CertificationEvaluator()
        assert len(ev.criteria) == 12  # 4 bronze + 4 silver + 4 gold

    def test_bronze_criteria(self):
        ev = CertificationEvaluator()
        bronze = ev.criteria_for_tier(CertificationTier.BRONZE)
        assert len(bronze) == 4

    def test_silver_criteria_includes_bronze(self):
        ev = CertificationEvaluator()
        silver = ev.criteria_for_tier(CertificationTier.SILVER)
        assert len(silver) == 8  # 4 bronze + 4 silver

    def test_gold_criteria_includes_all(self):
        ev = CertificationEvaluator()
        gold = ev.criteria_for_tier(CertificationTier.GOLD)
        assert len(gold) == 12


# ---------------------------------------------------------------------------
# CertificationEvaluator — bronze
# ---------------------------------------------------------------------------

class TestBronzeCertification:
    def test_bronze_passes(self):
        ev = CertificationEvaluator()
        result = ev.evaluate(CertificationTier.BRONZE, BRONZE_EVIDENCE)
        assert result.passed is True
        assert result.tier == CertificationTier.BRONZE
        assert result.certificate_id != ""

    def test_bronze_fails_no_slo(self):
        ev = CertificationEvaluator()
        evidence = {**BRONZE_EVIDENCE, "has_slo": False}
        result = ev.evaluate(CertificationTier.BRONZE, evidence)
        assert result.passed is False
        assert result.certificate_id == ""

    def test_bronze_fails_no_tests(self):
        ev = CertificationEvaluator()
        evidence = {**BRONZE_EVIDENCE, "has_tests": False}
        result = ev.evaluate(CertificationTier.BRONZE, evidence)
        assert result.passed is False

    def test_bronze_fails_empty_evidence(self):
        ev = CertificationEvaluator()
        result = ev.evaluate(CertificationTier.BRONZE, {})
        assert result.passed is False


# ---------------------------------------------------------------------------
# CertificationEvaluator — silver
# ---------------------------------------------------------------------------

class TestSilverCertification:
    def test_silver_passes(self):
        ev = CertificationEvaluator()
        result = ev.evaluate(CertificationTier.SILVER, SILVER_EVIDENCE)
        assert result.passed is True
        assert result.tier == CertificationTier.SILVER

    def test_silver_fails_low_compliance(self):
        ev = CertificationEvaluator()
        evidence = {**SILVER_EVIDENCE, "slo_compliance": 0.90}
        result = ev.evaluate(CertificationTier.SILVER, evidence)
        assert result.passed is False

    def test_silver_fails_too_many_incidents(self):
        ev = CertificationEvaluator()
        evidence = {**SILVER_EVIDENCE, "incident_count_30d": 10}
        result = ev.evaluate(CertificationTier.SILVER, evidence)
        assert result.passed is False

    def test_silver_fails_no_chaos(self):
        ev = CertificationEvaluator()
        evidence = {**SILVER_EVIDENCE, "chaos_tested": False}
        result = ev.evaluate(CertificationTier.SILVER, evidence)
        assert result.passed is False


# ---------------------------------------------------------------------------
# CertificationEvaluator — gold
# ---------------------------------------------------------------------------

class TestGoldCertification:
    def test_gold_passes(self):
        ev = CertificationEvaluator()
        result = ev.evaluate(CertificationTier.GOLD, GOLD_EVIDENCE)
        assert result.passed is True
        assert result.tier == CertificationTier.GOLD

    def test_gold_fails_low_compliance(self):
        ev = CertificationEvaluator()
        evidence = {**GOLD_EVIDENCE, "slo_compliance": 0.97}
        result = ev.evaluate(CertificationTier.GOLD, evidence)
        assert result.passed is False

    def test_gold_passes_without_postmortem(self):
        ev = CertificationEvaluator()
        evidence = {**GOLD_EVIDENCE, "has_postmortem": False}
        result = ev.evaluate(CertificationTier.GOLD, evidence)
        # postmortem is advisory (required=False), so should still pass
        assert result.passed is True
        assert result.optional_passed < len([
            c for c in result.criteria_results if not c.required
        ])

    def test_gold_requires_canary(self):
        ev = CertificationEvaluator()
        evidence = {**GOLD_EVIDENCE, "has_canary": False}
        result = ev.evaluate(CertificationTier.GOLD, evidence)
        assert result.passed is False


# ---------------------------------------------------------------------------
# CertificationEvaluator — highest_tier
# ---------------------------------------------------------------------------

class TestHighestTier:
    def test_highest_is_gold(self):
        ev = CertificationEvaluator()
        result = ev.highest_tier(GOLD_EVIDENCE)
        assert result.tier == CertificationTier.GOLD
        assert result.passed is True

    def test_highest_is_silver(self):
        ev = CertificationEvaluator()
        # Pass silver but not gold
        evidence = {**SILVER_EVIDENCE, "slo_compliance": 0.97}
        result = ev.highest_tier(evidence)
        assert result.tier == CertificationTier.SILVER
        assert result.passed is True

    def test_highest_is_bronze(self):
        ev = CertificationEvaluator()
        result = ev.highest_tier(BRONZE_EVIDENCE)
        assert result.tier == CertificationTier.BRONZE
        assert result.passed is True

    def test_highest_is_failed_bronze(self):
        ev = CertificationEvaluator()
        result = ev.highest_tier({})
        assert result.tier == CertificationTier.BRONZE
        assert result.passed is False

    def test_highest_with_agent_id(self):
        ev = CertificationEvaluator()
        result = ev.highest_tier(GOLD_EVIDENCE, agent_id="my-agent")
        assert result.agent_id == "my-agent"


# ---------------------------------------------------------------------------
# Custom criteria
# ---------------------------------------------------------------------------

class TestCustomCriteria:
    def test_custom_evaluator(self):
        custom = [
            Criterion(
                name="custom-check",
                description="Custom requirement",
                tier=CertificationTier.BRONZE,
                check_fn=lambda e: e.get("custom_value", 0) > 10,
            ),
        ]
        ev = CertificationEvaluator(criteria=custom)
        result = ev.evaluate(CertificationTier.BRONZE, {"custom_value": 15})
        assert result.passed is True

    def test_custom_criterion_fails(self):
        custom = [
            Criterion(
                name="custom-check",
                description="Must have X",
                tier=CertificationTier.BRONZE,
                check_fn=lambda e: e.get("x", False),
            ),
        ]
        ev = CertificationEvaluator(criteria=custom)
        result = ev.evaluate(CertificationTier.BRONZE, {})
        assert result.passed is False
