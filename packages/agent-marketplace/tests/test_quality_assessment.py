# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import pytest

from agent_marketplace.quality_assessment import (
    AssessmentDimension,
    AssessmentGrade,
    DimensionResult,
    QualityAssessmentReport,
    QualityAssessor,
)


# ---------------------------------------------------------------------------
# DimensionResult
# ---------------------------------------------------------------------------


class TestDimensionResult:
    def test_grade_a(self) -> None:
        r = DimensionResult(AssessmentDimension.SECURITY_POSTURE, 95)
        assert r.grade == AssessmentGrade.A

    def test_grade_b(self) -> None:
        r = DimensionResult(AssessmentDimension.SECURITY_POSTURE, 80)
        assert r.grade == AssessmentGrade.B

    def test_grade_c(self) -> None:
        r = DimensionResult(AssessmentDimension.SECURITY_POSTURE, 65)
        assert r.grade == AssessmentGrade.C

    def test_grade_d(self) -> None:
        r = DimensionResult(AssessmentDimension.SECURITY_POSTURE, 45)
        assert r.grade == AssessmentGrade.D

    def test_grade_f(self) -> None:
        r = DimensionResult(AssessmentDimension.SECURITY_POSTURE, 20)
        assert r.grade == AssessmentGrade.F

    def test_percentage_calculation(self) -> None:
        r = DimensionResult(AssessmentDimension.DOCUMENTATION, 75, 150)
        assert r.percentage == pytest.approx(50.0)

    def test_percentage_zero_max_score(self) -> None:
        r = DimensionResult(AssessmentDimension.DOCUMENTATION, 50, 0)
        assert r.percentage == 0.0

    def test_grade_zero_max_score(self) -> None:
        r = DimensionResult(AssessmentDimension.DOCUMENTATION, 50, 0)
        assert r.grade == AssessmentGrade.F


# ---------------------------------------------------------------------------
# QualityAssessmentReport
# ---------------------------------------------------------------------------


class TestQualityAssessmentReport:
    def test_overall_score_empty(self) -> None:
        report = QualityAssessmentReport(name="test", version="1.0")
        assert report.overall_score == 0.0

    def test_overall_score_single_dimension(self) -> None:
        report = QualityAssessmentReport(
            name="test", version="1.0",
            dimensions=[DimensionResult(AssessmentDimension.SECURITY_POSTURE, 80)],
        )
        assert report.overall_score == pytest.approx(80.0)

    def test_overall_score_multiple_dimensions(self) -> None:
        report = QualityAssessmentReport(
            name="test", version="1.0",
            dimensions=[
                DimensionResult(AssessmentDimension.SECURITY_POSTURE, 90),
                DimensionResult(AssessmentDimension.DOCUMENTATION, 70),
            ],
        )
        assert report.overall_score == pytest.approx(80.0)

    def test_overall_grade(self) -> None:
        report = QualityAssessmentReport(
            name="test", version="1.0",
            dimensions=[DimensionResult(AssessmentDimension.SECURITY_POSTURE, 92)],
        )
        assert report.overall_grade == AssessmentGrade.A

    def test_top_recommendations_ordered_by_lowest_score(self) -> None:
        low = DimensionResult(
            AssessmentDimension.TEST_COVERAGE, 20,
            recommendations=["add tests", "add CI"],
        )
        high = DimensionResult(
            AssessmentDimension.SECURITY_POSTURE, 90,
            recommendations=["sign packages"],
        )
        report = QualityAssessmentReport(
            name="test", version="1.0", dimensions=[high, low],
        )
        recs = report.top_recommendations
        assert recs[0] == "add tests"
        assert recs[1] == "add CI"

    def test_top_recommendations_capped_at_five(self) -> None:
        dims = [
            DimensionResult(
                AssessmentDimension.SECURITY_POSTURE, 10,
                recommendations=["r1", "r2", "r3"],
            ),
            DimensionResult(
                AssessmentDimension.DOCUMENTATION, 20,
                recommendations=["r4", "r5", "r6"],
            ),
            DimensionResult(
                AssessmentDimension.TEST_COVERAGE, 30,
                recommendations=["r7", "r8", "r9"],
            ),
        ]
        report = QualityAssessmentReport(name="t", version="1", dimensions=dims)
        assert len(report.top_recommendations) == 5

    def test_to_dict_structure(self) -> None:
        dim = DimensionResult(
            AssessmentDimension.SECURITY_POSTURE, 80, 100,
            findings=["OWASP ok"], recommendations=["sign"],
        )
        report = QualityAssessmentReport(
            name="my-plugin", version="2.0", dimensions=[dim],
        )
        d = report.to_dict()
        assert d["name"] == "my-plugin"
        assert d["version"] == "2.0"
        assert d["overall_grade"] == "B"
        assert len(d["dimensions"]) == 1
        assert d["dimensions"][0]["dimension"] == "security_posture"
        assert d["dimensions"][0]["grade"] == "B"


# ---------------------------------------------------------------------------
# QualityAssessor methods
# ---------------------------------------------------------------------------


class TestQualityAssessor:
    def test_assess_security_full_score(self) -> None:
        a = QualityAssessor()
        r = a.assess_security(True, True, True, True)
        assert r.score == 100
        assert r.grade == AssessmentGrade.A
        assert len(r.recommendations) == 0

    def test_assess_security_no_checks(self) -> None:
        a = QualityAssessor()
        r = a.assess_security(False, False, False, False)
        assert r.score == 0
        assert r.grade == AssessmentGrade.F
        assert len(r.recommendations) == 4

    def test_assess_documentation_partial(self) -> None:
        a = QualityAssessor()
        r = a.assess_documentation(True, False, True, False)
        assert r.score == 55
        assert r.grade == AssessmentGrade.D

    def test_assess_testing_zero_tests(self) -> None:
        a = QualityAssessor()
        r = a.assess_testing(0, False, False)
        assert r.score == 0
        assert r.grade == AssessmentGrade.F

    def test_assess_testing_moderate(self) -> None:
        a = QualityAssessor()
        r = a.assess_testing(15, True, False)
        assert r.score == 60  # 25 + 35 + 0

    def test_assess_testing_full(self) -> None:
        a = QualityAssessor()
        r = a.assess_testing(25, True, True)
        assert r.score == 100
        assert r.grade == AssessmentGrade.A

    def test_assess_operational_all_present(self) -> None:
        a = QualityAssessor()
        r = a.assess_operational(True, True, True, True)
        assert r.score == 100
        assert len(r.findings) == 4