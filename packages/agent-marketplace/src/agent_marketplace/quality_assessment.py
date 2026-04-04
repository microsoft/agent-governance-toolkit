# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Multi-dimensional quality assessment for plugins and agents.

Goes beyond binary pass/fail to provide actionable quality scores
across multiple dimensions with improvement recommendations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AssessmentDimension(str, Enum):
    """Dimensions for multi-faceted plugin quality evaluation."""

    SECURITY_POSTURE = "security_posture"
    DOCUMENTATION = "documentation"
    OPERATIONAL_READINESS = "operational_readiness"
    TEST_COVERAGE = "test_coverage"
    API_DESIGN = "api_design"
    PERFORMANCE = "performance"


class AssessmentGrade(str, Enum):
    """Letter grades for quality assessment results."""

    A = "A"    # 90-100: Excellent
    B = "B"    # 75-89: Good
    C = "C"    # 60-74: Adequate
    D = "D"    # 40-59: Needs improvement
    F = "F"    # 0-39: Failing


@dataclass
class DimensionResult:
    """Assessment result for a single dimension."""

    dimension: AssessmentDimension
    score: float  # 0-100
    max_score: float = 100.0
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def grade(self) -> AssessmentGrade:
        pct = (self.score / self.max_score) * 100 if self.max_score > 0 else 0
        if pct >= 90:
            return AssessmentGrade.A
        if pct >= 75:
            return AssessmentGrade.B
        if pct >= 60:
            return AssessmentGrade.C
        if pct >= 40:
            return AssessmentGrade.D
        return AssessmentGrade.F

    @property
    def percentage(self) -> float:
        return (self.score / self.max_score) * 100 if self.max_score > 0 else 0.0


@dataclass
class QualityAssessmentReport:
    """Complete multi-dimensional quality assessment."""

    name: str
    version: str
    dimensions: list[DimensionResult] = field(default_factory=list)

    @property
    def overall_score(self) -> float:
        if not self.dimensions:
            return 0.0
        return sum(d.percentage for d in self.dimensions) / len(self.dimensions)

    @property
    def overall_grade(self) -> AssessmentGrade:
        s = self.overall_score
        if s >= 90:
            return AssessmentGrade.A
        if s >= 75:
            return AssessmentGrade.B
        if s >= 60:
            return AssessmentGrade.C
        if s >= 40:
            return AssessmentGrade.D
        return AssessmentGrade.F

    @property
    def top_recommendations(self) -> list[str]:
        recs: list[str] = []
        for d in sorted(self.dimensions, key=lambda x: x.percentage):
            recs.extend(d.recommendations[:2])
        return recs[:5]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "overall_score": round(self.overall_score, 1),
            "overall_grade": self.overall_grade.value,
            "dimensions": [
                {
                    "dimension": d.dimension.value,
                    "score": d.score,
                    "max_score": d.max_score,
                    "grade": d.grade.value,
                    "percentage": round(d.percentage, 1),
                    "findings": d.findings,
                    "recommendations": d.recommendations,
                }
                for d in self.dimensions
            ],
            "top_recommendations": self.top_recommendations,
        }


class QualityAssessor:
    """Runs multi-dimensional quality assessments."""

    def __init__(self) -> None:
        self._evaluators: dict[AssessmentDimension, Any] = {}

    def assess_security(
        self,
        has_owasp: bool,
        has_mcp_safety: bool,
        has_injection_defense: bool,
        has_signing: bool,
    ) -> DimensionResult:
        score: float = 0.0
        findings: list[str] = []
        recs: list[str] = []
        if has_owasp:
            score += 30
            findings.append("OWASP compliance verified")
        else:
            recs.append("Add OWASP Top 10 compliance checks")
        if has_mcp_safety:
            score += 25
            findings.append("MCP safety scanning enabled")
        else:
            recs.append("Enable MCP tool poisoning detection")
        if has_injection_defense:
            score += 25
            findings.append("Prompt injection defense active")
        else:
            recs.append("Add prompt injection detection")
        if has_signing:
            score += 20
            findings.append("Package signing configured")
        else:
            recs.append("Sign packages for supply chain integrity")
        return DimensionResult(
            AssessmentDimension.SECURITY_POSTURE, score, 100, findings, recs,
        )

    def assess_documentation(
        self,
        has_readme: bool,
        has_examples: bool,
        has_api_docs: bool,
        has_changelog: bool,
    ) -> DimensionResult:
        score: float = 0.0
        findings: list[str] = []
        recs: list[str] = []
        if has_readme:
            score += 30
            findings.append("README present")
        else:
            recs.append("Add a comprehensive README")
        if has_examples:
            score += 30
            findings.append("Usage examples provided")
        else:
            recs.append("Add usage examples and tutorials")
        if has_api_docs:
            score += 25
            findings.append("API documentation available")
        else:
            recs.append("Generate API reference documentation")
        if has_changelog:
            score += 15
            findings.append("CHANGELOG maintained")
        else:
            recs.append("Maintain a CHANGELOG for version history")
        return DimensionResult(
            AssessmentDimension.DOCUMENTATION, score, 100, findings, recs,
        )

    def assess_testing(
        self,
        test_count: int,
        has_integration_tests: bool,
        has_edge_cases: bool,
    ) -> DimensionResult:
        score: float = 0.0
        findings: list[str] = []
        recs: list[str] = []
        if test_count >= 20:
            score += 40
            findings.append(f"{test_count} tests")
        elif test_count >= 10:
            score += 25
            findings.append(f"{test_count} tests")
            recs.append("Add more tests (target 20+)")
        elif test_count > 0:
            score += 10
            findings.append(f"{test_count} tests")
            recs.append("Significantly increase test count")
        else:
            recs.append("Add unit tests")
        if has_integration_tests:
            score += 35
            findings.append("Integration tests present")
        else:
            recs.append("Add integration tests")
        if has_edge_cases:
            score += 25
            findings.append("Edge case coverage")
        else:
            recs.append("Add edge case and error path tests")
        return DimensionResult(
            AssessmentDimension.TEST_COVERAGE, score, 100, findings, recs,
        )

    def assess_operational(
        self,
        has_owner: bool,
        has_telemetry: bool,
        has_health_check: bool,
        has_license: bool,
    ) -> DimensionResult:
        score: float = 0.0
        findings: list[str] = []
        recs: list[str] = []
        if has_owner:
            score += 25
            findings.append("Owner declared")
        else:
            recs.append("Declare a maintainer/owner")
        if has_telemetry:
            score += 25
            findings.append("Telemetry instrumented")
        else:
            recs.append("Add observability instrumentation")
        if has_health_check:
            score += 25
            findings.append("Health check endpoint")
        else:
            recs.append("Implement health check endpoint")
        if has_license:
            score += 25
            findings.append("License declared")
        else:
            recs.append("Add license file")
        return DimensionResult(
            AssessmentDimension.OPERATIONAL_READINESS, score, 100, findings, recs,
        )