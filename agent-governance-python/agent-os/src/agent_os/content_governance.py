# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Content and knowledge quality governance for AI agents.

Runtime governance answers 'is the agent behavior safe?'
Content governance answers 'is the agent output accurate, well-structured,
and meeting quality standards?'
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContentDimension(str, Enum):
    """Dimensions for content quality evaluation."""
    ACCURACY = "accuracy"
    COMPLETENESS = "completeness"
    FRESHNESS = "freshness"
    STRUCTURE = "structure"
    RELEVANCE = "relevance"
    CONSISTENCY = "consistency"


class QualityGate(str, Enum):
    """Content quality gate decisions."""
    PASS = "pass"  # noqa: S105 — not a password, evaluation result constant
    WARN = "warn"
    FAIL = "fail"


@dataclass
class ContentQualityRule:
    """A rule for evaluating content quality."""
    name: str
    dimension: ContentDimension
    threshold: float  # 0.0 to 1.0
    gate: QualityGate = QualityGate.WARN
    description: str = ""


@dataclass
class ContentEvaluation:
    """Result of evaluating content against quality rules."""
    dimension: ContentDimension
    score: float
    gate_result: QualityGate
    rule_name: str
    details: str = ""


@dataclass
class ContentQualityReport:
    """Aggregated quality report for agent output."""
    agent_id: str
    content_id: str
    evaluations: list[ContentEvaluation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(e.gate_result != QualityGate.FAIL for e in self.evaluations)

    @property
    def overall_score(self) -> float:
        if not self.evaluations:
            return 0.0
        return sum(e.score for e in self.evaluations) / len(self.evaluations)

    @property
    def warnings(self) -> list[ContentEvaluation]:
        return [e for e in self.evaluations if e.gate_result == QualityGate.WARN]

    @property
    def failures(self) -> list[ContentEvaluation]:
        return [e for e in self.evaluations if e.gate_result == QualityGate.FAIL]


class ContentQualityEvaluator:
    """Evaluates agent output against content quality rules.

    Usage:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="min-accuracy",
            dimension=ContentDimension.ACCURACY,
            threshold=0.8,
            gate=QualityGate.FAIL,
        ))

        report = evaluator.evaluate(
            agent_id="agent-1",
            content_id="response-123",
            scores={ContentDimension.ACCURACY: 0.75},
        )
        assert not report.passed  # Below 0.8 threshold
    """

    def __init__(self) -> None:
        self._rules: list[ContentQualityRule] = []

    def add_rule(self, rule: ContentQualityRule) -> None:
        self._rules.append(rule)

    def load_rules(self, rules: list[dict[str, Any]]) -> None:
        """Load rules from a list of dicts (e.g., from YAML config)."""
        for r in rules:
            self._rules.append(ContentQualityRule(
                name=r["name"],
                dimension=ContentDimension(r["dimension"]),
                threshold=float(r["threshold"]),
                gate=QualityGate(r.get("gate", "warn")),
                description=r.get("description", ""),
            ))

    def evaluate(
        self,
        agent_id: str,
        content_id: str,
        scores: dict[ContentDimension, float],
    ) -> ContentQualityReport:
        """Evaluate content scores against configured rules."""
        evaluations = []
        for rule in self._rules:
            score = scores.get(rule.dimension, 0.0)
            if score >= rule.threshold:
                gate_result = QualityGate.PASS
            else:
                gate_result = rule.gate
            evaluations.append(ContentEvaluation(
                dimension=rule.dimension,
                score=score,
                gate_result=gate_result,
                rule_name=rule.name,
                details=f"Score {score:.2f} vs threshold {rule.threshold:.2f}",
            ))
        return ContentQualityReport(
            agent_id=agent_id,
            content_id=content_id,
            evaluations=evaluations,
        )
