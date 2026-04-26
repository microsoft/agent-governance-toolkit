# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for content and knowledge quality governance (issue #734)."""

from __future__ import annotations

import pytest

from agent_os.content_governance import (
    ContentDimension,
    ContentEvaluation,
    ContentQualityEvaluator,
    ContentQualityReport,
    ContentQualityRule,
    QualityGate,
)


# ---------------------------------------------------------------------------
# Issue #734: Content quality governance
# ---------------------------------------------------------------------------


class TestBasicEvaluation:
    """Tests for basic pass / fail / warn evaluation logic."""

    def test_score_above_threshold_passes(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-check",
            dimension=ContentDimension.ACCURACY,
            threshold=0.8,
            gate=QualityGate.FAIL,
        ))
        report = evaluator.evaluate(
            agent_id="agent-1",
            content_id="resp-1",
            scores={ContentDimension.ACCURACY: 0.9},
        )
        assert report.passed
        assert len(report.evaluations) == 1
        assert report.evaluations[0].gate_result == QualityGate.PASS

    def test_score_at_threshold_passes(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-check",
            dimension=ContentDimension.ACCURACY,
            threshold=0.8,
            gate=QualityGate.FAIL,
        ))
        report = evaluator.evaluate(
            agent_id="agent-1",
            content_id="resp-2",
            scores={ContentDimension.ACCURACY: 0.8},
        )
        assert report.passed
        assert report.evaluations[0].gate_result == QualityGate.PASS

    def test_score_below_threshold_fails(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-check",
            dimension=ContentDimension.ACCURACY,
            threshold=0.8,
            gate=QualityGate.FAIL,
        ))
        report = evaluator.evaluate(
            agent_id="agent-1",
            content_id="resp-3",
            scores={ContentDimension.ACCURACY: 0.75},
        )
        assert not report.passed
        assert report.evaluations[0].gate_result == QualityGate.FAIL
        assert len(report.failures) == 1

    def test_score_below_threshold_warns(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="freshness-check",
            dimension=ContentDimension.FRESHNESS,
            threshold=0.6,
            gate=QualityGate.WARN,
        ))
        report = evaluator.evaluate(
            agent_id="agent-1",
            content_id="resp-4",
            scores={ContentDimension.FRESHNESS: 0.5},
        )
        # warn does not block passing
        assert report.passed
        assert report.evaluations[0].gate_result == QualityGate.WARN
        assert len(report.warnings) == 1

    def test_missing_score_defaults_to_zero(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="relevance-check",
            dimension=ContentDimension.RELEVANCE,
            threshold=0.5,
            gate=QualityGate.FAIL,
        ))
        report = evaluator.evaluate(
            agent_id="agent-1",
            content_id="resp-5",
            scores={},  # no scores provided
        )
        assert not report.passed
        assert report.evaluations[0].score == 0.0


class TestOverallScore:
    """Tests for overall score calculation."""

    def test_single_evaluation_score(self) -> None:
        report = ContentQualityReport(
            agent_id="a",
            content_id="c",
            evaluations=[
                ContentEvaluation(
                    dimension=ContentDimension.ACCURACY,
                    score=0.85,
                    gate_result=QualityGate.PASS,
                    rule_name="r1",
                ),
            ],
        )
        assert report.overall_score == pytest.approx(0.85)

    def test_multiple_evaluations_averaged(self) -> None:
        report = ContentQualityReport(
            agent_id="a",
            content_id="c",
            evaluations=[
                ContentEvaluation(
                    dimension=ContentDimension.ACCURACY,
                    score=0.9,
                    gate_result=QualityGate.PASS,
                    rule_name="r1",
                ),
                ContentEvaluation(
                    dimension=ContentDimension.COMPLETENESS,
                    score=0.7,
                    gate_result=QualityGate.WARN,
                    rule_name="r2",
                ),
            ],
        )
        assert report.overall_score == pytest.approx(0.8)

    def test_empty_evaluations_returns_zero(self) -> None:
        report = ContentQualityReport(
            agent_id="a",
            content_id="c",
            evaluations=[],
        )
        assert report.overall_score == 0.0


class TestLoadRulesFromDict:
    """Tests for loading rules from dict config."""

    def test_load_minimal_rule(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.load_rules([
            {
                "name": "min-accuracy",
                "dimension": "accuracy",
                "threshold": 0.7,
            },
        ])
        report = evaluator.evaluate(
            agent_id="a",
            content_id="c",
            scores={ContentDimension.ACCURACY: 0.8},
        )
        assert report.passed
        assert report.evaluations[0].rule_name == "min-accuracy"
        # default gate is WARN
        assert report.evaluations[0].gate_result == QualityGate.PASS

    def test_load_full_rule(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.load_rules([
            {
                "name": "strict-completeness",
                "dimension": "completeness",
                "threshold": 0.9,
                "gate": "fail",
                "description": "Content must be complete",
            },
        ])
        report = evaluator.evaluate(
            agent_id="a",
            content_id="c",
            scores={ContentDimension.COMPLETENESS: 0.85},
        )
        assert not report.passed
        assert report.evaluations[0].gate_result == QualityGate.FAIL

    def test_load_multiple_rules(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.load_rules([
            {"name": "r1", "dimension": "accuracy", "threshold": 0.5},
            {"name": "r2", "dimension": "freshness", "threshold": 0.6},
        ])
        report = evaluator.evaluate(
            agent_id="a",
            content_id="c",
            scores={
                ContentDimension.ACCURACY: 0.8,
                ContentDimension.FRESHNESS: 0.9,
            },
        )
        assert len(report.evaluations) == 2
        assert report.passed


class TestEmptyRules:
    """Tests for empty rules producing empty report."""

    def test_no_rules_returns_empty_evaluations(self) -> None:
        evaluator = ContentQualityEvaluator()
        report = evaluator.evaluate(
            agent_id="agent-x",
            content_id="content-y",
            scores={ContentDimension.ACCURACY: 0.99},
        )
        assert report.evaluations == []
        assert report.passed  # no failures
        assert report.overall_score == 0.0

    def test_empty_report_metadata(self) -> None:
        evaluator = ContentQualityEvaluator()
        report = evaluator.evaluate(
            agent_id="agent-x",
            content_id="content-y",
            scores={},
        )
        assert report.agent_id == "agent-x"
        assert report.content_id == "content-y"
        assert report.warnings == []
        assert report.failures == []


class TestMultipleRulesSameDimension:
    """Tests for multiple rules targeting the same dimension."""

    def test_two_rules_same_dimension_both_pass(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-warn",
            dimension=ContentDimension.ACCURACY,
            threshold=0.5,
            gate=QualityGate.WARN,
        ))
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-fail",
            dimension=ContentDimension.ACCURACY,
            threshold=0.8,
            gate=QualityGate.FAIL,
        ))
        report = evaluator.evaluate(
            agent_id="a",
            content_id="c",
            scores={ContentDimension.ACCURACY: 0.9},
        )
        assert report.passed
        assert len(report.evaluations) == 2
        assert all(e.gate_result == QualityGate.PASS for e in report.evaluations)

    def test_two_rules_same_dimension_one_fails(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-warn",
            dimension=ContentDimension.ACCURACY,
            threshold=0.5,
            gate=QualityGate.WARN,
        ))
        evaluator.add_rule(ContentQualityRule(
            name="accuracy-fail",
            dimension=ContentDimension.ACCURACY,
            threshold=0.8,
            gate=QualityGate.FAIL,
        ))
        report = evaluator.evaluate(
            agent_id="a",
            content_id="c",
            scores={ContentDimension.ACCURACY: 0.6},
        )
        assert not report.passed
        assert len(report.evaluations) == 2
        # first rule passes, second fails
        assert report.evaluations[0].gate_result == QualityGate.PASS
        assert report.evaluations[1].gate_result == QualityGate.FAIL
        assert len(report.failures) == 1

    def test_details_string_contains_scores(self) -> None:
        evaluator = ContentQualityEvaluator()
        evaluator.add_rule(ContentQualityRule(
            name="r",
            dimension=ContentDimension.STRUCTURE,
            threshold=0.7,
            gate=QualityGate.WARN,
        ))
        report = evaluator.evaluate(
            agent_id="a",
            content_id="c",
            scores={ContentDimension.STRUCTURE: 0.65},
        )
        details = report.evaluations[0].details
        assert "0.65" in details
        assert "0.70" in details
