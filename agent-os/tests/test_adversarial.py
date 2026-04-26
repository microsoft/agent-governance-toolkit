# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the adversarial evaluation module."""

from __future__ import annotations

import pytest

from agent_os.adversarial import (
    AdversarialEvaluator,
    AttackCategory,
    AttackVector,
    BUILTIN_VECTORS,
    EvaluationReport,
    VectorResult,
)
from agent_os.integrations.base import (
    GovernancePolicy,
    PatternType,
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strict_policy() -> GovernancePolicy:
    """A strict policy that blocks dangerous patterns and tools."""
    return GovernancePolicy(
        name="strict_test",
        allowed_tools=["read_file", "web_search"],
        blocked_patterns=[
            "rm -rf",
            "password",
            ("ignore.*instructions", PatternType.REGEX),
            ("eval\\(", PatternType.REGEX),
            ("sudo", PatternType.SUBSTRING),
            ("grant admin", PatternType.SUBSTRING),
            ("/etc/passwd", PatternType.SUBSTRING),
            ("disable_governance", PatternType.SUBSTRING),
            ("override", PatternType.SUBSTRING),
            ("superuser", PatternType.SUBSTRING),
            ("base64decode", PatternType.SUBSTRING),
        ],
    )


def _permissive_policy() -> GovernancePolicy:
    """A permissive policy that allows everything (for negative testing)."""
    return GovernancePolicy(name="permissive")


# ---------------------------------------------------------------------------
# Built-in vectors sanity checks
# ---------------------------------------------------------------------------

class TestBuiltinVectors:
    def test_builtin_vectors_not_empty(self):
        assert len(BUILTIN_VECTORS) >= 8

    def test_all_categories_covered(self):
        categories = {v.category for v in BUILTIN_VECTORS}
        assert AttackCategory.PROMPT_INJECTION in categories
        assert AttackCategory.TOOL_ABUSE in categories
        assert AttackCategory.POLICY_OVERRIDE in categories
        assert AttackCategory.PRIVILEGE_ESCALATION in categories

    def test_all_expect_blocked(self):
        for v in BUILTIN_VECTORS:
            assert v.expected_outcome == "blocked"


# ---------------------------------------------------------------------------
# Evaluator with strict policy — all vectors should be blocked
# ---------------------------------------------------------------------------

class TestEvaluatorStrict:
    def test_all_builtin_blocked(self):
        interceptor = PolicyInterceptor(_strict_policy())
        evaluator = AdversarialEvaluator(interceptor)
        report = evaluator.evaluate()

        assert report.total == len(BUILTIN_VECTORS)
        assert report.passed == report.total
        assert report.failed == 0
        assert report.risk_score == 0.0
        assert any("correctly" in r.lower() for r in report.recommendations)

    def test_custom_vector(self):
        interceptor = PolicyInterceptor(_strict_policy())
        evaluator = AdversarialEvaluator(interceptor)
        custom = [
            AttackVector(
                name="custom_bad",
                category=AttackCategory.TOOL_ABUSE,
                payload={"cmd": "rm -rf /tmp"},
                expected_outcome="blocked",
            )
        ]
        report = evaluator.evaluate(vectors=custom)
        assert report.total == 1
        assert report.passed == 1


# ---------------------------------------------------------------------------
# Evaluator with permissive policy — vectors should pass through (= failures)
# ---------------------------------------------------------------------------

class TestEvaluatorPermissive:
    def test_permissive_has_failures(self):
        interceptor = PolicyInterceptor(_permissive_policy())
        evaluator = AdversarialEvaluator(interceptor)
        report = evaluator.evaluate()

        assert report.failed > 0
        assert report.risk_score > 0.0

    def test_recommendations_generated(self):
        interceptor = PolicyInterceptor(_permissive_policy())
        evaluator = AdversarialEvaluator(interceptor)
        report = evaluator.evaluate()

        assert len(report.recommendations) > 0
        combined = " ".join(report.recommendations).lower()
        assert "blocked_patterns" in combined or "allowed_tools" in combined


# ---------------------------------------------------------------------------
# EvaluationReport dataclass
# ---------------------------------------------------------------------------

class TestEvaluationReport:
    def test_empty_report(self):
        r = EvaluationReport()
        assert r.total == 0
        assert r.risk_score == 0.0

    def test_vector_result_fields(self):
        v = AttackVector(
            name="test",
            category=AttackCategory.PROMPT_INJECTION,
            payload={},
        )
        vr = VectorResult(vector=v, actual_outcome="blocked", passed=True)
        assert vr.passed is True
        assert vr.actual_outcome == "blocked"
