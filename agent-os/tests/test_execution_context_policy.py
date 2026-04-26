# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import pytest

from agent_os.execution_context_policy import (
    ContextualPolicyEngine,
    ContextualPolicyRule,
    EnforcementLevel,
    ExecutionContext,
    PolicyViolation,
)


# ---------------------------------------------------------------------------
# ExecutionContext & EnforcementLevel enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_execution_context_values(self) -> None:
        assert ExecutionContext.INNER_LOOP.value == "inner_loop"
        assert ExecutionContext.CI_CD.value == "ci_cd"
        assert ExecutionContext.AUTONOMOUS.value == "autonomous"

    def test_enforcement_level_values(self) -> None:
        assert EnforcementLevel.BLOCK.value == "block"
        assert EnforcementLevel.WARN.value == "warn"
        assert EnforcementLevel.AUDIT.value == "audit"
        assert EnforcementLevel.SKIP.value == "skip"


# ---------------------------------------------------------------------------
# ContextualPolicyRule
# ---------------------------------------------------------------------------


class TestContextualPolicyRule:
    def test_effective_level_returns_default_when_no_override(self) -> None:
        rule = ContextualPolicyRule(name="r1", default_level=EnforcementLevel.WARN)
        assert rule.effective_level(ExecutionContext.INNER_LOOP) == EnforcementLevel.WARN

    def test_effective_level_returns_override(self) -> None:
        rule = ContextualPolicyRule(
            name="r1",
            default_level=EnforcementLevel.WARN,
            context_overrides={ExecutionContext.AUTONOMOUS: EnforcementLevel.BLOCK},
        )
        assert rule.effective_level(ExecutionContext.AUTONOMOUS) == EnforcementLevel.BLOCK
        assert rule.effective_level(ExecutionContext.CI_CD) == EnforcementLevel.WARN

    def test_rule_category_and_description_defaults(self) -> None:
        rule = ContextualPolicyRule(name="r2")
        assert rule.category == ""
        assert rule.description == ""


# ---------------------------------------------------------------------------
# ContextualPolicyEngine - basic behaviour
# ---------------------------------------------------------------------------


class TestContextualPolicyEngine:
    def test_default_context_is_ci_cd(self) -> None:
        engine = ContextualPolicyEngine()
        assert engine.context == ExecutionContext.CI_CD

    def test_custom_context(self) -> None:
        engine = ContextualPolicyEngine(context=ExecutionContext.AUTONOMOUS)
        assert engine.context == ExecutionContext.AUTONOMOUS

    def test_evaluate_unknown_rule_returns_none(self) -> None:
        engine = ContextualPolicyEngine()
        result = engine.evaluate("nonexistent", "msg")
        assert result is None

    def test_evaluate_skip_level_returns_none(self) -> None:
        engine = ContextualPolicyEngine(context=ExecutionContext.INNER_LOOP)
        rule = ContextualPolicyRule(
            name="skip-me",
            default_level=EnforcementLevel.WARN,
            context_overrides={ExecutionContext.INNER_LOOP: EnforcementLevel.SKIP},
        )
        engine.add_rule(rule)
        assert engine.evaluate("skip-me", "should skip") is None

    def test_evaluate_returns_violation_with_correct_fields(self) -> None:
        engine = ContextualPolicyEngine(context=ExecutionContext.AUTONOMOUS)
        rule = ContextualPolicyRule(
            name="sec-01",
            default_level=EnforcementLevel.WARN,
            context_overrides={ExecutionContext.AUTONOMOUS: EnforcementLevel.BLOCK},
        )
        engine.add_rule(rule)
        v = engine.evaluate("sec-01", "no auth", location="api.py:10", suggestion="add auth")
        assert v is not None
        assert v.rule_name == "sec-01"
        assert v.level == EnforcementLevel.BLOCK
        assert v.context == ExecutionContext.AUTONOMOUS
        assert v.location == "api.py:10"
        assert v.suggestion == "add auth"


# ---------------------------------------------------------------------------
# Blocking / warning classification
# ---------------------------------------------------------------------------


class TestViolationClassification:
    def _build_engine(self) -> ContextualPolicyEngine:
        engine = ContextualPolicyEngine(context=ExecutionContext.CI_CD)
        engine.add_rule(ContextualPolicyRule(
            name="block-rule", default_level=EnforcementLevel.BLOCK,
        ))
        engine.add_rule(ContextualPolicyRule(
            name="warn-rule", default_level=EnforcementLevel.WARN,
        ))
        engine.add_rule(ContextualPolicyRule(
            name="audit-rule", default_level=EnforcementLevel.AUDIT,
        ))
        engine.evaluate("block-rule", "blocked")
        engine.evaluate("warn-rule", "warned")
        engine.evaluate("audit-rule", "audited")
        return engine

    def test_blocking_violations(self) -> None:
        engine = self._build_engine()
        assert len(engine.blocking_violations) == 1
        assert engine.blocking_violations[0].rule_name == "block-rule"

    def test_warnings(self) -> None:
        engine = self._build_engine()
        assert len(engine.warnings) == 1
        assert engine.warnings[0].rule_name == "warn-rule"

    def test_has_blocking(self) -> None:
        engine = self._build_engine()
        assert engine.has_blocking is True

    def test_has_blocking_false_when_none(self) -> None:
        engine = ContextualPolicyEngine()
        assert engine.has_blocking is False

    def test_summary(self) -> None:
        engine = self._build_engine()
        s = engine.summary()
        assert s["context"] == "ci_cd"
        assert s["total_violations"] == 3
        assert s["blocking"] == 1
        assert s["warnings"] == 1
        assert s["audit_only"] == 1


# ---------------------------------------------------------------------------
# Rule loading from dicts
# ---------------------------------------------------------------------------


class TestLoadRules:
    def test_load_rules_from_dicts(self) -> None:
        engine = ContextualPolicyEngine(context=ExecutionContext.AUTONOMOUS)
        engine.load_rules([
            {
                "name": "no-shell",
                "category": "security",
                "description": "Disallow shell execution",
                "default_level": "warn",
                "context_overrides": {
                    "autonomous": "block",
                    "inner_loop": "skip",
                },
            },
        ])
        v = engine.evaluate("no-shell", "shell detected")
        assert v is not None
        assert v.level == EnforcementLevel.BLOCK

    def test_load_rules_default_level_fallback(self) -> None:
        engine = ContextualPolicyEngine()
        engine.load_rules([{"name": "simple"}])
        v = engine.evaluate("simple", "msg")
        assert v is not None
        assert v.level == EnforcementLevel.WARN