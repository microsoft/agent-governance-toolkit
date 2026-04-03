# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Execution-context-aware policy enforcement.

Policies behave differently depending on where they run:
- inner_loop (IDE/CLI): advisory, blocks only critical violations
- ci_cd (pipeline): enforces anti-patterns, warns on advisory
- autonomous (agent runtime): strictest, blocks everything non-compliant
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutionContext(str, Enum):
    INNER_LOOP = "inner_loop"    # IDE, CLI, local dev
    CI_CD = "ci_cd"              # Pipeline, PR checks
    AUTONOMOUS = "autonomous"    # Agent runtime, production


class EnforcementLevel(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    AUDIT = "audit"        # log only, no user-visible output
    SKIP = "skip"


@dataclass
class ContextualPolicyRule:
    """A policy rule with per-context enforcement levels."""

    name: str
    category: str = ""
    description: str = ""
    default_level: EnforcementLevel = EnforcementLevel.WARN
    context_overrides: dict[ExecutionContext, EnforcementLevel] = field(
        default_factory=dict,
    )

    def effective_level(self, context: ExecutionContext) -> EnforcementLevel:
        return self.context_overrides.get(context, self.default_level)


@dataclass
class PolicyViolation:
    """A detected policy violation with context-aware severity."""

    rule_name: str
    message: str
    level: EnforcementLevel
    context: ExecutionContext
    location: str = ""
    suggestion: str = ""


class ContextualPolicyEngine:
    """Policy engine that adjusts enforcement based on execution context."""

    def __init__(
        self, context: ExecutionContext = ExecutionContext.CI_CD,
    ) -> None:
        self._context = context
        self._rules: list[ContextualPolicyRule] = []
        self._violations: list[PolicyViolation] = []

    @property
    def context(self) -> ExecutionContext:
        return self._context

    def add_rule(self, rule: ContextualPolicyRule) -> None:
        self._rules.append(rule)

    def load_rules(self, rules: list[dict[str, Any]]) -> None:
        for r in rules:
            overrides: dict[ExecutionContext, EnforcementLevel] = {}
            for ctx_name, level_name in r.get("context_overrides", {}).items():
                overrides[ExecutionContext(ctx_name)] = EnforcementLevel(level_name)
            self._rules.append(
                ContextualPolicyRule(
                    name=r["name"],
                    category=r.get("category", ""),
                    description=r.get("description", ""),
                    default_level=EnforcementLevel(
                        r.get("default_level", "warn"),
                    ),
                    context_overrides=overrides,
                ),
            )

    def evaluate(
        self,
        rule_name: str,
        message: str,
        location: str = "",
        suggestion: str = "",
    ) -> PolicyViolation | None:
        rule = next((r for r in self._rules if r.name == rule_name), None)
        if rule is None:
            return None
        level = rule.effective_level(self._context)
        if level == EnforcementLevel.SKIP:
            return None
        violation = PolicyViolation(
            rule_name=rule_name,
            message=message,
            level=level,
            context=self._context,
            location=location,
            suggestion=suggestion,
        )
        self._violations.append(violation)
        return violation

    @property
    def blocking_violations(self) -> list[PolicyViolation]:
        return [v for v in self._violations if v.level == EnforcementLevel.BLOCK]

    @property
    def warnings(self) -> list[PolicyViolation]:
        return [v for v in self._violations if v.level == EnforcementLevel.WARN]

    @property
    def has_blocking(self) -> bool:
        return len(self.blocking_violations) > 0

    def summary(self) -> dict[str, Any]:
        return {
            "context": self._context.value,
            "total_violations": len(self._violations),
            "blocking": len(self.blocking_violations),
            "warnings": len(self.warnings),
            "audit_only": len(
                [v for v in self._violations if v.level == EnforcementLevel.AUDIT],
            ),
        }
