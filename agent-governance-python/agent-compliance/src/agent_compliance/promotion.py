# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Lifecycle Promotion Gates — maturity tracking and automated gate checks.

Tracks agent lifecycle stages (experimental → beta → stable) with
automated promotion criteria validation.  Each *gate* is a named
check function that returns pass/fail with a reason.  A
:class:`PromotionChecker` aggregates gate results into a
:class:`PromotionReport` that indicates whether an agent is ready
to advance to the next maturity level.

Usage::

    from agent_compliance.promotion import (
        PromotionChecker, MaturityLevel,
    )

    checker = PromotionChecker()   # includes 9 built-in gates
    report = checker.check_promotion(
        agent_id="implementer",
        current=MaturityLevel.EXPERIMENTAL,
        target=MaturityLevel.BETA,
        context={
            "test_coverage": 82.5,
            "critical_vulns": 0,
            "slo_compliance_pct": 99.2,
            "slo_compliance_days": 14,
            "trust_score": 0.85,
            "peer_reviews": 3,
            "error_budget_remaining_pct": 42.0,
            "has_metrics": True,
            "has_logging": True,
            "has_readme": True,
            "has_api_docs": True,
            "has_approved_change_request": True,
        },
    )
    print(report.overall_passed)   # True / False
    print(report.blockers)         # list of failed gate names
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ── Enums & value objects ──────────────────────────────────────


class MaturityLevel(Enum):
    """Agent lifecycle maturity stages."""

    EXPERIMENTAL = "experimental"
    BETA = "beta"
    STABLE = "stable"
    DEPRECATED = "deprecated"


# Ordered progression (DEPRECATED can be reached from any level)
_PROGRESSION = [
    MaturityLevel.EXPERIMENTAL,
    MaturityLevel.BETA,
    MaturityLevel.STABLE,
]


@dataclass
class PromotionGate:
    """Definition of a single promotion gate.

    Attributes:
        name: Human-readable gate name.
        check_fn: Callable ``(context: dict) -> (passed: bool, reason: str)``.
        required_for: Set of target maturity levels where this gate applies.
        severity: ``"blocker"`` (blocks promotion) or ``"warning"`` (advisory).
    """

    name: str
    check_fn: Callable[[dict[str, Any]], tuple[bool, str]]
    required_for: set[MaturityLevel] = field(
        default_factory=lambda: {MaturityLevel.BETA, MaturityLevel.STABLE}
    )
    severity: str = "blocker"


@dataclass
class PromotionResult:
    """Result of a single gate evaluation.

    Attributes:
        gate_name: Name of the evaluated gate.
        passed: Whether the gate passed.
        reason: Explanation of the outcome.
        details: Arbitrary extra data for audit.
    """

    gate_name: str
    passed: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PromotionReport:
    """Aggregate promotion evaluation.

    Attributes:
        agent_id: Agent being evaluated.
        current_level: Current maturity level.
        target_level: Target maturity level.
        gates: Individual gate results.
        overall_passed: ``True`` if **all** blocker gates passed.
        blockers: Names of failed blocker gates.
    """

    agent_id: str
    current_level: MaturityLevel
    target_level: MaturityLevel
    gates: list[PromotionResult] = field(default_factory=list)
    overall_passed: bool = True
    blockers: list[str] = field(default_factory=list)


# ── Built-in gate check functions ──────────────────────────────


def _test_coverage_check(context: dict[str, Any]) -> tuple[bool, str]:
    """Requires minimum test coverage percentage."""
    coverage = context.get("test_coverage", 0.0)
    threshold = context.get("test_coverage_threshold", 80.0)
    if coverage >= threshold:
        return True, f"Test coverage {coverage}% meets threshold {threshold}%"
    return False, f"Test coverage {coverage}% below threshold {threshold}%"


def _security_scan_check(context: dict[str, Any]) -> tuple[bool, str]:
    """No critical vulnerabilities allowed."""
    critical = context.get("critical_vulns", None)
    if critical is None:
        return False, "Security scan results not provided"
    if critical == 0:
        return True, "No critical vulnerabilities found"
    return False, f"{critical} critical vulnerability(ies) found"


def _slo_compliance_check(context: dict[str, Any]) -> tuple[bool, str]:
    """Meets SLO targets for a minimum number of days."""
    pct = context.get("slo_compliance_pct", 0.0)
    days = context.get("slo_compliance_days", 0)
    min_pct = context.get("slo_min_pct", 99.0)
    min_days = context.get("slo_min_days", 7)
    if pct >= min_pct and days >= min_days:
        return True, f"SLO {pct}% for {days} days meets targets"
    reasons = []
    if pct < min_pct:
        reasons.append(f"compliance {pct}% < {min_pct}%")
    if days < min_days:
        reasons.append(f"observation window {days}d < {min_days}d")
    return False, f"SLO not met: {'; '.join(reasons)}"


def _trust_score_check(context: dict[str, Any]) -> tuple[bool, str]:
    """Minimum trust score threshold."""
    score = context.get("trust_score", 0.0)
    threshold = context.get("trust_score_threshold", 0.7)
    if score >= threshold:
        return True, f"Trust score {score} meets threshold {threshold}"
    return False, f"Trust score {score} below threshold {threshold}"


def _peer_review_check(context: dict[str, Any]) -> tuple[bool, str]:
    """At least N peer reviews completed."""
    reviews = context.get("peer_reviews", 0)
    required = context.get("peer_reviews_required", 2)
    if reviews >= required:
        return True, f"{reviews} peer review(s) — meets requirement of {required}"
    return False, f"Only {reviews} peer review(s); {required} required"


def _error_budget_check(context: dict[str, Any]) -> tuple[bool, str]:
    """Remaining error budget above threshold."""
    remaining = context.get("error_budget_remaining_pct", 0.0)
    threshold = context.get("error_budget_threshold", 20.0)
    if remaining >= threshold:
        return True, f"Error budget {remaining}% above threshold {threshold}%"
    return False, f"Error budget {remaining}% below threshold {threshold}%"


def _observability_check(context: dict[str, Any]) -> tuple[bool, str]:
    """Metrics and logging must be configured."""
    has_metrics = context.get("has_metrics", False)
    has_logging = context.get("has_logging", False)
    missing = []
    if not has_metrics:
        missing.append("metrics")
    if not has_logging:
        missing.append("logging")
    if not missing:
        return True, "Metrics and logging configured"
    return False, f"Missing observability: {', '.join(missing)}"


def _documentation_check(context: dict[str, Any]) -> tuple[bool, str]:
    """README and API docs must be present."""
    has_readme = context.get("has_readme", False)
    has_api_docs = context.get("has_api_docs", False)
    missing = []
    if not has_readme:
        missing.append("README")
    if not has_api_docs:
        missing.append("API docs")
    if not missing:
        return True, "Documentation present"
    return False, f"Missing documentation: {', '.join(missing)}"


def _change_control_check(context: dict[str, Any]) -> tuple[bool, str]:
    """Approved change request must exist."""
    approved = context.get("has_approved_change_request", False)
    if approved:
        return True, "Approved change request exists"
    return False, "No approved change request found"


# Registry of default gates
_DEFAULT_GATES: list[PromotionGate] = [
    PromotionGate(
        name="test_coverage_gate",
        check_fn=_test_coverage_check,
        required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="security_scan_gate",
        check_fn=_security_scan_check,
        required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="slo_compliance_gate",
        check_fn=_slo_compliance_check,
        required_for={MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="trust_score_gate",
        check_fn=_trust_score_check,
        required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="peer_review_gate",
        check_fn=_peer_review_check,
        required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="error_budget_gate",
        check_fn=_error_budget_check,
        required_for={MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="observability_gate",
        check_fn=_observability_check,
        required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="documentation_gate",
        check_fn=_documentation_check,
        required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    ),
    PromotionGate(
        name="change_control_gate",
        check_fn=_change_control_check,
        required_for={MaturityLevel.STABLE},
        severity="blocker",
    ),
]


# ── Promotion Checker ──────────────────────────────────────────


class PromotionChecker:
    """Evaluates whether an agent is ready to promote to a higher maturity level.

    By default includes all 9 built-in gates.  Additional custom gates can
    be registered via :meth:`register_gate`.

    Args:
        gates: Optional explicit gate list.  When ``None`` the built-in
            defaults are used.
    """

    def __init__(
        self, gates: Optional[list[PromotionGate]] = None
    ) -> None:
        self._gates: list[PromotionGate] = (
            list(gates) if gates is not None else list(_DEFAULT_GATES)
        )

    # ── public API ──────────────────────────────────────────

    def register_gate(self, gate: PromotionGate) -> None:
        """Add a custom promotion gate.

        Args:
            gate: The gate definition to register.
        """
        self._gates.append(gate)

    def check_promotion(
        self,
        agent_id: str,
        current: MaturityLevel,
        target: MaturityLevel,
        context: dict[str, Any],
    ) -> PromotionReport:
        """Evaluate all applicable gates for a proposed promotion.

        Args:
            agent_id: Agent identifier.
            current: Current maturity level.
            target: Desired maturity level.
            context: Dict of metrics / signals consumed by gate check
                functions (e.g. ``test_coverage``, ``critical_vulns``).

        Returns:
            A :class:`PromotionReport` summarising gate results.

        Raises:
            ValueError: If the promotion direction is invalid.
        """
        self._validate_transition(current, target)

        results: list[PromotionResult] = []
        blockers: list[str] = []

        for gate in self._gates:
            if target not in gate.required_for:
                continue

            try:
                passed, reason = gate.check_fn(context)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Gate %s raised an exception: %s", gate.name, exc
                )
                passed = False
                reason = f"Gate raised exception: {exc}"

            result = PromotionResult(
                gate_name=gate.name,
                passed=passed,
                reason=reason,
            )
            results.append(result)

            if not passed and gate.severity == "blocker":
                blockers.append(gate.name)

        overall = len(blockers) == 0

        report = PromotionReport(
            agent_id=agent_id,
            current_level=current,
            target_level=target,
            gates=results,
            overall_passed=overall,
            blockers=blockers,
        )

        logger.info(
            "Promotion check %s → %s for %s: %s (blockers=%s)",
            current.value,
            target.value,
            agent_id,
            "PASSED" if overall else "BLOCKED",
            blockers,
        )
        return report

    # ── helpers ──────────────────────────────────────────────

    @staticmethod
    def _validate_transition(
        current: MaturityLevel, target: MaturityLevel
    ) -> None:
        """Raise if the transition is invalid."""
        if target == MaturityLevel.DEPRECATED:
            return  # anything can be deprecated

        if current == target:
            raise ValueError(
                f"Current and target levels are the same: {current.value}"
            )

        try:
            cur_idx = _PROGRESSION.index(current)
            tgt_idx = _PROGRESSION.index(target)
        except ValueError as exc:
            raise ValueError(
                f"Invalid level in progression: {exc}"
            ) from exc

        if tgt_idx <= cur_idx:
            raise ValueError(
                f"Cannot demote from {current.value} to {target.value}; "
                "use DEPRECATED for end-of-life"
            )
