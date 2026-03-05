# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Reliability Certification Program.

Defines certification tiers, criteria, and an evaluator that checks
whether an agent meets the requirements for a given tier.

Tiers:
- BRONZE: Basic reliability — SLO defined, tests exist, cost tracking enabled
- SILVER: Production-grade — SLO compliance >95%, chaos tested, incidents <5/month
- GOLD:   Enterprise-ready — SLO compliance >99%, full observability, error budget managed

Components:
- CertificationTier: Enum of certification levels
- Criterion: Individual requirement with check function
- CertificationResult: Pass/fail result with details
- CertificationEvaluator: Evaluates an agent against tier criteria

Usage:
    evaluator = CertificationEvaluator()
    result = evaluator.evaluate(
        tier=CertificationTier.SILVER,
        evidence={
            "slo_compliance": 0.97,
            "chaos_tested": True,
            "incident_count_30d": 3,
            "has_cost_tracking": True,
            "has_observability": True,
            "error_budget_managed": True,
        },
    )
    print(result.passed)  # True
    print(result.tier)    # CertificationTier.SILVER
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------

class CertificationTier(Enum):
    """Certification levels for agent reliability."""

    BRONZE = "bronze"    # Basic reliability
    SILVER = "silver"    # Production-grade
    GOLD = "gold"        # Enterprise-ready


# ---------------------------------------------------------------------------
# Criterion
# ---------------------------------------------------------------------------

@dataclass
class Criterion:
    """A single certification requirement."""

    name: str
    description: str
    tier: CertificationTier
    check_fn: Callable[[dict[str, Any]], bool]
    evidence_key: str = ""  # Key to look up in evidence dict
    required: bool = True   # If False, failure is advisory only

    def check(self, evidence: dict[str, Any]) -> bool:
        """Evaluate this criterion against provided evidence."""
        return self.check_fn(evidence)


@dataclass
class CriterionResult:
    """Result of evaluating a single criterion."""

    name: str
    passed: bool
    required: bool
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "required": self.required,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# Certification result
# ---------------------------------------------------------------------------

@dataclass
class CertificationResult:
    """Result of a certification evaluation."""

    tier: CertificationTier
    passed: bool
    agent_id: str = ""
    criteria_results: list[CriterionResult] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    certificate_id: str = ""

    @property
    def required_passed(self) -> int:
        return sum(1 for c in self.criteria_results if c.required and c.passed)

    @property
    def required_total(self) -> int:
        return sum(1 for c in self.criteria_results if c.required)

    @property
    def optional_passed(self) -> int:
        return sum(1 for c in self.criteria_results if not c.required and c.passed)

    @property
    def failures(self) -> list[CriterionResult]:
        return [c for c in self.criteria_results if not c.passed and c.required]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "passed": self.passed,
            "agent_id": self.agent_id,
            "certificate_id": self.certificate_id,
            "required_passed": self.required_passed,
            "required_total": self.required_total,
            "optional_passed": self.optional_passed,
            "criteria": [c.to_dict() for c in self.criteria_results],
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Default criteria
# ---------------------------------------------------------------------------

def _default_criteria() -> list[Criterion]:
    """Build the default certification criteria for all tiers."""
    criteria: list[Criterion] = []

    # -- BRONZE: Basic reliability --
    criteria.append(Criterion(
        name="slo-defined",
        description="At least one SLO is defined",
        tier=CertificationTier.BRONZE,
        evidence_key="has_slo",
        check_fn=lambda e: bool(e.get("has_slo", False)),
    ))
    criteria.append(Criterion(
        name="tests-exist",
        description="Agent has automated tests",
        tier=CertificationTier.BRONZE,
        evidence_key="has_tests",
        check_fn=lambda e: bool(e.get("has_tests", False)),
    ))
    criteria.append(Criterion(
        name="cost-tracking",
        description="Cost tracking is enabled",
        tier=CertificationTier.BRONZE,
        evidence_key="has_cost_tracking",
        check_fn=lambda e: bool(e.get("has_cost_tracking", False)),
    ))
    criteria.append(Criterion(
        name="error-handling",
        description="Agent handles errors gracefully",
        tier=CertificationTier.BRONZE,
        evidence_key="has_error_handling",
        check_fn=lambda e: bool(e.get("has_error_handling", False)),
    ))

    # -- SILVER: Production-grade --
    criteria.append(Criterion(
        name="slo-compliance-95",
        description="SLO compliance >= 95%",
        tier=CertificationTier.SILVER,
        evidence_key="slo_compliance",
        check_fn=lambda e: e.get("slo_compliance", 0) >= 0.95,
    ))
    criteria.append(Criterion(
        name="chaos-tested",
        description="Agent has passed chaos/resilience testing",
        tier=CertificationTier.SILVER,
        evidence_key="chaos_tested",
        check_fn=lambda e: bool(e.get("chaos_tested", False)),
    ))
    criteria.append(Criterion(
        name="incidents-low",
        description="Fewer than 5 incidents in last 30 days",
        tier=CertificationTier.SILVER,
        evidence_key="incident_count_30d",
        check_fn=lambda e: e.get("incident_count_30d", 999) < 5,
    ))
    criteria.append(Criterion(
        name="observability",
        description="Observability integration is configured",
        tier=CertificationTier.SILVER,
        evidence_key="has_observability",
        check_fn=lambda e: bool(e.get("has_observability", False)),
    ))

    # -- GOLD: Enterprise-ready --
    criteria.append(Criterion(
        name="slo-compliance-99",
        description="SLO compliance >= 99%",
        tier=CertificationTier.GOLD,
        evidence_key="slo_compliance",
        check_fn=lambda e: e.get("slo_compliance", 0) >= 0.99,
    ))
    criteria.append(Criterion(
        name="error-budget-managed",
        description="Error budget is actively managed with burn rate alerts",
        tier=CertificationTier.GOLD,
        evidence_key="error_budget_managed",
        check_fn=lambda e: bool(e.get("error_budget_managed", False)),
    ))
    criteria.append(Criterion(
        name="canary-deployments",
        description="Uses canary or shadow deployment strategy",
        tier=CertificationTier.GOLD,
        evidence_key="has_canary",
        check_fn=lambda e: bool(e.get("has_canary", False)),
    ))
    criteria.append(Criterion(
        name="postmortem-process",
        description="Postmortem template generation for incidents",
        tier=CertificationTier.GOLD,
        evidence_key="has_postmortem",
        check_fn=lambda e: bool(e.get("has_postmortem", False)),
        required=False,  # Advisory for Gold
    ))

    return criteria


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class CertificationEvaluator:
    """Evaluates an agent against certification criteria.

    Supports custom criteria in addition to defaults.
    """

    def __init__(self, criteria: list[Criterion] | None = None) -> None:
        self._criteria = criteria if criteria is not None else _default_criteria()

    @property
    def criteria(self) -> list[Criterion]:
        return list(self._criteria)

    def criteria_for_tier(self, tier: CertificationTier) -> list[Criterion]:
        """Get all criteria applicable to a tier (cumulative)."""
        tier_order = [CertificationTier.BRONZE, CertificationTier.SILVER, CertificationTier.GOLD]
        tier_idx = tier_order.index(tier)
        applicable_tiers = set(tier_order[: tier_idx + 1])
        return [c for c in self._criteria if c.tier in applicable_tiers]

    def evaluate(
        self,
        tier: CertificationTier,
        evidence: dict[str, Any],
        agent_id: str = "",
    ) -> CertificationResult:
        """Evaluate an agent against a certification tier.

        Args:
            tier: The certification tier to evaluate against.
            evidence: Dictionary of evidence values.
            agent_id: Optional agent identifier.

        Returns:
            CertificationResult with pass/fail and details.
        """
        applicable = self.criteria_for_tier(tier)
        results: list[CriterionResult] = []

        for criterion in applicable:
            try:
                passed = criterion.check(evidence)
            except Exception:
                passed = False

            msg = ""
            if not passed and criterion.required:
                msg = f"Required criterion not met: {criterion.description}"
            elif not passed:
                msg = f"Advisory: {criterion.description}"

            results.append(CriterionResult(
                name=criterion.name,
                passed=passed,
                required=criterion.required,
                message=msg,
            ))

        # Pass only if ALL required criteria pass
        all_required_pass = all(r.passed for r in results if r.required)

        cert_id = ""
        if all_required_pass:
            # Generate a deterministic certificate ID
            content = f"{agent_id}:{tier.value}:{time.time()}"
            cert_id = hashlib.sha256(content.encode()).hexdigest()[:16]

        return CertificationResult(
            tier=tier,
            passed=all_required_pass,
            agent_id=agent_id,
            criteria_results=results,
            certificate_id=cert_id,
        )

    def highest_tier(self, evidence: dict[str, Any], agent_id: str = "") -> CertificationResult:
        """Find the highest tier an agent qualifies for.

        Evaluates from GOLD down to BRONZE, returning the first passing tier.
        If no tier passes, returns a failed BRONZE result.
        """
        for tier in [CertificationTier.GOLD, CertificationTier.SILVER, CertificationTier.BRONZE]:
            result = self.evaluate(tier, evidence, agent_id)
            if result.passed:
                return result
        # Return failed bronze
        return self.evaluate(CertificationTier.BRONZE, evidence, agent_id)
