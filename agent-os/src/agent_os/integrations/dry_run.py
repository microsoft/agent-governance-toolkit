# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dry-run policy wrapper for governance policies.

Wraps any GovernancePolicy and runs enforcement in "dry run" mode,
recording what WOULD have happened without actually blocking execution.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .base import BaseIntegration, ExecutionContext


class DryRunDecision(Enum):
    """Decision that would have been made by the wrapped policy."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    WARN = "WARN"


@dataclass
class DryRunResult:
    """Result of a dry-run policy evaluation."""
    action: str
    decision: DryRunDecision
    reason: Optional[str]
    policy_name: str
    timestamp: datetime = field(default_factory=datetime.now)


class DryRunCollector:
    """Accumulates dry-run results and provides summary reports."""

    def __init__(self) -> None:
        self._results: list[DryRunResult] = []

    def add(self, result: DryRunResult) -> None:
        self._results.append(result)

    def get_results(self) -> list[DryRunResult]:
        return list(self._results)

    def summary(self) -> dict[str, Any]:
        total = len(self._results)
        counts = {d.value: 0 for d in DryRunDecision}
        for r in self._results:
            counts[r.decision.value] += 1
        return {
            "total": total,
            "allowed": counts["ALLOW"],
            "denied": counts["DENY"],
            "warnings": counts["WARN"],
        }

    def clear(self) -> None:
        self._results.clear()


class DryRunPolicy:
    """
    Wraps a BaseIntegration to run policy checks in dry-run mode.

    All policy evaluations are recorded but never block execution.
    """

    def __init__(
        self,
        integration: BaseIntegration,
        *,
        policy_name: str = "default",
        collector: Optional[DryRunCollector] = None,
    ) -> None:
        self._integration = integration
        self._policy_name = policy_name
        self.collector = collector or DryRunCollector()

    def evaluate(self, action: str, context: ExecutionContext, input_data: Any = None) -> DryRunResult:
        """
        Evaluate a policy check in dry-run mode.

        Runs the wrapped integration's pre_execute and records the decision
        without blocking. Always returns a DryRunResult.
        """
        allowed, reason = self._integration.pre_execute(context, input_data)

        if allowed:
            decision = DryRunDecision.ALLOW
        else:
            # Distinguish warnings from denials: threshold-based checks
            # (confidence, drift) are warnings; hard blocks are denials.
            decision = DryRunDecision.DENY

        result = DryRunResult(
            action=action,
            decision=decision,
            reason=reason,
            policy_name=self._policy_name,
        )
        self.collector.add(result)
        return result

    def evaluate_warn(self, action: str, reason: str) -> DryRunResult:
        """Record a warning without running policy checks."""
        result = DryRunResult(
            action=action,
            decision=DryRunDecision.WARN,
            reason=reason,
            policy_name=self._policy_name,
        )
        self.collector.add(result)
        return result

    def get_results(self) -> list[DryRunResult]:
        return self.collector.get_results()

    def summary(self) -> dict[str, Any]:
        return self.collector.summary()

    def clear(self) -> None:
        self.collector.clear()
