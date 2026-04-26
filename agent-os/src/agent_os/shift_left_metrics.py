# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shift-left compliance metrics.

Tracks where policy violations are caught in the development lifecycle
and computes a shift-left score: the earlier violations are detected,
the higher the score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ViolationStage(str, Enum):
    """Stage in the development lifecycle where a violation was caught."""

    PRE_COMMIT = "pre_commit"      # IDE / local hooks
    PR_CHECK = "pr_check"          # Pull-request checks
    CI_GATE = "ci_gate"            # CI/CD pipeline gates
    RUNTIME = "runtime"            # Production / agent runtime


# Weights: earlier stages earn a higher shift-left contribution.
_STAGE_WEIGHTS: dict[ViolationStage, float] = {
    ViolationStage.PRE_COMMIT: 1.0,
    ViolationStage.PR_CHECK: 0.75,
    ViolationStage.CI_GATE: 0.5,
    ViolationStage.RUNTIME: 0.0,
}


@dataclass
class ViolationRecord:
    """A single recorded policy violation."""

    rule_name: str
    stage: ViolationStage
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    message: str = ""


class ShiftLeftTracker:
    """Tracks violation records and computes shift-left metrics."""

    def __init__(self) -> None:
        self._records: list[ViolationRecord] = []

    def record(
        self,
        rule_name: str,
        stage: ViolationStage,
        *,
        resolved: bool = False,
        message: str = "",
    ) -> ViolationRecord:
        """Record a new violation and return the record."""
        rec = ViolationRecord(
            rule_name=rule_name,
            stage=stage,
            resolved=resolved,
            message=message,
        )
        self._records.append(rec)
        return rec

    @property
    def records(self) -> list[ViolationRecord]:
        return list(self._records)

    # ------------------------------------------------------------------
    # Stage distribution
    # ------------------------------------------------------------------

    def stage_distribution(self) -> dict[str, int]:
        """Return counts of violations per stage."""
        dist: dict[str, int] = {s.value: 0 for s in ViolationStage}
        for rec in self._records:
            dist[rec.stage.value] += 1
        return dist

    # ------------------------------------------------------------------
    # Shift-left score
    # ------------------------------------------------------------------

    def shift_left_score(self) -> float:
        """Compute the shift-left score (0.0 - 1.0).

        A score of 1.0 means every violation was caught at *pre_commit*.
        A score of 0.0 means every violation was only caught at *runtime*
        (or no violations were recorded).
        """
        if not self._records:
            return 0.0
        total_weight = sum(
            _STAGE_WEIGHTS[rec.stage] for rec in self._records
        )
        return total_weight / len(self._records)

    # ------------------------------------------------------------------
    # Trend report
    # ------------------------------------------------------------------

    def trend_report(self) -> dict[str, Any]:
        """Generate a summary trend report."""
        total = len(self._records)
        resolved = sum(1 for r in self._records if r.resolved)
        return {
            "total_violations": total,
            "resolved": resolved,
            "unresolved": total - resolved,
            "shift_left_score": round(self.shift_left_score(), 3),
            "stage_distribution": self.stage_distribution(),
            "resolution_rate": round(resolved / total, 3) if total else 0.0,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def violations_for_rule(self, rule_name: str) -> list[ViolationRecord]:
        """Return all violation records for a given rule name."""
        return [r for r in self._records if r.rule_name == rule_name]

    def clear(self) -> None:
        """Remove all recorded violations."""
        self._records.clear()
