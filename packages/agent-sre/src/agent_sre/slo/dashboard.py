# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""SLO compliance dashboard and reporting."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_sre.slo.objectives import SLO, SLOStatus


class ReportPeriod(Enum):
    """Dashboard reporting period."""
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"

    @property
    def seconds(self) -> int:
        _map = {"hour": 3600, "day": 86400, "week": 604800, "month": 2592000}
        return _map[self.value]


@dataclass
class SLOSnapshot:
    """Point-in-time snapshot of an SLO's state."""
    slo_name: str
    status: SLOStatus
    error_budget_remaining_percent: float
    burn_rate: float
    indicator_values: dict[str, float | None]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slo_name": self.slo_name,
            "status": self.status.value,
            "error_budget_remaining_percent": round(self.error_budget_remaining_percent, 2),
            "burn_rate": round(self.burn_rate, 2),
            "indicator_values": self.indicator_values,
            "timestamp": self.timestamp,
        }


@dataclass
class ComplianceRecord:
    """Historical compliance record for trend analysis."""
    slo_name: str
    period: ReportPeriod
    compliant: bool
    error_budget_consumed_percent: float
    avg_burn_rate: float
    incidents: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "slo_name": self.slo_name,
            "period": self.period.value,
            "compliant": self.compliant,
            "error_budget_consumed_percent": round(self.error_budget_consumed_percent, 2),
            "avg_burn_rate": round(self.avg_burn_rate, 2),
            "incidents": self.incidents,
        }


class SLODashboard:
    """SLO compliance dashboard engine.

    Collects snapshots, tracks compliance history, and generates
    reports for operational visibility.
    """

    def __init__(self, snapshot_interval_seconds: int = 300) -> None:
        self._slos: dict[str, SLO] = {}
        self._snapshots: list[SLOSnapshot] = []
        self._compliance_history: list[ComplianceRecord] = []
        self.snapshot_interval = snapshot_interval_seconds

    def register_slo(self, slo: SLO) -> None:
        """Register an SLO for dashboard tracking."""
        self._slos[slo.name] = slo

    def take_snapshot(self) -> list[SLOSnapshot]:
        """Take a snapshot of all registered SLOs."""
        snapshots = []
        for slo in self._slos.values():
            indicator_values = {}
            for ind in slo.indicators:
                indicator_values[ind.name] = ind.current_value()

            snapshot = SLOSnapshot(
                slo_name=slo.name,
                status=slo.evaluate(),
                error_budget_remaining_percent=slo.error_budget.remaining_percent,
                burn_rate=slo.error_budget.burn_rate(86400),
                indicator_values=indicator_values,
            )
            snapshots.append(snapshot)

        self._snapshots.extend(snapshots)
        return snapshots

    def record_compliance(
        self,
        slo_name: str,
        period: ReportPeriod,
        compliant: bool,
        budget_consumed_percent: float,
        avg_burn_rate: float,
        incidents: int = 0,
    ) -> ComplianceRecord:
        """Record a compliance result for a period."""
        record = ComplianceRecord(
            slo_name=slo_name,
            period=period,
            compliant=compliant,
            error_budget_consumed_percent=budget_consumed_percent,
            avg_burn_rate=avg_burn_rate,
            incidents=incidents,
            start_time=time.time() - period.seconds,
            end_time=time.time(),
        )
        self._compliance_history.append(record)
        return record

    def current_status(self) -> dict[str, Any]:
        """Get current status of all SLOs."""
        status = {}
        for name, slo in self._slos.items():
            status[name] = slo.to_dict()
        return status

    def snapshots_in_range(
        self,
        slo_name: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> list[SLOSnapshot]:
        """Get snapshots filtered by SLO name and time range."""
        result = self._snapshots
        if slo_name:
            result = [s for s in result if s.slo_name == slo_name]
        if since:
            result = [s for s in result if s.timestamp >= since]
        if until:
            result = [s for s in result if s.timestamp <= until]
        return result

    def compliance_report(
        self,
        slo_name: str | None = None,
        period: ReportPeriod | None = None,
    ) -> list[ComplianceRecord]:
        """Get compliance history filtered by SLO and period."""
        result = self._compliance_history
        if slo_name:
            result = [r for r in result if r.slo_name == slo_name]
        if period:
            result = [r for r in result if r.period == period]
        return result

    def health_summary(self) -> dict[str, Any]:
        """Generate overall health summary."""
        statuses = {name: slo.evaluate() for name, slo in self._slos.items()}
        return {
            "total_slos": len(self._slos),
            "healthy": sum(1 for s in statuses.values() if s == SLOStatus.HEALTHY),
            "warning": sum(1 for s in statuses.values() if s == SLOStatus.WARNING),
            "critical": sum(1 for s in statuses.values() if s == SLOStatus.CRITICAL),
            "exhausted": sum(1 for s in statuses.values() if s == SLOStatus.EXHAUSTED),
            "unknown": sum(1 for s in statuses.values() if s == SLOStatus.UNKNOWN),
            "slos": {name: s.value for name, s in statuses.items()},
            "total_snapshots": len(self._snapshots),
            "compliance_records": len(self._compliance_history),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "health": self.health_summary(),
            "slos": self.current_status(),
        }
