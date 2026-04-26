# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SLO compliance dashboard."""

from agent_sre.slo.dashboard import (
    ReportPeriod,
    SLODashboard,
    SLOSnapshot,
)
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.slo.objectives import SLO, SLOStatus


class TestSLODashboard:
    def _make_slo(self, name="test-slo"):
        sli = TaskSuccessRate(target=0.99)
        sli.record_task(True)
        return SLO(name=name, indicators=[sli])

    def test_register_slo(self):
        dashboard = SLODashboard()
        slo = self._make_slo()
        dashboard.register_slo(slo)
        assert "test-slo" in dashboard.current_status()

    def test_take_snapshot(self):
        dashboard = SLODashboard()
        dashboard.register_slo(self._make_slo())
        snapshots = dashboard.take_snapshot()
        assert len(snapshots) == 1
        assert snapshots[0].slo_name == "test-slo"

    def test_snapshot_to_dict(self):
        snap = SLOSnapshot(
            slo_name="test",
            status=SLOStatus.HEALTHY,
            error_budget_remaining_percent=95.0,
            burn_rate=0.5,
            indicator_values={"task_success_rate": 0.999},
        )
        d = snap.to_dict()
        assert d["slo_name"] == "test"
        assert d["status"] == "healthy"

    def test_record_compliance(self):
        dashboard = SLODashboard()
        record = dashboard.record_compliance(
            slo_name="test-slo",
            period=ReportPeriod.DAY,
            compliant=True,
            budget_consumed_percent=5.0,
            avg_burn_rate=0.5,
        )
        assert record.compliant
        assert record.period == ReportPeriod.DAY

    def test_compliance_report_filter(self):
        dashboard = SLODashboard()
        dashboard.record_compliance("slo-a", ReportPeriod.DAY, True, 5.0, 0.5)
        dashboard.record_compliance("slo-b", ReportPeriod.WEEK, False, 80.0, 3.0)
        results = dashboard.compliance_report(slo_name="slo-a")
        assert len(results) == 1
        assert results[0].slo_name == "slo-a"

    def test_health_summary(self):
        dashboard = SLODashboard()
        dashboard.register_slo(self._make_slo("slo-1"))
        dashboard.register_slo(self._make_slo("slo-2"))
        summary = dashboard.health_summary()
        assert summary["total_slos"] == 2

    def test_snapshots_in_range(self):
        dashboard = SLODashboard()
        dashboard.register_slo(self._make_slo())
        dashboard.take_snapshot()
        results = dashboard.snapshots_in_range(slo_name="test-slo")
        assert len(results) == 1

    def test_report_period_seconds(self):
        assert ReportPeriod.HOUR.seconds == 3600
        assert ReportPeriod.DAY.seconds == 86400

    def test_to_dict(self):
        dashboard = SLODashboard()
        dashboard.register_slo(self._make_slo())
        d = dashboard.to_dict()
        assert "health" in d
        assert "slos" in d
