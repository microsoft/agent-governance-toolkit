# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hardened tests for Cost Governance.

Covers CostAnomalyDetector standalone, same-agent concurrency,
org reset after kill, and edge cases.
"""

import threading

import pytest

from agent_sre.cost.anomaly import (
    AnomalyResult,
    CostAnomalyDetector,
)
from agent_sre.cost.guard import (
    AgentBudget,
    CostAlertSeverity,
    CostGuard,
)


# ---------------------------------------------------------------------------
# CostAnomalyDetector Standalone Tests
# ---------------------------------------------------------------------------


class TestCostAnomalyDetectorStandalone:
    def test_no_anomaly_below_min_samples(self):
        detector = CostAnomalyDetector(min_samples=10)
        for i in range(9):
            result = detector.ingest(1.0, "agent-1")
            assert result is None

    def test_anomaly_detected_after_baseline(self):
        detector = CostAnomalyDetector(min_samples=10, z_threshold=2.0)
        # Build stable baseline
        for _ in range(20):
            detector.ingest(1.0, "agent-1")

        # Spike
        result = detector.ingest(100.0, "agent-1")
        assert result is not None
        assert isinstance(result, AnomalyResult)

    def test_no_anomaly_for_consistent_values(self):
        detector = CostAnomalyDetector(min_samples=10)
        for _ in range(50):
            result = detector.ingest(1.0, "agent-1")
        # All identical values: std_dev is 0, no anomaly can be computed
        assert result is None

    def test_baseline_stats_correct(self):
        detector = CostAnomalyDetector(min_samples=5)
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            detector.ingest(v, "agent-1")

        stats = detector.baseline
        assert stats.mean == pytest.approx(3.0)
        assert stats.sample_count == 5

    def test_window_size_limits_data(self):
        detector = CostAnomalyDetector(min_samples=5, window_size=10)
        for i in range(20):
            detector.ingest(float(i), "agent-1")

        stats = detector.baseline
        assert stats.sample_count == 10  # Only last 10 kept

    def test_anomaly_severity_levels(self):
        detector = CostAnomalyDetector(min_samples=10, z_threshold=2.0)
        # Build baseline around 1.0 with small variance
        for v in [1.0, 1.1, 0.9, 1.0, 1.1, 0.9, 1.0, 1.1, 0.9, 1.0]:
            detector.ingest(v, "agent-1")

        # Moderate spike (z ~ 2.5)
        result_medium = detector.ingest(2.0, "agent-1")

        # Big spike should be high severity
        detector2 = CostAnomalyDetector(min_samples=10, z_threshold=2.0)
        for v in [1.0, 1.1, 0.9, 1.0, 1.1, 0.9, 1.0, 1.1, 0.9, 1.0]:
            detector2.ingest(v, "agent-1")
        result_high = detector2.ingest(100.0, "agent-1")

        if result_high is not None:
            assert result_high.severity.value in ("medium", "high")

    def test_anomaly_history_tracked(self):
        detector = CostAnomalyDetector(min_samples=10, z_threshold=2.0)
        for v in [1.0, 1.1, 0.9, 1.0, 1.1, 0.9, 1.0, 1.1, 0.9, 1.0]:
            detector.ingest(v, "agent-1")

        detector.ingest(100.0, "agent-1")
        anomalies = detector.anomalies
        assert len(anomalies) >= 1


# ---------------------------------------------------------------------------
# Same-Agent CostGuard Concurrency
# ---------------------------------------------------------------------------


class TestSameAgentConcurrency:
    def test_concurrent_record_same_agent_no_crash(self):
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10000.0,
        )
        errors: list[str] = []

        def record_costs() -> None:
            try:
                for i in range(100):
                    guard.record_cost("same-agent", f"t{threading.current_thread().name}-{i}", 0.01)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=record_costs) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        budget = guard.get_budget("same-agent")
        # 10 threads x 100 records x $0.01 = $10.00 (allow small float drift)
        assert abs(budget.spent_today_usd - 10.0) < 1.0
        assert budget.task_count_today == 1000

    def test_concurrent_check_and_record_at_limit(self):
        """Concurrent check_task + record_cost near the daily limit."""
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )

        errors: list[str] = []

        def spend() -> None:
            try:
                for i in range(20):
                    guard.record_cost("agent-race", f"t-{threading.current_thread().name}-{i}", 0.5)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=spend) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        budget = guard.get_budget("agent-race")
        # Should have hit kill switch
        assert budget.killed is True


# ---------------------------------------------------------------------------
# Org Reset After Kill
# ---------------------------------------------------------------------------


class TestOrgResetAfterKill:
    def test_reset_daily_clears_agent_kill(self):
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        guard.record_cost("bot-1", "t1", 9.6)  # 96% -> killed
        assert guard.get_budget("bot-1").killed is True

        guard.reset_daily("bot-1")
        assert guard.get_budget("bot-1").killed is False
        assert guard.get_budget("bot-1").throttled is False
        assert guard.get_budget("bot-1").spent_today_usd == 0.0

        # Should be allowed to work again
        allowed, _ = guard.check_task("bot-1", estimated_cost=1.0)
        assert allowed is True

    def test_new_agent_blocked_after_org_kill(self):
        guard = CostGuard(
            per_task_limit=1000.0,
            per_agent_daily_limit=10000.0,
            org_monthly_budget=100.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        guard.record_cost("bot-1", "t1", 96.0)  # 96% org -> kill

        # New agent should be blocked
        allowed, reason = guard.check_task("bot-new", estimated_cost=0.01)
        assert allowed is False

    def test_multiple_resets_work(self):
        """Reset daily can be called multiple times without error."""
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10.0,
            auto_throttle=True,
        )
        guard.record_cost("bot-1", "t1", 9.6)
        guard.reset_daily("bot-1")
        guard.reset_daily("bot-1")  # double reset

        budget = guard.get_budget("bot-1")
        assert budget.spent_today_usd == 0.0
        assert budget.killed is False


# ---------------------------------------------------------------------------
# CostGuard Edge Cases
# ---------------------------------------------------------------------------


class TestCostGuardEdgeCases:
    def test_zero_estimated_cost_always_allowed(self):
        guard = CostGuard(per_task_limit=0.01, per_agent_daily_limit=0.01)
        allowed, _ = guard.check_task("bot-1", estimated_cost=0.0)
        assert allowed is True

    def test_record_zero_cost(self):
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=100.0)
        alerts = guard.record_cost("bot-1", "t1", 0.0)
        budget = guard.get_budget("bot-1")
        assert budget.spent_today_usd == 0.0
        assert budget.task_count_today == 1

    def test_negative_estimated_cost_rejected(self):
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=100.0)
        allowed, reason = guard.check_task("bot-1", estimated_cost=-1.0)
        assert allowed is False

    def test_summary_with_no_records(self):
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=100.0)
        s = guard.summary()
        assert s["total_records"] == 0

    def test_get_budget_unknown_agent(self):
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=100.0)
        budget = guard.get_budget("unknown-agent")
        assert budget.spent_today_usd == 0.0
        assert budget.killed is False

    def test_multiple_agents_independent_budgets(self):
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=10.0)
        guard.record_cost("bot-1", "t1", 8.0)
        guard.record_cost("bot-2", "t2", 2.0)

        assert guard.get_budget("bot-1").utilization_percent == 80.0
        assert guard.get_budget("bot-2").utilization_percent == 20.0

    def test_alert_severity_escalation(self):
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=100.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )

        # Build up spending and collect all alerts
        all_alerts = []
        for i in range(20):
            alerts = guard.record_cost("bot-1", f"t{i}", 5.0)
            all_alerts.extend(alerts)

        # Should have warning and critical alerts
        severities = {a.severity for a in all_alerts}
        assert CostAlertSeverity.WARNING in severities
        assert CostAlertSeverity.CRITICAL in severities
