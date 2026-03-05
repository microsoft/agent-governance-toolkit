# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for cost guard — budget management and anomaly detection."""

from agent_sre.cost.guard import (
    AgentBudget,
    CostAlertSeverity,
    CostGuard,
)


class TestAgentBudget:
    def test_defaults(self) -> None:
        b = AgentBudget(agent_id="bot-1")
        assert b.remaining_today_usd == 100.0
        assert b.utilization_percent == 0.0
        assert b.throttled is False
        assert b.killed is False

    def test_spending(self) -> None:
        b = AgentBudget(agent_id="bot-1", daily_limit_usd=10.0)
        b.spent_today_usd = 7.5
        b.task_count_today = 3
        assert b.remaining_today_usd == 2.5
        assert b.utilization_percent == 75.0
        assert b.avg_cost_per_task == 2.5

    def test_to_dict(self) -> None:
        b = AgentBudget(agent_id="bot-1")
        d = b.to_dict()
        assert d["agent_id"] == "bot-1"
        assert "remaining_today_usd" in d


class TestCostGuard:
    def test_check_task_allowed(self) -> None:
        guard = CostGuard(per_task_limit=2.0, per_agent_daily_limit=100.0)
        allowed, reason = guard.check_task("bot-1", estimated_cost=0.50)
        assert allowed is True
        assert reason == "ok"

    def test_check_task_exceeds_per_task_limit(self) -> None:
        guard = CostGuard(per_task_limit=1.0)
        allowed, reason = guard.check_task("bot-1", estimated_cost=1.50)
        assert allowed is False
        assert "per-task limit" in reason

    def test_record_cost(self) -> None:
        guard = CostGuard(per_task_limit=5.0, per_agent_daily_limit=100.0)
        guard.record_cost("bot-1", "task-1", 0.50)
        budget = guard.get_budget("bot-1")
        assert budget.spent_today_usd == 0.50
        assert budget.task_count_today == 1

    def test_per_task_alert(self) -> None:
        guard = CostGuard(per_task_limit=1.0, per_agent_daily_limit=100.0)
        alerts = guard.record_cost("bot-1", "task-1", 1.50)
        assert any(a.severity == CostAlertSeverity.WARNING for a in alerts)

    def test_budget_threshold_alerts(self) -> None:
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=10.0)
        # Spend 60% of budget
        guard.record_cost("bot-1", "t1", 6.0)
        budget = guard.get_budget("bot-1")
        assert budget.utilization_percent == 60.0

    def test_kill_switch(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        guard.record_cost("bot-1", "t1", 9.6)  # 96% utilization
        budget = guard.get_budget("bot-1")
        assert budget.killed is True

        allowed, reason = guard.check_task("bot-1")
        assert allowed is False
        assert "killed" in reason.lower()

    def test_throttle(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        guard.record_cost("bot-1", "t1", 8.6)  # 86% — above throttle, below kill
        budget = guard.get_budget("bot-1")
        assert budget.throttled is True
        assert budget.killed is False

    def test_anomaly_detection(self) -> None:
        guard = CostGuard(anomaly_detection=True, per_task_limit=100.0, per_agent_daily_limit=1000.0)
        # Build baseline
        for i in range(20):
            guard.record_cost("bot-1", f"t{i}", 0.10)
        # Spike
        alerts = guard.record_cost("bot-1", "spike", 5.0)
        anomaly_alerts = [a for a in alerts if "anomal" in a.message.lower() or "Anomal" in a.message]
        assert len(anomaly_alerts) > 0

    def test_reset_daily(self) -> None:
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=10.0, auto_throttle=True)
        guard.record_cost("bot-1", "t1", 9.6)
        budget = guard.get_budget("bot-1")
        assert budget.killed is True

        guard.reset_daily("bot-1")
        budget = guard.get_budget("bot-1")
        assert budget.killed is False
        assert budget.spent_today_usd == 0.0

    def test_org_budget(self) -> None:
        guard = CostGuard(org_monthly_budget=100.0, per_task_limit=100.0, per_agent_daily_limit=1000.0)
        guard.record_cost("bot-1", "t1", 30.0)
        guard.record_cost("bot-2", "t2", 20.0)
        assert guard.org_spent_month == 50.0
        assert guard.org_remaining_month == 50.0

    def test_summary(self) -> None:
        guard = CostGuard(per_task_limit=100.0, per_agent_daily_limit=100.0)
        guard.record_cost("bot-1", "t1", 1.0)
        s = guard.summary()
        assert s["total_records"] == 1
        assert "bot-1" in s["agents"]
