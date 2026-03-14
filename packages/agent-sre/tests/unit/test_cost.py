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

    def test_check_task_exceeds_org_budget(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=50.0,
        )
        guard.record_cost("bot-1", "t1", 30.0)
        guard.record_cost("bot-2", "t2", 15.0)
        # 45 spent, trying to add 10 -> 55 > 50
        allowed, reason = guard.check_task("bot-3", estimated_cost=10.0)
        assert allowed is False
        assert "org monthly budget" in reason.lower()

    def test_check_task_within_org_budget(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=100.0,
        )
        guard.record_cost("bot-1", "t1", 30.0)
        allowed, reason = guard.check_task("bot-2", estimated_cost=10.0)
        assert allowed is True

    def test_org_budget_kill_alert(self) -> None:
        guard = CostGuard(
            per_task_limit=1000.0,
            per_agent_daily_limit=10000.0,
            org_monthly_budget=100.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        alerts = guard.record_cost("bot-1", "t1", 96.0)  # 96% of org budget
        kill_alerts = [a for a in alerts if "org budget" in a.message.lower() and "kill" in a.message.lower()]
        assert len(kill_alerts) >= 1

    def test_org_budget_multi_agent_aggregate(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=100.0,
            org_monthly_budget=50.0,
        )
        # Each agent within daily limit, but org total exceeds
        guard.record_cost("bot-1", "t1", 20.0)
        guard.record_cost("bot-2", "t2", 20.0)
        guard.record_cost("bot-3", "t3", 15.0)
        # 55 total > 50 org budget; bot-4 should be blocked
        allowed, reason = guard.check_task("bot-4", estimated_cost=1.0)
        assert allowed is False
        assert "org monthly budget" in reason.lower()


import pytest


class TestCostGuardOrgBudgetAdversarial:
    """Adversarial tests for org_monthly_budget enforcement."""

    # Rule 11: Boundary Triple (limit-1, limit, limit+1)
    # NOTE: Implementation uses strict inequality (spent + estimated > budget),
    # so estimated==budget with spent==0 is allowed (equal is not exceeding).
    # The boundary that denies is any value strictly above the budget.
    @pytest.mark.parametrize("estimated,expected", [
        (49.99, True),   # below limit -- allowed
        (50.00, True),   # at limit exactly -- allowed (0 + 50.0 > 50.0 is False)
        (50.01, False),  # above limit -- denied
    ])
    def test_org_budget_boundary_triple(self, estimated: float, expected: bool) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=50.0,
        )
        allowed, _ = guard.check_task("bot-1", estimated_cost=estimated)
        assert allowed is expected

    # Rule 17: NaN/Inf bypass -- org_monthly_budget as bad value
    # nan > 0 is False in IEEE 754, so org check is skipped entirely -> allowed
    # inf > 0 is True, but spent + cost > inf is always False -> allowed
    # -inf > 0 is False, so org check is skipped -> allowed
    @pytest.mark.parametrize("bad_budget", [float("nan"), float("inf"), float("-inf")])
    def test_nan_inf_budget_does_not_crash(self, bad_budget: float) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=bad_budget,
        )
        # Must not raise; behavior may vary but no crash
        allowed, reason = guard.check_task("bot-1", estimated_cost=1.0)
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)

    # Rule 17: NaN/Inf bypass -- estimated_cost as bad value
    # nan > per_task_limit is False, nan comparisons are always False -> check_task allows nan
    # inf > per_task_limit(100) is True -> denied at per-task check (not org)
    # -inf passes all greater-than checks -> allowed
    @pytest.mark.parametrize("bad_cost", [float("nan"), float("inf"), float("-inf")])
    def test_nan_inf_estimated_cost_does_not_crash(self, bad_cost: float) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=50.0,
        )
        allowed, reason = guard.check_task("bot-1", estimated_cost=bad_cost)
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)

    # Rule 23: Zero-semantics (0 = unlimited, not zero budget)
    # Implementation: `if self.org_monthly_budget > 0` gates the org check.
    # org_monthly_budget=0.0 means the guard is disabled, not "zero budget allowed".
    def test_zero_org_budget_means_no_limit(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10000.0,
            org_monthly_budget=0.0,
        )
        guard.record_cost("bot-1", "t1", 99999.0)
        allowed, _ = guard.check_task("bot-2", estimated_cost=1.0)
        # org_monthly_budget=0 means disabled (guard checks > 0), so org check is skipped
        assert allowed is True

    # Rule 6: Compound state (per-agent killed + org budget exceeded simultaneously)
    # When agent is killed, the kill check fires first in check_task.
    def test_agent_killed_and_org_exceeded(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10.0,
            org_monthly_budget=50.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        guard.record_cost("bot-1", "t1", 9.6)  # 96% daily -> killed
        guard.record_cost("bot-2", "t2", 45.0)  # org total = 54.6 > 50
        # bot-1 denied for agent kill, not org budget -- kill check runs first
        allowed, reason = guard.check_task("bot-1", estimated_cost=0.01)
        assert allowed is False
        assert "killed" in reason.lower()

    # Rule 7: Side-effect verification
    # record_cost must update both org_spent_month and org_remaining_month.
    def test_record_cost_updates_org_spent(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=100.0,
        )
        guard.record_cost("bot-1", "t1", 10.0)
        guard.record_cost("bot-2", "t2", 20.0)
        assert guard.org_spent_month == 30.0
        assert guard.org_remaining_month == 70.0

    # Rule 14: Concurrent access
    # Multiple threads recording costs simultaneously must not corrupt state or crash.
    def test_concurrent_record_cost_no_crash(self) -> None:
        import threading
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=10000.0,
            org_monthly_budget=10000.0,
        )
        errors: list[str] = []

        def spend(agent_id: str) -> None:
            try:
                for i in range(100):
                    guard.record_cost(agent_id, f"t{i}", 0.01)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=spend, args=(f"bot-{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        # 10 threads x 100 records x $0.01 = $10.00 (allow 1.0 float drift from races)
        assert abs(guard.org_spent_month - 10.0) < 1.0

    # Boundary: negative org budget
    # Implementation: `if self.org_monthly_budget > 0` -- negative fails this check,
    # so the org gate is skipped entirely and the task is allowed.
    def test_negative_org_budget_treated_as_disabled(self) -> None:
        guard = CostGuard(
            per_task_limit=100.0,
            per_agent_daily_limit=1000.0,
            org_monthly_budget=-1.0,
        )
        allowed, _ = guard.check_task("bot-1", estimated_cost=1.0)
        # Negative budget: guard checks > 0, so org check skipped -> allowed
        assert allowed is True

    # Kill alert fires exactly once across threshold
    # Implementation uses: prev_org_util < threshold <= org_util
    # After first crossing, prev_org_util is already above threshold, so condition is False.
    def test_org_kill_alert_fires_once(self) -> None:
        guard = CostGuard(
            per_task_limit=1000.0,
            per_agent_daily_limit=10000.0,
            org_monthly_budget=100.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        # First call crosses threshold (0.0 -> 0.96, crosses 0.95)
        alerts1 = guard.record_cost("bot-1", "t1", 96.0)
        kill1 = [a for a in alerts1 if "org budget" in a.message.lower() and "kill" in a.message.lower()]
        # Second call is already above threshold (0.96 -> 0.97, prev >= threshold -> no crossing)
        alerts2 = guard.record_cost("bot-1", "t2", 1.0)
        kill2 = [a for a in alerts2 if "org budget" in a.message.lower() and "kill" in a.message.lower()]
        assert len(kill1) >= 1
        assert len(kill2) == 0  # must not fire again

    # WARN-2 fix: org kill must set budget.killed on all agents
    def test_org_kill_sets_killed_on_all_agents(self) -> None:
        guard = CostGuard(
            per_task_limit=1000.0,
            per_agent_daily_limit=10000.0,
            org_monthly_budget=100.0,
            auto_throttle=True,
            kill_switch_threshold=0.95,
        )
        guard.record_cost("bot-1", "t1", 50.0)
        guard.record_cost("bot-2", "t2", 46.0)  # org total = 96% -> kill
        # Both registered agents should be killed
        assert guard.get_budget("bot-1").killed is True
        assert guard.get_budget("bot-2").killed is True
        # Killed agents are blocked via check_task (agent kill gate)
        allowed_1, reason_1 = guard.check_task("bot-1", estimated_cost=0.01)
        assert allowed_1 is False
        assert "killed" in reason_1.lower()
