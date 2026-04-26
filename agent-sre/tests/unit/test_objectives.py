# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SLO definitions and error budget engine."""



from agent_sre.slo.indicators import CostPerTask, PolicyCompliance, TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget, ExhaustionAction, SLOStatus


class TestErrorBudget:
    def test_initial_state(self) -> None:
        budget = ErrorBudget(total=0.01)  # 1% budget
        assert budget.remaining == 1.0
        assert budget.remaining_percent == 100.0
        assert budget.is_exhausted is False

    def test_consumption(self) -> None:
        budget = ErrorBudget(total=10.0)
        for _ in range(5):
            budget.record_event(good=False)
        assert budget.consumed == 5.0
        assert budget.remaining == 0.5  # 50% remaining

    def test_exhaustion(self) -> None:
        budget = ErrorBudget(total=3.0, exhaustion_action=ExhaustionAction.FREEZE_DEPLOYMENTS)
        for _ in range(3):
            budget.record_event(good=False)
        assert budget.is_exhausted is True

    def test_good_events_dont_consume(self) -> None:
        budget = ErrorBudget(total=10.0)
        for _ in range(100):
            budget.record_event(good=True)
        assert budget.consumed == 0.0
        assert budget.remaining == 1.0

    def test_burn_rate_zero_with_no_events(self) -> None:
        budget = ErrorBudget(total=0.01)
        assert budget.burn_rate() == 0.0

    def test_to_dict(self) -> None:
        budget = ErrorBudget(total=0.01)
        budget.record_event(good=True)
        d = budget.to_dict()
        assert "total" in d
        assert "remaining_percent" in d
        assert "is_exhausted" in d
        assert "burn_rate" in d
        assert "firing_alerts" in d

    def test_alerts(self) -> None:
        budget = ErrorBudget(total=0.01, burn_rate_alert=2.0, burn_rate_critical=10.0)
        alerts = budget.alerts()
        assert len(alerts) == 2
        names = [a.name for a in alerts]
        assert "burn_rate_warning" in names
        assert "burn_rate_critical" in names

    def test_events_bounded_by_max_events(self) -> None:
        """Events beyond max_events are silently evicted (oldest first)."""
        budget = ErrorBudget(total=10.0, max_events=100)
        for _ in range(200):
            budget.record_event(good=True)
        assert budget.event_count == 100  # capped at maxlen

    def test_custom_max_events(self) -> None:
        """Custom max_events parameter is respected."""
        budget = ErrorBudget(total=10.0, max_events=5)
        for i in range(10):
            budget.record_event(good=(i % 2 == 0))
        assert budget.event_count == 5
        # The deque should contain only the last 5 events
        assert budget._events.maxlen == 5

    def test_clear_events(self) -> None:
        """clear_events() empties the deque but does not reset consumed."""
        budget = ErrorBudget(total=10.0)
        for _ in range(5):
            budget.record_event(good=False)
        assert budget.consumed == 5.0
        assert budget.event_count == 5
        budget.clear_events()
        assert budget.event_count == 0
        assert budget.consumed == 5.0  # consumed is NOT reset


class TestSLO:
    def test_creation(self) -> None:
        sli = TaskSuccessRate(target=0.995)
        slo = SLO(
            name="test-agent",
            indicators=[sli],
            description="Test SLO",
        )
        assert slo.name == "test-agent"
        assert len(slo.indicators) == 1
        assert abs(slo.error_budget.total - 0.005) < 1e-10  # 1 - 0.995

    def test_custom_error_budget(self) -> None:
        sli = TaskSuccessRate(target=0.995)
        budget = ErrorBudget(total=0.01, exhaustion_action=ExhaustionAction.CIRCUIT_BREAK)
        slo = SLO(name="test", indicators=[sli], error_budget=budget)
        assert slo.error_budget.total == 0.01
        assert slo.error_budget.exhaustion_action == ExhaustionAction.CIRCUIT_BREAK

    def test_evaluate_unknown_no_data(self) -> None:
        sli = TaskSuccessRate()
        slo = SLO(name="test", indicators=[sli])
        assert slo.evaluate() == SLOStatus.UNKNOWN

    def test_evaluate_healthy(self) -> None:
        sli = TaskSuccessRate(target=0.99)
        sli.record_task(True)  # Generate some data
        slo = SLO(name="test", indicators=[sli])
        assert slo.evaluate() == SLOStatus.HEALTHY

    def test_evaluate_exhausted(self) -> None:
        sli = TaskSuccessRate(target=0.99)
        sli.record_task(True)
        budget = ErrorBudget(total=1.0)
        slo = SLO(name="test", indicators=[sli], error_budget=budget)
        # Exhaust the budget
        slo.record_event(good=False)
        assert slo.evaluate() == SLOStatus.EXHAUSTED

    def test_record_event(self) -> None:
        sli = TaskSuccessRate(target=0.99)
        slo = SLO(name="test", indicators=[sli])
        slo.record_event(good=True)
        slo.record_event(good=False)
        assert slo.error_budget.consumed == 1.0

    def test_indicator_summary(self) -> None:
        sli1 = TaskSuccessRate(target=0.99)
        sli2 = CostPerTask(target_usd=0.50)
        sli1.record_task(True)
        sli2.record_cost(0.30)
        slo = SLO(name="test", indicators=[sli1, sli2])
        summary = slo.indicator_summary()
        assert len(summary) == 2
        assert summary[0]["name"] == "task_success_rate"
        assert summary[1]["name"] == "cost_per_task"

    def test_to_dict(self) -> None:
        sli = TaskSuccessRate(target=0.995)
        sli.record_task(True)
        slo = SLO(name="my-agent", indicators=[sli], labels={"team": "platform"})
        d = slo.to_dict()
        assert d["name"] == "my-agent"
        assert d["labels"]["team"] == "platform"
        assert "error_budget" in d
        assert "indicators" in d
        assert d["status"] in ["healthy", "warning", "critical", "exhausted", "unknown"]

    def test_repr(self) -> None:
        sli = TaskSuccessRate(target=0.99)
        sli.record_task(True)
        slo = SLO(name="bot", indicators=[sli])
        r = repr(slo)
        assert "bot" in r
        assert "healthy" in r

    def test_multiple_indicators_budget_from_strictest(self) -> None:
        sli1 = TaskSuccessRate(target=0.99)  # 1% budget
        sli2 = PolicyCompliance(target=1.0)  # 0% budget
        slo = SLO(name="strict", indicators=[sli1, sli2])
        # Budget derived from min target (0.99), so 1 - 0.99 = 0.01
        assert abs(slo.error_budget.total - 0.01) < 1e-10
