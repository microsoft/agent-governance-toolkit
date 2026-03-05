# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Context Budget Scheduler."""

import pytest
from agent_os.context_budget import (
    AgentSignal,
    BudgetExceeded,
    ContextPriority,
    ContextScheduler,
    ContextWindow,
    UsageRecord,
)


@pytest.fixture
def scheduler():
    return ContextScheduler(total_budget=8000)


# =============================================================================
# Allocation tests
# =============================================================================


class TestAllocation:
    def test_basic_allocation(self, scheduler):
        window = scheduler.allocate("agent-1", "summarise docs")
        assert window.agent_id == "agent-1"
        assert window.total > 0
        assert window.lookup_budget + window.reasoning_budget == window.total

    def test_lookup_ratio(self, scheduler):
        window = scheduler.allocate("a", "task")
        assert abs(window.lookup_ratio - 0.90) < 0.02

    def test_priority_scaling(self, scheduler):
        low = scheduler.allocate("low", "t", priority=ContextPriority.LOW)
        high = scheduler.allocate("high", "t", priority=ContextPriority.HIGH)
        # High-priority gets a bigger allocation than low
        assert high.total >= low.total

    def test_max_tokens_cap(self, scheduler):
        window = scheduler.allocate("a", "t", max_tokens=500)
        assert window.total <= 500

    def test_pool_depletion(self):
        s = ContextScheduler(total_budget=2000)
        w1 = s.allocate("a", "t", max_tokens=1500)
        w2 = s.allocate("b", "t", max_tokens=1500)
        # Second allocation capped by remaining pool
        assert w1.total + w2.total <= 2000

    def test_available_tokens(self, scheduler):
        initial = scheduler.available_tokens
        assert initial == 8000
        scheduler.allocate("a", "t", max_tokens=3000)
        assert scheduler.available_tokens < initial


# =============================================================================
# Usage tracking tests
# =============================================================================


class TestUsageTracking:
    def test_record_usage(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=1000)
        rec = scheduler.record_usage("a", lookup_tokens=100, reasoning_tokens=50)
        assert rec.lookup_used == 100
        assert rec.reasoning_used == 50
        assert rec.total_used == 150
        assert rec.remaining == 850

    def test_budget_exceeded_raises(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=100)
        with pytest.raises(BudgetExceeded):
            scheduler.record_usage("a", lookup_tokens=200)

    def test_budget_exceeded_stops_agent(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=100)
        with pytest.raises(BudgetExceeded):
            scheduler.record_usage("a", lookup_tokens=200)
        rec = scheduler.get_usage("a")
        assert rec.stopped is True
        assert rec.stop_reason == "budget_exceeded"

    def test_double_exceed_raises(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=100)
        with pytest.raises(BudgetExceeded):
            scheduler.record_usage("a", lookup_tokens=200)
        # Second call also raises (agent is stopped)
        with pytest.raises(BudgetExceeded):
            scheduler.record_usage("a", lookup_tokens=1)

    def test_no_allocation_raises(self, scheduler):
        with pytest.raises(KeyError):
            scheduler.record_usage("ghost", lookup_tokens=1)

    def test_utilization_tracking(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=1000)
        scheduler.record_usage("a", lookup_tokens=500)
        rec = scheduler.get_usage("a")
        assert abs(rec.utilization - 0.5) < 0.01

    def test_release(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=1000)
        scheduler.record_usage("a", lookup_tokens=100)
        rec = scheduler.release("a")
        assert rec is not None
        assert rec.total_used == 100
        assert scheduler.get_usage("a") is None


# =============================================================================
# Signal tests
# =============================================================================


class TestSignals:
    def test_sigwarn_fires(self, scheduler):
        signals = []
        scheduler.on_signal(AgentSignal.SIGWARN, lambda aid, sig: signals.append((aid, sig)))
        scheduler.allocate("a", "t", max_tokens=100)
        scheduler.record_usage("a", lookup_tokens=90)  # 90% → warn
        assert any(sig == AgentSignal.SIGWARN for _, sig in signals)

    def test_sigstop_fires(self, scheduler):
        signals = []
        scheduler.on_signal(AgentSignal.SIGSTOP, lambda aid, sig: signals.append((aid, sig)))
        scheduler.allocate("a", "t", max_tokens=100)
        with pytest.raises(BudgetExceeded):
            scheduler.record_usage("a", lookup_tokens=200)
        assert any(sig == AgentSignal.SIGSTOP for _, sig in signals)


# =============================================================================
# Scheduler-level tests
# =============================================================================


class TestSchedulerGlobal:
    def test_active_agents(self, scheduler):
        assert scheduler.active_count == 0
        scheduler.allocate("a", "t")
        scheduler.allocate("b", "t")
        assert scheduler.active_count == 2
        assert set(scheduler.active_agents) == {"a", "b"}

    def test_global_utilization(self):
        s = ContextScheduler(total_budget=4000)
        s.allocate("a", "t", max_tokens=2000)
        assert abs(s.utilization - 0.5) < 0.05

    def test_health_report(self, scheduler):
        scheduler.allocate("a", "t", max_tokens=500)
        report = scheduler.get_health_report()
        assert report["total_budget"] == 8000
        assert "a" in report["agents"]
        assert report["active_agents"] == 1

    def test_invalid_lookup_ratio(self):
        with pytest.raises(ValueError):
            ContextScheduler(total_budget=8000, lookup_ratio=0.0)
        with pytest.raises(ValueError):
            ContextScheduler(total_budget=8000, lookup_ratio=1.0)

    def test_invalid_budget(self):
        with pytest.raises(ValueError):
            ContextScheduler(total_budget=0)


# =============================================================================
# ContextWindow tests
# =============================================================================


class TestContextWindow:
    def test_ratios(self):
        w = ContextWindow(
            agent_id="a", task="t",
            lookup_budget=900, reasoning_budget=100, total=1000,
        )
        assert abs(w.lookup_ratio - 0.9) < 0.01
        assert abs(w.reasoning_ratio - 0.1) < 0.01

    def test_frozen(self):
        w = ContextWindow(
            agent_id="a", task="t",
            lookup_budget=900, reasoning_budget=100, total=1000,
        )
        with pytest.raises(AttributeError):
            w.total = 2000
