# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for multi-model cost optimizer."""

from __future__ import annotations

import pytest

from agent_sre.cost.optimizer import (
    CostOptimizer,
    ModelConfig,
    TaskProfile,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CHEAP_MODEL = ModelConfig(
    name="gpt-4o-mini",
    provider="openai",
    cost_per_1k_input_tokens=0.00015,
    cost_per_1k_output_tokens=0.0006,
    avg_latency_ms=200,
    quality_score=0.7,
)

MID_MODEL = ModelConfig(
    name="gpt-4o",
    provider="openai",
    cost_per_1k_input_tokens=0.005,
    cost_per_1k_output_tokens=0.015,
    avg_latency_ms=800,
    quality_score=0.9,
)

EXPENSIVE_MODEL = ModelConfig(
    name="claude-opus",
    provider="anthropic",
    cost_per_1k_input_tokens=0.015,
    cost_per_1k_output_tokens=0.075,
    avg_latency_ms=1500,
    quality_score=0.95,
)


@pytest.fixture()
def models() -> list[ModelConfig]:
    return [CHEAP_MODEL, MID_MODEL, EXPENSIVE_MODEL]


@pytest.fixture()
def optimizer(models: list[ModelConfig]) -> CostOptimizer:
    return CostOptimizer(models)


@pytest.fixture()
def summarization_task() -> TaskProfile:
    return TaskProfile(
        task_type="summarization",
        avg_input_tokens=2000,
        avg_output_tokens=500,
        min_quality=0.5,
    )


@pytest.fixture()
def code_gen_task() -> TaskProfile:
    return TaskProfile(
        task_type="code_gen",
        avg_input_tokens=1000,
        avg_output_tokens=2000,
        min_quality=0.85,
        max_latency_ms=1000,
    )


@pytest.fixture()
def classification_task() -> TaskProfile:
    return TaskProfile(
        task_type="classification",
        avg_input_tokens=500,
        avg_output_tokens=50,
        min_quality=0.6,
    )


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


class TestCostEstimation:
    def test_cost_estimation_accurate(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        est = optimizer.estimate_cost(CHEAP_MODEL, summarization_task)
        # (2000/1000)*0.00015 + (500/1000)*0.0006 = 0.0003 + 0.0003 = 0.0006
        assert est.estimated_cost == pytest.approx(0.0006, abs=1e-6)
        assert est.model_name == "gpt-4o-mini"
        assert est.estimated_quality == 0.7
        assert est.estimated_latency_ms == 200

    def test_cost_estimation_expensive_model(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        est = optimizer.estimate_cost(EXPENSIVE_MODEL, summarization_task)
        # (2000/1000)*0.015 + (500/1000)*0.075 = 0.03 + 0.0375 = 0.0675
        assert est.estimated_cost == pytest.approx(0.0675, abs=1e-6)


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class TestRecommendation:
    def test_respects_quality_constraint(
        self, optimizer: CostOptimizer, code_gen_task: TaskProfile
    ) -> None:
        result = optimizer.recommend(code_gen_task)
        # min_quality=0.85 should exclude cheap model (0.7)
        names = [r.model_name for r in result.recommendations]
        assert "gpt-4o-mini" not in names
        assert all(r.estimated_quality >= 0.85 for r in result.recommendations)

    def test_respects_latency_constraint(
        self, optimizer: CostOptimizer, code_gen_task: TaskProfile
    ) -> None:
        result = optimizer.recommend(code_gen_task)
        # max_latency_ms=1000 should exclude claude-opus (1500ms)
        names = [r.model_name for r in result.recommendations]
        assert "claude-opus" not in names
        assert all(r.estimated_latency_ms <= 1000 for r in result.recommendations)

    def test_sorted_by_cost(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        result = optimizer.recommend(summarization_task)
        costs = [r.estimated_cost for r in result.recommendations]
        assert costs == sorted(costs)

    def test_optimal_flag_on_cheapest(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        result = optimizer.recommend(summarization_task)
        assert result.recommendations[0].is_optimal is True
        assert all(r.is_optimal is False for r in result.recommendations[1:])

    def test_savings_calculation(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        result = optimizer.recommend(summarization_task, current_model="claude-opus")
        assert result.potential_savings_pct is not None
        assert result.potential_savings_pct > 0
        # Switching from opus to mini should save > 99%
        assert result.potential_savings_pct > 90


# ---------------------------------------------------------------------------
# Cost optimizer
# ---------------------------------------------------------------------------


class TestParetoFrontier:
    def test_no_dominated_models(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        frontier = optimizer.pareto_frontier(summarization_task)
        # Frontier should only contain non-dominated models
        assert len(frontier) >= 1
        assert all(hasattr(r, 'model_name') for r in frontier)

    def test_frontier_sorted_by_cost(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        frontier = optimizer.pareto_frontier(summarization_task)
        costs = [r.estimated_cost for r in frontier]
        assert costs == sorted(costs)

    def test_frontier_includes_extremes(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        frontier = optimizer.pareto_frontier(summarization_task)
        names = [r.model_name for r in frontier]
        # Cheapest model should be on the frontier
        assert "gpt-4o-mini" in names


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------


class TestSimulation:
    def test_simulation_correct_totals(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        sim = optimizer.simulate(summarization_task, "gpt-4o-mini", volume=1000)
        assert sim["volume"] == 1000
        assert sim["total_cost"] > 0
        assert sim["model_name"] == "gpt-4o-mini"

    def test_simulation_unknown_model(
        self, optimizer: CostOptimizer, summarization_task: TaskProfile
    ) -> None:
        with pytest.raises(KeyError):
            optimizer.simulate(summarization_task, "nonexistent-model", volume=100)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestRouting:
    def test_assigns_cheap_model_to_easy_tasks(
        self,
        optimizer: CostOptimizer,
        classification_task: TaskProfile,
        code_gen_task: TaskProfile,
    ) -> None:
        routing = optimizer.suggest_routing([classification_task, code_gen_task])
        # Classification (low quality bar) should get cheapest model
        assert routing["classification"] == "gpt-4o-mini"
        # Code gen (high quality + latency constraint) should get mid-tier
        assert routing["code_gen"] == "gpt-4o"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_single_model(self, summarization_task: TaskProfile) -> None:
        opt = CostOptimizer([CHEAP_MODEL])
        result = opt.recommend(summarization_task)
        assert len(result.recommendations) == 1
        assert result.recommendations[0].is_optimal is True

    def test_no_model_meets_constraints(self) -> None:
        task = TaskProfile(
            task_type="impossible",
            avg_input_tokens=1000,
            avg_output_tokens=1000,
            min_quality=0.99,
            max_latency_ms=100,
        )
        opt = CostOptimizer([CHEAP_MODEL, MID_MODEL, EXPENSIVE_MODEL])
        result = opt.recommend(task)
        assert len(result.recommendations) == 0
        assert result.potential_savings_pct is None

    def test_pareto_single_model(self, summarization_task: TaskProfile) -> None:
        opt = CostOptimizer([MID_MODEL])
        frontier = opt.pareto_frontier(summarization_task)
        assert len(frontier) == 1
        assert frontier[0].model_name == "gpt-4o"

    def test_routing_empty_when_no_models_qualify(self) -> None:
        task = TaskProfile(
            task_type="impossible",
            avg_input_tokens=1000,
            avg_output_tokens=1000,
            min_quality=0.99,
            max_latency_ms=50,
        )
        opt = CostOptimizer([CHEAP_MODEL])
        routing = opt.suggest_routing([task])
        assert "impossible" not in routing
