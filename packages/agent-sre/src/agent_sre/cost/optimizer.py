# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Cost optimization — basic model cost estimation and recommendation.

Cost optimization analysis is not available in Community Edition.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    """Configuration and cost profile for a single LLM model."""

    name: str
    provider: str
    cost_per_1k_input_tokens: float
    cost_per_1k_output_tokens: float
    avg_latency_ms: float
    quality_score: float = Field(ge=0.0, le=1.0)


class TaskProfile(BaseModel):
    """Profile describing a task type and its requirements."""

    task_type: str
    avg_input_tokens: int
    avg_output_tokens: int
    min_quality: float = Field(ge=0.0, le=1.0)
    max_latency_ms: float | None = None


class CostEstimate(BaseModel):
    """Cost estimate for running a specific model on a task."""

    model_name: str
    estimated_cost: float
    estimated_quality: float
    estimated_latency_ms: float
    is_optimal: bool = False


class OptimizationResult(BaseModel):
    """Result of a cost optimization recommendation."""

    task_type: str
    recommendations: list[CostEstimate]
    current_model: str | None = None
    potential_savings_pct: float | None = None


class CostOptimizer:
    """Multi-model cost optimizer with routing.

    Evaluates models against task profiles to find cost-optimal
    configurations that meet quality and latency constraints.
    """

    def __init__(self, models: list[ModelConfig]) -> None:
        self._models = {m.name: m for m in models}

    def estimate_cost(self, model: ModelConfig, task: TaskProfile) -> CostEstimate:
        """Compute cost estimate for a model+task pair."""
        input_cost = (task.avg_input_tokens / 1000) * model.cost_per_1k_input_tokens
        output_cost = (task.avg_output_tokens / 1000) * model.cost_per_1k_output_tokens
        return CostEstimate(
            model_name=model.name,
            estimated_cost=round(input_cost + output_cost, 6),
            estimated_quality=model.quality_score,
            estimated_latency_ms=model.avg_latency_ms,
        )

    def recommend(
        self, task: TaskProfile, current_model: str | None = None
    ) -> OptimizationResult:
        """Find optimal models meeting quality/latency constraints, sorted by cost."""
        estimates: list[CostEstimate] = []
        for model in self._models.values():
            if model.quality_score < task.min_quality:
                continue
            if task.max_latency_ms is not None and model.avg_latency_ms > task.max_latency_ms:
                continue
            estimates.append(self.estimate_cost(model, task))

        estimates.sort(key=lambda e: e.estimated_cost)

        if estimates:
            estimates[0].is_optimal = True

        savings_pct: float | None = None
        if current_model and current_model in self._models and estimates:
            current_est = self.estimate_cost(self._models[current_model], task)
            best_cost = estimates[0].estimated_cost
            if current_est.estimated_cost > 0:
                savings_pct = round(
                    ((current_est.estimated_cost - best_cost) / current_est.estimated_cost) * 100,
                    2,
                )

        return OptimizationResult(
            task_type=task.task_type,
            recommendations=estimates,
            current_model=current_model,
            potential_savings_pct=savings_pct,
        )

    def pareto_frontier(self, task: TaskProfile) -> list[CostEstimate]:
        """Cost optimization — not available in Community Edition."""
        raise NotImplementedError(
            "Not available in Community Edition"
        )

    def simulate(self, task: TaskProfile, model_name: str, volume: int) -> dict[str, object]:
        """Cost simulation — not available in Community Edition."""
        raise NotImplementedError(
            "Cost simulation is not available in Community Edition"
        )

    def suggest_routing(self, tasks: list[TaskProfile]) -> dict[str, str]:
        """For each task type, suggest the cheapest model meeting constraints."""
        routing: dict[str, str] = {}
        for task in tasks:
            result = self.recommend(task)
            if result.recommendations:
                routing[task.task_type] = result.recommendations[0].model_name
        return routing
