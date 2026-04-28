# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Cost optimization — model cost estimation, recommendation, and analysis.

Includes Pareto frontier analysis and volume-based cost simulation.
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
        """Compute the Pareto-optimal set of models for a task.

        A model is Pareto-optimal if no other model is both cheaper
        AND higher quality while meeting the task constraints.

        Args:
            task: Task profile specifying quality and latency constraints.

        Returns:
            List of Pareto-optimal ``CostEstimate`` objects sorted by
            ascending cost. Empty if no model meets the constraints.
        """
        # Get all feasible estimates
        feasible: list[CostEstimate] = []
        for model in self._models.values():
            if model.quality_score < task.min_quality:
                continue
            if task.max_latency_ms is not None and model.avg_latency_ms > task.max_latency_ms:
                continue
            feasible.append(self.estimate_cost(model, task))

        if not feasible:
            return []

        # Sort by cost ascending
        feasible.sort(key=lambda e: e.estimated_cost)

        # Build Pareto frontier: walk cost-sorted list, keep only those
        # that improve quality over the best quality seen so far.
        frontier: list[CostEstimate] = []
        best_quality = -1.0
        for est in feasible:
            if est.estimated_quality > best_quality:
                frontier.append(est)
                best_quality = est.estimated_quality

        return frontier

    def simulate(self, task: TaskProfile, model_name: str, volume: int) -> dict[str, object]:
        """Project costs for running a model at a given request volume.

        Args:
            task: The task profile to simulate.
            model_name: Name of the model to simulate.
            volume: Number of requests to project.

        Returns:
            Dict with per-request cost, total cost, and model metadata.

        Raises:
            KeyError: If model_name is not registered.
        """
        if model_name not in self._models:
            raise KeyError(f"Unknown model: {model_name}")

        model = self._models[model_name]
        per_request = self.estimate_cost(model, task)
        total_cost = round(per_request.estimated_cost * volume, 6)

        return {
            "model_name": model_name,
            "task_type": task.task_type,
            "volume": volume,
            "cost_per_request": per_request.estimated_cost,
            "total_cost": total_cost,
            "estimated_quality": per_request.estimated_quality,
            "estimated_latency_ms": per_request.estimated_latency_ms,
        }

    def suggest_routing(self, tasks: list[TaskProfile]) -> dict[str, str]:
        """For each task type, suggest the cheapest model meeting constraints."""
        routing: dict[str, str] = {}
        for task in tasks:
            result = self.recommend(task)
            if result.recommendations:
                routing[task.task_type] = result.recommendations[0].model_name
        return routing
