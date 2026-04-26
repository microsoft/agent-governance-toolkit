# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Performance benchmarks for Progressive Delivery.

Measures throughput and latency of:
- Staged rollout analysis (step analysis criteria evaluation)
- Rollback decision checks
- Traffic split calculation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from agent_sre.delivery.rollout import (
    AnalysisCriterion,
    CanaryRollout,
    RollbackCondition,
    RolloutStep,
)


@dataclass
class BenchResult:
    """Single benchmark result."""

    name: str
    ops: int
    elapsed_s: float
    latencies_us: list[float] = field(default_factory=list)

    @property
    def throughput(self) -> float:
        return self.ops / self.elapsed_s if self.elapsed_s > 0 else 0.0

    @property
    def p50_us(self) -> float:
        if not self.latencies_us:
            return 0.0
        s = sorted(self.latencies_us)
        return s[len(s) // 2]

    @property
    def p99_us(self) -> float:
        if not self.latencies_us:
            return 0.0
        s = sorted(self.latencies_us)
        return s[int(len(s) * 0.99)]


def _timed_loop(fn, iterations: int = 10_000) -> BenchResult:
    latencies: list[float] = []
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        latencies.append((time.perf_counter() - t0) * 1_000_000)
    elapsed = time.perf_counter() - start
    return BenchResult(name="", ops=iterations, elapsed_s=elapsed, latencies_us=latencies)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------


def bench_canary_analysis(iterations: int = 10_000) -> BenchResult:
    """Benchmark canary step analysis criteria evaluation."""
    criteria = [
        AnalysisCriterion(metric="task_success_rate", threshold=0.99, comparator="gte"),
        AnalysisCriterion(metric="cost_per_task", threshold=0.50, comparator="lte"),
        AnalysisCriterion(metric="hallucination_rate", threshold=0.05, comparator="lte"),
        AnalysisCriterion(metric="response_latency_p95", threshold=5000.0, comparator="lte"),
    ]
    metrics = {
        "task_success_rate": 0.995,
        "cost_per_task": 0.35,
        "hallucination_rate": 0.02,
        "response_latency_p95": 3200.0,
    }

    def _analyze():
        for c in criteria:
            c.evaluate(metrics.get(c.metric, 0.0))

    result = _timed_loop(_analyze, iterations)
    result.name = "Staged Rollout Analysis"
    return result


def bench_rollback_decision(iterations: int = 10_000) -> BenchResult:
    """Benchmark rollback condition checking."""
    rollout = CanaryRollout(
        name="bench-rollout",
        steps=[
            RolloutStep(name="canary-5%", weight=0.05, duration_seconds=3600),
            RolloutStep(name="canary-25%", weight=0.25, duration_seconds=7200),
            RolloutStep(name="full", weight=1.0),
        ],
        rollback_conditions=[
            RollbackCondition(metric="error_rate", threshold=0.05, comparator="gte"),
            RollbackCondition(metric="cost_per_task", threshold=2.0, comparator="gte"),
            RollbackCondition(metric="burn_rate", threshold=5.0, comparator="gte"),
        ],
    )
    rollout.start()
    metrics = {"error_rate": 0.02, "cost_per_task": 0.45, "burn_rate": 1.2}

    def _check():
        rollout.check_rollback(metrics)

    result = _timed_loop(_check, iterations)
    result.name = "Rollback Decision"
    return result


def bench_traffic_split(iterations: int = 10_000) -> BenchResult:
    """Benchmark traffic split weight calculation during rollout progression."""
    rollout = CanaryRollout(
        name="bench-split",
        steps=[
            RolloutStep(name="canary-5%", weight=0.05, duration_seconds=3600),
            RolloutStep(name="canary-25%", weight=0.25, duration_seconds=7200),
            RolloutStep(name="canary-50%", weight=0.50, duration_seconds=7200),
            RolloutStep(name="full", weight=1.0),
        ],
    )
    rollout.start()

    def _split():
        _ = rollout.current_weight
        _ = rollout.progress_percent

    result = _timed_loop(_split, iterations)
    result.name = "Traffic Split Calc"
    return result


def run_all(iterations: int = 10_000) -> list[BenchResult]:
    """Run all Progressive Delivery benchmarks and return results."""
    return [
        bench_canary_analysis(iterations),
        bench_rollback_decision(iterations),
        bench_traffic_split(iterations),
    ]


if __name__ == "__main__":
    for r in run_all():
        print(
            f"{r.name:25s}  {r.throughput:>12,.0f} ops/sec  "
            f"p50={r.p50_us:>8.2f}µs  p99={r.p99_us:>8.2f}µs"
        )
