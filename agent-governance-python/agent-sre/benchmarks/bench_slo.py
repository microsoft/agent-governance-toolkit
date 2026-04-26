# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Performance benchmarks for the SLO Engine.

Measures throughput and latency of:
- SLO evaluation
- Error budget calculation
- Burn rate alert detection
- SLI recording (all 7 indicator types)
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from agent_sre.slo.indicators import (
    CostPerTask,
    DelegationChainDepth,
    HallucinationRate,
    PolicyCompliance,
    ResponseLatency,
    TaskSuccessRate,
    ToolCallAccuracy,
)
from agent_sre.slo.objectives import ErrorBudget, SLO


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
    """Run *fn* for *iterations* and collect per-call latencies."""
    latencies: list[float] = []
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        latencies.append((time.perf_counter() - t0) * 1_000_000)  # µs
    elapsed = time.perf_counter() - start
    return BenchResult(name="", ops=iterations, elapsed_s=elapsed, latencies_us=latencies)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------


def bench_slo_evaluation(iterations: int = 10_000) -> BenchResult:
    """Benchmark SLO.evaluate() throughput and latency."""
    tsr = TaskSuccessRate(target=0.95, window="1h")
    for _ in range(100):
        tsr.record_task(success=True)
    slo = SLO(name="bench-slo", indicators=[tsr], error_budget=ErrorBudget(total=0.05))
    for _ in range(50):
        slo.record_event(good=True)

    result = _timed_loop(slo.evaluate, iterations)
    result.name = "SLO Evaluation"
    return result


def bench_error_budget_calc(iterations: int = 10_000) -> BenchResult:
    """Benchmark ErrorBudget remaining/burn-rate calculations."""
    budget = ErrorBudget(total=0.05, window_seconds=2_592_000)
    for i in range(200):
        budget.record_event(good=(i % 10 != 0))

    def _calc():
        _ = budget.remaining_percent
        _ = budget.burn_rate()

    result = _timed_loop(_calc, iterations)
    result.name = "Error Budget Calc"
    return result


def bench_burn_rate_alert(iterations: int = 10_000) -> BenchResult:
    """Benchmark burn rate alert detection time."""
    budget = ErrorBudget(total=0.05, burn_rate_alert=2.0, burn_rate_critical=10.0)
    for i in range(200):
        budget.record_event(good=(i % 5 != 0))

    result = _timed_loop(budget.firing_alerts, iterations)
    result.name = "Burn Rate Alert"
    return result


def bench_sli_recording(iterations: int = 10_000) -> BenchResult:
    """Benchmark SLI recording throughput across all 7 indicator types."""
    indicators = [
        TaskSuccessRate(target=0.99, window="1h"),
        ToolCallAccuracy(target=0.999, window="1h"),
        ResponseLatency(target_ms=5000, window="1h"),
        CostPerTask(target_usd=0.50, window="1h"),
        PolicyCompliance(target=1.0, window="1h"),
        DelegationChainDepth(max_depth=3, window="1h"),
        HallucinationRate(target=0.05, window="1h"),
    ]
    idx = 0

    def _record():
        nonlocal idx
        ind = indicators[idx % 7]
        ind.record(0.95)
        idx += 1

    result = _timed_loop(_record, iterations)
    result.name = "SLI Recording"
    return result


def run_all(iterations: int = 10_000) -> list[BenchResult]:
    """Run all SLO benchmarks and return results."""
    return [
        bench_slo_evaluation(iterations),
        bench_error_budget_calc(iterations),
        bench_burn_rate_alert(iterations),
        bench_sli_recording(iterations),
    ]


if __name__ == "__main__":
    for r in run_all():
        print(
            f"{r.name:25s}  {r.throughput:>12,.0f} ops/sec  "
            f"p50={r.p50_us:>8.2f}µs  p99={r.p99_us:>8.2f}µs"
        )
