# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Performance benchmarks for the Chaos Engine.

Measures throughput and latency of:
- Fault injection
- Template instantiation (9 built-in templates)
- Chaos schedule evaluation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime

from agent_sre.chaos.engine import (
    AbortCondition,
    ChaosExperiment,
    Fault,
    FaultType,
)
from agent_sre.chaos.library import ChaosLibrary
from agent_sre.chaos.scheduler import BlackoutWindow, ChaosSchedule, ProgressiveConfig


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


def bench_fault_injection(iterations: int = 10_000) -> BenchResult:
    """Benchmark fault injection event creation and recording."""
    experiment = ChaosExperiment(
        name="bench-experiment",
        target_agent="bench-agent",
        faults=[
            Fault.tool_timeout("search", delay_ms=5000),
            Fault.tool_error("db", error="connection_refused"),
        ],
        duration_seconds=60,
    )
    experiment.start()

    fault = experiment.faults[0]

    def _inject():
        experiment.inject_fault(fault, applied=True)

    result = _timed_loop(_inject, iterations)
    result.name = "Fault Injection"
    return result


def bench_template_instantiation(iterations: int = 10_000) -> BenchResult:
    """Benchmark instantiation throughput across all 9 templates."""
    library = ChaosLibrary()
    templates = library.list_templates()
    idx = 0

    def _instantiate():
        nonlocal idx
        tmpl = templates[idx % len(templates)]
        tmpl.instantiate(target_agent="bench-agent")
        idx += 1

    result = _timed_loop(_instantiate, iterations)
    result.name = "Chaos Template Init"
    return result


def bench_chaos_schedule_evaluation(iterations: int = 10_000) -> BenchResult:
    """Benchmark chaos schedule blackout-window evaluation."""
    schedule = ChaosSchedule(
        id="bench-schedule",
        name="Bench Schedule",
        experiment_id="exp-001",
        cron_expression="0 */6 * * *",
        blackout_windows=[
            BlackoutWindow(start="22:00", end="06:00", reason="night freeze"),
            BlackoutWindow(start="12:00", end="13:00", reason="lunch deploy"),
        ],
        progressive_config=ProgressiveConfig(
            initial_severity=0.1,
            max_severity=1.0,
            step_increase=0.1,
        ),
    )
    now = datetime(2025, 6, 15, 14, 30)

    def _evaluate():
        for bw in schedule.blackout_windows:
            bw.contains(now)

    result = _timed_loop(_evaluate, iterations)
    result.name = "Chaos Schedule Eval"
    return result


def run_all(iterations: int = 10_000) -> list[BenchResult]:
    """Run all Chaos Engine benchmarks and return results."""
    return [
        bench_fault_injection(iterations),
        bench_template_instantiation(iterations),
        bench_chaos_schedule_evaluation(iterations),
    ]


if __name__ == "__main__":
    for r in run_all():
        print(
            f"{r.name:25s}  {r.throughput:>12,.0f} ops/sec  "
            f"p50={r.p50_us:>8.2f}µs  p99={r.p99_us:>8.2f}µs"
        )
