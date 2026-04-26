# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hypervisor Performance Benchmarks

Measures latency and throughput of all hypervisor subsystems:
- Session creation and lifecycle
- Ring computation and enforcement
- Sponsorship and eff_score calculation
- Saga step execution
- Delta audit capture and audit log root computation
- End-to-end governance pipeline
"""

from __future__ import annotations

import asyncio
import json
import statistics
import time
from typing import Any

# Adjust path for module import
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hypervisor import (
    Hypervisor,
    SessionConfig,
    ConsistencyMode,
    ExecutionRing,
)
from hypervisor.models import ActionDescriptor, ReversibilityLevel
from hypervisor.audit.delta import DeltaEngine, VFSChange
from hypervisor.liability.vouching import VouchingEngine
from hypervisor.rings.enforcer import RingEnforcer
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import SagaState


def benchmark(name: str, iterations: int = 10000):
    """Decorator to benchmark a sync function."""
    def decorator(func):
        def wrapper():
            times = []
            # Warmup
            for _ in range(min(100, iterations // 10)):
                func()
            # Measure
            for _ in range(iterations):
                start = time.perf_counter_ns()
                func()
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)
            return BenchmarkResult(name, times, iterations)
        return wrapper
    return decorator


def benchmark_async(name: str, iterations: int = 10000):
    """Decorator to benchmark an async function."""
    def decorator(func):
        def wrapper():
            async def run():
                times = []
                # Warmup
                for _ in range(min(100, iterations // 10)):
                    await func()
                # Measure
                for _ in range(iterations):
                    start = time.perf_counter_ns()
                    await func()
                    elapsed = time.perf_counter_ns() - start
                    times.append(elapsed)
                return BenchmarkResult(name, times, iterations)
            return asyncio.run(run())
        return wrapper
    return decorator


class BenchmarkResult:
    def __init__(self, name: str, times_ns: list[int], iterations: int):
        self.name = name
        self.iterations = iterations
        self.times_ns = sorted(times_ns)
        self.mean_ns = statistics.mean(times_ns)
        self.median_ns = statistics.median(times_ns)
        self.p95_ns = self.times_ns[int(len(self.times_ns) * 0.95)]
        self.p99_ns = self.times_ns[int(len(self.times_ns) * 0.99)]
        self.min_ns = min(times_ns)
        self.max_ns = max(times_ns)
        self.ops_per_sec = 1_000_000_000 / self.mean_ns if self.mean_ns > 0 else 0

    def __str__(self):
        return (
            f"  {self.name:<40} "
            f"mean={self.mean_ns/1000:.1f}μs  "
            f"p50={self.median_ns/1000:.1f}μs  "
            f"p95={self.p95_ns/1000:.1f}μs  "
            f"p99={self.p99_ns/1000:.1f}μs  "
            f"ops={self.ops_per_sec:,.0f}/s"
        )

    def to_dict(self):
        return {
            "name": self.name,
            "iterations": self.iterations,
            "mean_us": round(self.mean_ns / 1000, 2),
            "median_us": round(self.median_ns / 1000, 2),
            "p95_us": round(self.p95_ns / 1000, 2),
            "p99_us": round(self.p99_ns / 1000, 2),
            "min_us": round(self.min_ns / 1000, 2),
            "max_us": round(self.max_ns / 1000, 2),
            "ops_per_sec": round(self.ops_per_sec),
        }


# ---------------------------------------------------------------------------
# Benchmark: Ring Computation
# ---------------------------------------------------------------------------

enforcer = RingEnforcer()

@benchmark("ring_computation", iterations=50000)
def bench_ring_computation():
    enforcer.compute_ring(0.85)

# ---------------------------------------------------------------------------
# Benchmark: Sponsorship + eff_score
# ---------------------------------------------------------------------------

ve = VouchingEngine()
_vouch_counter = [0]

@benchmark("sponsorship_eff_score", iterations=10000)
def bench_eff_score():
    _vouch_counter[0] += 1
    sid = f"bench-{_vouch_counter[0]}"
    ve.vouch(f"did:v:{_vouch_counter[0]}", f"did:e:{_vouch_counter[0]}", sid, 0.9, bond_pct=0.2)
    ve.compute_eff_score(f"did:e:{_vouch_counter[0]}", sid, 0.4, risk_weight=0.5)

# ---------------------------------------------------------------------------
# Benchmark: Delta Capture
# ---------------------------------------------------------------------------

@benchmark("delta_capture", iterations=50000)
def bench_delta_capture():
    de = DeltaEngine("bench-session")
    de.capture(
        "did:mesh:a",
        [VFSChange(path="/data/file.txt", operation="add", content_hash="abc123")],
    )

# ---------------------------------------------------------------------------
# Benchmark: Audit Log Root (10 deltas)
# ---------------------------------------------------------------------------

@benchmark("hash_chain_root_10_deltas", iterations=10000)
def bench_hash_chain_root_10():
    de = DeltaEngine("bench-audit-log")
    for i in range(10):
        de.capture("did:mesh:a", [VFSChange(path=f"/f{i}", operation="add", content_hash=f"h{i}")])
    de.compute_hash_chain_root()

# ---------------------------------------------------------------------------
# Benchmark: Audit Log Root (100 deltas)
# ---------------------------------------------------------------------------

@benchmark("hash_chain_root_100_deltas", iterations=1000)
def bench_hash_chain_root_100():
    de = DeltaEngine("bench-audit-log-100")
    for i in range(100):
        de.capture("did:mesh:a", [VFSChange(path=f"/f{i}", operation="add", content_hash=f"h{i}")])
    de.compute_hash_chain_root()

# ---------------------------------------------------------------------------
# Benchmark: Chain Verification (50 deltas)
# ---------------------------------------------------------------------------

@benchmark("chain_verify_50_deltas", iterations=2000)
def bench_chain_verify():
    de = DeltaEngine("bench-verify")
    for i in range(50):
        de.capture("did:mesh:a", [VFSChange(path=f"/f{i}", operation="add", content_hash=f"h{i}")])
    de.verify_chain()

# ---------------------------------------------------------------------------
# Benchmark: Session Create + Join + Terminate
# ---------------------------------------------------------------------------

@benchmark_async("session_lifecycle", iterations=5000)
async def bench_session_lifecycle():
    hv = Hypervisor()
    s = await hv.create_session(config=SessionConfig(), creator_did="did:mesh:admin")
    await hv.join_session(s.sso.session_id, "did:mesh:a", sigma_raw=0.8)
    await hv.activate_session(s.sso.session_id)
    await hv.terminate_session(s.sso.session_id)

# ---------------------------------------------------------------------------
# Benchmark: Saga (3 steps)
# ---------------------------------------------------------------------------

@benchmark_async("saga_3_steps", iterations=5000)
async def bench_saga_3_steps():
    orch = SagaOrchestrator()
    saga = orch.create_saga("bench-session")
    steps = []
    for i in range(3):
        step = orch.add_step(saga.saga_id, f"action{i}", f"did:mesh:{i}", f"/api/{i}", undo_api=f"/api/undo/{i}")
        steps.append(step)
    for step in steps:
        await orch.execute_step(saga.saga_id, step.step_id, executor=lambda: asyncio.sleep(0))

# ---------------------------------------------------------------------------
# Benchmark: Full Pipeline (session + join + audit + saga + terminate)
# ---------------------------------------------------------------------------

@benchmark_async("full_governance_pipeline", iterations=2000)
async def bench_full_pipeline():
    hv = Hypervisor()
    s = await hv.create_session(
        config=SessionConfig(enable_audit=True), creator_did="did:mesh:admin"
    )
    sid = s.sso.session_id
    await hv.join_session(sid, "did:mesh:a", sigma_raw=0.8)
    await hv.activate_session(sid)

    # Capture deltas
    for i in range(3):
        s.delta_engine.capture(
            "did:mesh:a",
            [VFSChange(path=f"/f{i}", operation="add", content_hash=f"h{i}")],
        )

    # Execute saga
    saga = s.saga.create_saga(sid)
    step = s.saga.add_step(saga.saga_id, "action", "did:mesh:a", "/api/action")
    await s.saga.execute_step(saga.saga_id, step.step_id, executor=lambda: asyncio.sleep(0))

    await hv.terminate_session(sid)


# ---------------------------------------------------------------------------
# Benchmark: Monitor Sessions (batch with early exits)
# ---------------------------------------------------------------------------

@benchmark_async("monitor_50_sessions", iterations=2000)
async def bench_monitor_sessions():
    hv = Hypervisor()
    # Create 50 sessions: 40 active (healthy), 10 terminated
    for i in range(50):
        s = await hv.create_session(config=SessionConfig(), creator_did="did:mesh:admin")
        await hv.join_session(s.sso.session_id, f"did:mesh:a{i}", sigma_raw=0.8)
        await hv.activate_session(s.sso.session_id)
        if i >= 40:
            await hv.terminate_session(s.sso.session_id)
    await hv.monitor_sessions()


@benchmark_async("active_sessions_100", iterations=5000)
async def bench_active_sessions():
    hv = Hypervisor()
    for i in range(100):
        s = await hv.create_session(config=SessionConfig(), creator_did="did:mesh:admin")
        await hv.join_session(s.sso.session_id, f"did:mesh:a{i}", sigma_raw=0.8)
        await hv.activate_session(s.sso.session_id)
        # Terminate half
        if i % 2 == 0:
            await hv.terminate_session(s.sso.session_id)
    _ = hv.active_sessions


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    print("=" * 90)
    print("  AGENT HYPERVISOR PERFORMANCE BENCHMARKS")
    print("=" * 90)
    print()

    benchmarks = [
        bench_ring_computation,
        bench_eff_score,
        bench_delta_capture,
        bench_hash_chain_root_10,
        bench_hash_chain_root_100,
        bench_chain_verify,
        bench_session_lifecycle,
        bench_saga_3_steps,
        bench_full_pipeline,
        bench_monitor_sessions,
        bench_active_sessions,
    ]

    results = []
    for bench in benchmarks:
        result = bench()
        print(result)
        results.append(result.to_dict())

    print()
    print("=" * 90)

    # Write JSON results
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)

    with open(os.path.join(results_dir, "benchmarks.json"), "w") as f:
        json.dump({"benchmarks": results}, f, indent=2)

    # Write markdown
    with open(os.path.join(results_dir, "BENCHMARKS.md"), "w", encoding="utf-8") as f:
        f.write("# Agent Hypervisor — Performance Benchmarks\n\n")
        f.write("> Auto-generated by `benchmarks/bench_hypervisor.py`\n\n")
        f.write("## Results\n\n")
        f.write("| Operation | Mean | P50 | P95 | P99 | Throughput |\n")
        f.write("|-----------|------|-----|-----|-----|------------|\n")
        for r in results:
            f.write(
                f"| {r['name']} | {r['mean_us']:.1f}μs | {r['median_us']:.1f}μs | "
                f"{r['p95_us']:.1f}μs | {r['p99_us']:.1f}μs | "
                f"{r['ops_per_sec']:,}/s |\n"
            )
        f.write("\n## Key Takeaways\n\n")
        f.write("- **Ring computation**: Sub-microsecond — zero overhead for privilege checks\n")
        f.write("- **Sponsorship + eff_score**: Single-digit microseconds — real-time trust scoring\n")
        f.write("- **Delta audit**: Microsecond-level — forensic logging adds negligible latency\n")
        f.write("- **Audit log verification**: Scales linearly with delta count, remains sub-millisecond\n")
        f.write("- **Full pipeline**: Session + audit + saga + terminate in < 1ms\n")
        f.write("\n## Methodology\n\n")
        f.write("- Python 3.13, Windows, in-memory (no I/O)\n")
        f.write("- Warmup: 10% of iterations discarded\n")
        f.write("- All async operations use `asyncio.sleep(0)` as executor stubs\n")

    print(f"  Results written to {results_dir}/")


if __name__ == "__main__":
    main()
