# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmarks for StatelessKernel enforcement."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

from agent_os.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from agent_os.stateless import ExecutionContext, MemoryBackend, StatelessKernel


def _timer(func, iterations: int = 10_000) -> Dict[str, Any]:
    """Run an async function *iterations* times and return latency stats."""
    loop = asyncio.new_event_loop()
    latencies: List[float] = []
    try:
        for _ in range(iterations):
            start = time.perf_counter()
            loop.run_until_complete(func())
            latencies.append((time.perf_counter() - start) * 1_000)  # ms
    finally:
        loop.close()
    latencies.sort()
    total_seconds = sum(latencies) / 1_000
    return {
        "iterations": iterations,
        "total_seconds": round(total_seconds, 4),
        "ops_per_sec": round(iterations / total_seconds) if total_seconds > 0 else 0,
        "p50_ms": round(latencies[len(latencies) // 2], 4),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 4),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 4),
    }


def bench_kernel_execute_allow(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark kernel.execute() when the action is allowed."""
    kernel = StatelessKernel(backend=MemoryBackend())
    ctx = ExecutionContext(agent_id="bench-agent", policies=[])

    async def run() -> None:
        await kernel.execute("read_data", {"key": "test"}, ctx)

    return {"name": "Kernel Execute (allow)", **_timer(run, iterations)}


def bench_kernel_execute_deny(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark kernel.execute() when the action is denied by policy."""
    kernel = StatelessKernel(backend=MemoryBackend())
    ctx = ExecutionContext(agent_id="bench-agent", policies=["read_only"])

    async def run() -> None:
        await kernel.execute("file_write", {"path": "/tmp/x"}, ctx)

    return {"name": "Kernel Execute (deny)", **_timer(run, iterations)}


def bench_concurrent_kernel(concurrency: int = 50, per_task: int = 200) -> Dict[str, Any]:
    """Benchmark concurrent kernel operations."""
    kernel = StatelessKernel(backend=MemoryBackend())

    async def worker() -> None:
        ctx = ExecutionContext(agent_id="bench-concurrent", policies=[])
        for _ in range(per_task):
            await kernel.execute("read_data", {"key": "test"}, ctx)

    async def run_all() -> None:
        await asyncio.gather(*(worker() for _ in range(concurrency)))

    total_ops = concurrency * per_task
    loop = asyncio.new_event_loop()
    start = time.perf_counter()
    try:
        loop.run_until_complete(run_all())
    finally:
        loop.close()
    elapsed = time.perf_counter() - start
    return {
        "name": "Concurrent Kernel Ops",
        "concurrency": concurrency,
        "total_ops": total_ops,
        "total_seconds": round(elapsed, 4),
        "ops_per_sec": round(total_ops / elapsed) if elapsed > 0 else 0,
    }


def bench_circuit_breaker_check(iterations: int = 100_000) -> Dict[str, Any]:
    """Benchmark circuit breaker state check overhead."""
    cb = CircuitBreaker(CircuitBreakerConfig())
    latencies: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        cb.get_state()
        latencies.append((time.perf_counter() - start) * 1_000)
    latencies.sort()
    total_seconds = sum(latencies) / 1_000
    return {
        "name": "Circuit Breaker Check",
        "iterations": iterations,
        "total_seconds": round(total_seconds, 4),
        "ops_per_sec": round(iterations / total_seconds) if total_seconds > 0 else 0,
        "p50_ms": round(latencies[len(latencies) // 2], 4),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 4),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 4),
    }


def run_all() -> List[Dict[str, Any]]:
    """Run all kernel benchmarks and return results."""
    return [
        bench_kernel_execute_allow(),
        bench_kernel_execute_deny(),
        bench_concurrent_kernel(),
        bench_circuit_breaker_check(),
    ]


if __name__ == "__main__":
    import json

    for result in run_all():
        print(json.dumps(result, indent=2))
