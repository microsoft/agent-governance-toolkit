# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmarks for audit system."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from agent_os.base_agent import AuditEntry


def _sync_timer(func, iterations: int = 10_000) -> Dict[str, Any]:
    """Run a synchronous function *iterations* times and return latency stats."""
    latencies: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        latencies.append((time.perf_counter() - start) * 1_000)
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


def bench_audit_entry_write(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark creating and appending AuditEntry objects."""
    audit_log: List[AuditEntry] = []

    def write() -> None:
        entry = AuditEntry(
            agent_id="bench-agent",
            action="read_data",
            success=True,
            metadata={"key": "value"},
        )
        audit_log.append(entry)

    return {"name": "Audit Entry Write", **_sync_timer(write, iterations)}


def bench_audit_log_query(num_entries: int = 10_000) -> Dict[str, Any]:
    """Benchmark querying audit log entries by action."""
    audit_log: List[AuditEntry] = []
    for i in range(num_entries):
        audit_log.append(
            AuditEntry(
                agent_id=f"agent-{i % 10}",
                action="read_data" if i % 2 == 0 else "write_data",
                success=i % 5 != 0,
                metadata={"index": i},
            )
        )

    def query() -> None:
        [e for e in audit_log if e.action == "read_data" and e.success]

    iterations = 1_000
    return {"name": f"Audit Log Query ({num_entries} entries)", **_sync_timer(query, iterations)}


def bench_audit_serialization(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark AuditEntry serialization (to_dict) overhead."""
    entry = AuditEntry(
        agent_id="bench-agent",
        action="read_data",
        success=True,
        metadata={"key": "value", "nested": {"a": 1}},
    )

    return {"name": "Audit Entry Serialization", **_sync_timer(entry.to_dict, iterations)}


def bench_execution_time_tracking(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark the overhead of execution time tracking."""
    latencies: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        # Simulate execution time tracking pattern used in BaseAgent
        exec_start = time.perf_counter()
        _ = 1 + 1  # minimal work
        exec_time = time.perf_counter() - exec_start
        _ = AuditEntry(
            agent_id="bench-agent",
            action="tracked_op",
            success=True,
            metadata={"execution_time_ms": exec_time * 1_000},
        )
        latencies.append((time.perf_counter() - start) * 1_000)
    latencies.sort()
    total_seconds = sum(latencies) / 1_000
    return {
        "name": "Execution Time Tracking",
        "iterations": iterations,
        "total_seconds": round(total_seconds, 4),
        "ops_per_sec": round(iterations / total_seconds) if total_seconds > 0 else 0,
        "p50_ms": round(latencies[len(latencies) // 2], 4),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 4),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 4),
    }


def run_all() -> List[Dict[str, Any]]:
    """Run all audit benchmarks and return results."""
    return [
        bench_audit_entry_write(),
        bench_audit_log_query(),
        bench_audit_serialization(),
        bench_execution_time_tracking(),
    ]


if __name__ == "__main__":
    import json

    for result in run_all():
        print(json.dumps(result, indent=2))
