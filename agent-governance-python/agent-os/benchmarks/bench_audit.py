# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmarks for audit system."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from agent_os.base_agent import AuditEntry
from agent_os.policies.evaluator import PolicyDecision


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


_ALLOW_DECISION = PolicyDecision(
    allowed=True, matched_rule="bench-rule", action="ALLOW", reason="benchmark"
)


def _make_entry(agent_id: str = "bench-agent", action: str = "read_data",
                result_success: bool = True) -> AuditEntry:
    """Create an AuditEntry with the current API."""
    return AuditEntry(
        timestamp=datetime.now(timezone.utc),
        agent_id=agent_id,
        request_id="bench-req-001",
        action=action,
        params={"key": "value"},
        decision=_ALLOW_DECISION,
        result_success=result_success,
    )


def bench_audit_entry_write(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark creating and appending AuditEntry objects."""
    audit_log: List[AuditEntry] = []

    def write() -> None:
        audit_log.append(_make_entry())

    return {"name": "Audit Entry Write", **_sync_timer(write, iterations)}


def bench_audit_log_query(num_entries: int = 10_000) -> Dict[str, Any]:
    """Benchmark querying audit log entries by action."""
    audit_log: List[AuditEntry] = []
    for i in range(num_entries):
        audit_log.append(
            _make_entry(
                agent_id=f"agent-{i % 10}",
                action="read_data" if i % 2 == 0 else "write_data",
                result_success=i % 5 != 0,
            )
        )

    def query() -> None:
        [e for e in audit_log if e.action == "read_data" and e.result_success]

    iterations = 1_000
    return {"name": f"Audit Log Query ({num_entries} entries)", **_sync_timer(query, iterations)}


def bench_audit_serialization(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark AuditEntry field access overhead (serialization proxy)."""
    entry = _make_entry()

    def serialize() -> None:
        _ = {
            "timestamp": str(entry.timestamp),
            "agent_id": entry.agent_id,
            "request_id": entry.request_id,
            "action": entry.action,
            "decision_allowed": entry.decision.allowed,
            "result_success": entry.result_success,
        }

    return {"name": "Audit Entry Serialization", **_sync_timer(serialize, iterations)}


def bench_execution_time_tracking(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark the overhead of execution time tracking."""
    latencies: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        # Simulate execution time tracking pattern used in BaseAgent
        exec_start = time.perf_counter()
        _ = 1 + 1  # minimal work
        _ = time.perf_counter() - exec_start
        _ = _make_entry()
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
