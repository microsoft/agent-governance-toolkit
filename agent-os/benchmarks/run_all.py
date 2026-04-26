# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run all Agent-OS benchmarks and output JSON + markdown results."""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from benchmarks import bench_adapters, bench_audit, bench_kernel, bench_policy


def collect_results() -> Dict[str, Any]:
    """Run every benchmark module and collect results."""
    results: List[Dict[str, Any]] = []
    print("Running kernel benchmarks...", flush=True)
    results.extend(bench_kernel.run_all())
    print("Running policy benchmarks...", flush=True)
    results.extend(bench_policy.run_all())
    print("Running audit benchmarks...", flush=True)
    results.extend(bench_audit.run_all())
    print("Running adapter benchmarks...", flush=True)
    results.extend(bench_adapters.run_all())
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "results": results,
    }


def write_json(data: Dict[str, Any], path: Path) -> None:
    """Write benchmark results as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"JSON results written to {path}")


def write_markdown(data: Dict[str, Any], path: Path) -> None:
    """Write benchmark results as a markdown table."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Agent OS Performance Benchmarks\n",
        f"> Benchmarked on: {data['platform']}, Python {data['python']}\n",
        f"> Timestamp: {data['timestamp']}\n",
        "## Results\n",
        "| Operation | Throughput | Latency (p50) | Latency (p99) |",
        "|-----------|-----------|---------------|---------------|",
    ]
    for r in data["results"]:
        if r.get("skipped"):
            lines.append(f"| {r['name']} | skipped | — | — |")
            continue
        ops = f"{r.get('ops_per_sec', '—'):,} ops/sec" if "ops_per_sec" in r else "—"
        p50 = f"{r['p50_ms']}ms" if "p50_ms" in r else "—"
        p99 = f"{r['p99_ms']}ms" if "p99_ms" in r else "—"
        lines.append(f"| {r['name']} | {ops} | {p50} | {p99} |")
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Markdown results written to {path}")


def main() -> None:
    results_dir = Path(__file__).parent / "results"
    data = collect_results()
    write_json(data, results_dir / "benchmarks.json")
    write_markdown(data, results_dir / "benchmarks_latest.md")
    print("\nAll benchmarks complete.")


if __name__ == "__main__":
    main()
