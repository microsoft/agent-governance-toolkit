#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run all Agent SRE performance benchmarks.

Usage:
    python benchmarks/run_all.py [--iterations N]
"""

from __future__ import annotations

import argparse
import sys

from benchmarks.bench_chaos import run_all as chaos_benchmarks
from benchmarks.bench_delivery import run_all as delivery_benchmarks
from benchmarks.bench_slo import run_all as slo_benchmarks

HEADER = (
    f"{'Benchmark':30s}  {'Throughput':>14s}  {'p50':>10s}  {'p99':>10s}"
)
SEP = "-" * len(HEADER)


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent SRE performance benchmarks")
    parser.add_argument(
        "--iterations", "-n", type=int, default=10_000, help="Iterations per benchmark"
    )
    args = parser.parse_args()
    n = args.iterations

    print()
    print("Agent SRE — Performance Benchmarks")
    print(f"Iterations per benchmark: {n:,}")
    print()
    print(HEADER)
    print(SEP)

    sections = [
        ("SLO Engine", slo_benchmarks),
        ("Chaos Engine", chaos_benchmarks),
        ("Progressive Delivery", delivery_benchmarks),
    ]

    for section_name, runner in sections:
        print(f"\n  [{section_name}]")
        for r in runner(n):
            throughput = f"{r.throughput:,.0f} ops/sec"
            p50 = f"{r.p50_us:.2f}µs"
            p99 = f"{r.p99_us:.2f}µs"
            print(f"  {r.name:28s}  {throughput:>14s}  {p50:>10s}  {p99:>10s}")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
