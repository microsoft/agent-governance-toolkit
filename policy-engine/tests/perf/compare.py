#!/usr/bin/env python3
"""Compare current Criterion stats against committed ACS core baselines."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_benches(path: Path) -> dict[str, dict[str, int]]:
    data = json.loads(path.read_text())
    if data.get("format_version") != 1:
        raise ValueError(f"{path} has unsupported format_version")
    benches = data.get("benches")
    if not isinstance(benches, dict):
        raise ValueError(f"{path} does not contain a benches object")
    return benches


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--threshold", type=float, default=25.0)
    parser.add_argument("--metric", choices=["p95_ns", "ns_per_iter"], default="p95_ns")
    args = parser.parse_args()

    baseline = load_benches(args.baseline)
    current = load_benches(args.current)

    failures: list[str] = []
    missing: list[str] = []

    for name, base in sorted(baseline.items()):
        cur = current.get(name)
        if cur is None:
            missing.append(name)
            continue

        base_value = int(base.get(args.metric, 0))
        cur_value = int(cur.get(args.metric, 0))
        if base_value <= 0:
            continue

        delta_pct = (cur_value - base_value) * 100.0 / base_value
        marker = " regression" if delta_pct > args.threshold else ""
        print(
            f"{name} [{args.metric}]: {base_value} -> {cur_value} "
            f"({delta_pct:+.2f}%){marker}"
        )
        if delta_pct > args.threshold:
            failures.append(
                f"{name}: {delta_pct:+.2f}% over baseline {args.metric} "
                f"with threshold {args.threshold:.2f}%"
            )

    for name in sorted(set(current) - set(baseline)):
        print(f"{name} [{args.metric}]: NEW {current[name].get(args.metric, 0)}")

    if missing:
        print("ERROR: missing current benchmarks: " + ", ".join(missing), file=sys.stderr)
        return 1
    if failures:
        print("ERROR: benchmark regressions:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"OK: every baseline benchmark is within {args.threshold:.2f}% on {args.metric}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
