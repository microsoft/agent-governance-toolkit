#!/usr/bin/env python3
"""Collect Criterion estimates into one stats JSON document."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def criterion_name(estimates_path: Path, root: Path) -> str:
    bench_dir = estimates_path.parent.parent
    return "/".join(bench_dir.relative_to(root).parts)


def numeric(value: Any) -> int | None:
    if isinstance(value, (int, float)):
        return int(round(value))
    return None


def collect(root: Path) -> dict[str, dict[str, int]]:
    benches: dict[str, dict[str, int]] = {}
    if not root.is_dir():
        return benches

    for estimates_path in sorted(root.glob("**/new/estimates.json")):
        try:
            estimates = json.loads(estimates_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue

        mean = estimates.get("mean", {})
        point = numeric(mean.get("point_estimate"))
        upper = numeric(mean.get("confidence_interval", {}).get("upper_bound"))
        if point is None:
            continue

        benches[criterion_name(estimates_path, root)] = {
            "ns_per_iter": point,
            "p95_ns": upper if upper is not None else point,
        }
    return benches


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path("target/criterion")
    output = {"format_version": 1, "benches": collect(root)}
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
