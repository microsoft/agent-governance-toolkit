#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONF = REPO / "tests" / "conformance"


def load_case_ids() -> set[str]:
    return {json.loads(path.read_text(encoding="utf-8"))["id"] for path in (CONF / "cases").glob("*.json")}


def parse_coverage() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in (CONF / "coverage.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("| ---") or "Spec section" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        section = cells[0]
        cases = "|".join(cells[3:])
        rows[section] = re.findall(r"spec-[A-Za-z0-9._-]+\.case-[0-9]{2}", cases)
    return rows


def main() -> int:
    case_ids = load_case_ids()
    coverage = parse_coverage()
    failures: list[str] = []
    for section, cases in sorted(coverage.items()):
        for case_id in cases:
            if case_id not in case_ids:
                failures.append(f"section {section} references missing case {case_id}")
    covered = {case_id for cases in coverage.values() for case_id in cases}
    for case_id in sorted(case_ids - covered):
        failures.append(f"case {case_id} is not mapped in coverage.md")
    if failures:
        for failure in failures:
            print(failure)
        return 1
    print(f"release claims PASS sections={len(coverage)} cases={len(case_ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
