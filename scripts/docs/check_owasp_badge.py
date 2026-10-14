#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Check that every README's OWASP badge matches the coverage mapping.

The badge is a hand-written string; the coverage table in
``docs/compliance/owasp-agentic-top10-architecture.md`` is the assessment it
summarizes. This checker counts the Full and Partial rows for ASI01 to ASI10
in that table, confirms the document's own summary line agrees with the
rows, and fails on any README whose ``OWASP_Agentic_Top_10`` badge does not
read ``<full>_Full,_<partial>_Partial``.

The AGT extension row is not counted; it sits outside the official ten.

Usage::

    python scripts/docs/check_owasp_badge.py --root .
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MAPPING = Path("docs/compliance/owasp-agentic-top10-architecture.md")
README_GLOBS = ("README.md", "docs/i18n/README.*.md")

_ROW_RE = re.compile(r"^\|\s*(ASI\d{2})\s*\|[^|]*\|\s*[^|A-Za-z]*(Full|Partial|Gap)\b", re.MULTILINE)
_SUMMARY_RE = re.compile(r"Official ASI coverage:\s*(\d+)/10 Full,\s*(\d+)/10 Partial,\s*(\d+) Gaps?")
_BADGE_RE = re.compile(r"img\.shields\.io/badge/OWASP_Agentic_Top_10-([^)\s\"]*?)-[a-z]+")


def coverage(text: str) -> tuple[int, int, int]:
    """Return (full, partial, gap) counted from the ASI rows of the table."""
    found = _ROW_RE.findall(text)
    ids = sorted(asi for asi, _ in found)
    # Compare the full list, not a dict: a duplicated row must fail rather than
    # silently replace the earlier one.
    if ids != [f"ASI{i:02d}" for i in range(1, 11)]:
        raise ValueError(f"expected rows ASI01..ASI10 once each, found {ids}")
    values = [level for _, level in found]
    return values.count("Full"), values.count("Partial"), values.count("Gap")


def expected_badge(full: int, partial: int, gap: int) -> str:
    parts = [f"{full}_Full", f"{partial}_Partial"] + ([f"{gap}_Gap"] if gap else [])
    return ",_".join(parts)


def check(root: Path) -> list[str]:
    text = (root / MAPPING).read_text(encoding="utf-8")
    full, partial, gap = coverage(text)
    errors: list[str] = []

    summary = _SUMMARY_RE.search(text)
    if not summary:
        errors.append(f"{MAPPING}: no 'Official ASI coverage' summary line")
    elif tuple(map(int, summary.groups())) != (full, partial, gap):
        errors.append(
            f"{MAPPING}: summary line says {summary.group(0)!r}, "
            f"table rows count {full} Full, {partial} Partial, {gap} Gap"
        )

    want = expected_badge(full, partial, gap)
    for pattern in README_GLOBS:
        for path in sorted(root.glob(pattern)):
            badges = _BADGE_RE.findall(path.read_text(encoding="utf-8"))
            rel = path.relative_to(root).as_posix()
            for got in badges:
                if got != want:
                    errors.append(f"{rel}: OWASP badge reads {got!r}, mapping table gives {want!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", type=Path, default=Path("."))
    args = p.parse_args(argv)
    errors = check(args.root)
    for e in errors:
        print(f"error: {e}")
    if errors:
        return 1
    print("OWASP badges match the coverage mapping.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
