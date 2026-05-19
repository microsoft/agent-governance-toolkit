#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validate YAML frontmatter on docs pages.

Required fields are configurable. By default this checks ``title``,
``last_reviewed``, and ``owner``. ``last_reviewed`` must parse as an
ISO-8601 calendar date (``YYYY-MM-DD``).

Pages without any frontmatter are reported as missing-frontmatter (one
finding per page). Pages with a frontmatter block missing one or more
required keys get one finding per missing key.

By default the checker runs in **warn** mode and exits 0 even when
findings exist — this lets the foundation PR land without forcing every
existing page to be edited in the same change. Pass ``--strict`` to exit
non-zero on findings (used by the final IA capstone PR).

Usage::

    python scripts/docs/check_frontmatter.py
    python scripts/docs/check_frontmatter.py --strict
    python scripts/docs/check_frontmatter.py --required title owner
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

DEFAULT_REQUIRED = ("title", "last_reviewed", "owner")

_FRONTMATTER_RE = re.compile(
    r"\A\ufeff?---\s*\n(?P<body>.*?)\n---\s*(?:\n|\Z)",
    re.DOTALL,
)

# Minimal flat YAML key parser: `key: value`. We deliberately avoid a
# YAML dependency for this CI gate — docs frontmatter is consistently
# flat in this repo. Nested structures are out of scope and would be
# reported as ``invalid scalar``.
_KEY_RE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*(?P<value>.*?)\s*$")


@dataclass
class Finding:
    source: Path
    severity: str  # "error" | "warn"
    message: str

    def format(self, root: Path) -> str:
        try:
            rel = self.source.relative_to(root)
        except ValueError:
            rel = self.source
        return f"[{self.severity}] {rel}: {self.message}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0


def parse_frontmatter(text: str) -> dict[str, str] | None:
    """Return a flat dict of frontmatter keys, or None if absent.

    Values are returned as raw strings (no type coercion). Quoted values
    have their surrounding single or double quotes stripped.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None
    body = m.group("body")
    out: dict[str, str] = {}
    for raw in body.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        km = _KEY_RE.match(line)
        if not km:
            # ignore continuation / nested lines silently — flat parser
            continue
        key = km.group("key").strip()
        value = km.group("value").strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        out[key] = value
    return out


def _validate_last_reviewed(value: str) -> str | None:
    """Return an error message if ``value`` is not a valid ISO date."""
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return f"last_reviewed must be YYYY-MM-DD, got {value!r}"
    return None


def check_file(
    path: Path,
    required: Iterable[str],
    strict: bool,
) -> list[Finding]:
    severity = "error" if strict else "warn"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [Finding(path, "error", f"unreadable: {exc}")]

    fm = parse_frontmatter(text)
    if fm is None:
        return [Finding(path, severity, "missing frontmatter block")]

    findings: list[Finding] = []
    for key in required:
        if key not in fm or not fm[key]:
            findings.append(Finding(path, severity, f"missing required key: {key}"))
    if "last_reviewed" in fm and fm["last_reviewed"]:
        err = _validate_last_reviewed(fm["last_reviewed"])
        if err:
            findings.append(Finding(path, severity, err))
    return findings


# Reuse discovery logic — small enough to duplicate without adding a dep
DEFAULT_EXCLUDES = (
    ".git",
    "node_modules",
    "site",
    "target",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
    "overrides",  # MkDocs theme overrides — not user-authored pages
    "stylesheets",
    "assets",
    "i18n",  # translated pages tracked separately
)


def discover_docs(root: Path, extras: Iterable[Path]) -> list[Path]:
    explicit = [p.resolve() for p in extras if p.suffix.lower() == ".md" and p.is_file()]
    if explicit:
        return explicit
    docs_dir = root / "docs"
    if not docs_dir.is_dir():
        return []
    out: list[Path] = []
    for p in docs_dir.rglob("*.md"):
        if any(part in DEFAULT_EXCLUDES for part in p.parts):
            continue
        out.append(p.resolve())
    return sorted(set(out))


def check(
    root: Path,
    required: Iterable[str] = DEFAULT_REQUIRED,
    paths: Iterable[Path] = (),
    strict: bool = False,
) -> Report:
    report = Report()
    for f in discover_docs(root, paths):
        report.files_scanned += 1
        report.findings.extend(check_file(f, required, strict))
    return report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*", type=Path, help="Specific markdown files (optional).")
    p.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root (default: cwd).")
    p.add_argument(
        "--required",
        nargs="+",
        default=list(DEFAULT_REQUIRED),
        help=f"Required frontmatter keys (default: {' '.join(DEFAULT_REQUIRED)}).",
    )
    p.add_argument("--strict", action="store_true", help="Exit non-zero on findings.")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON report.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = args.root.resolve()
    report = check(root, args.required, args.paths, strict=args.strict)

    if args.json:
        payload = {
            "files_scanned": report.files_scanned,
            "strict": args.strict,
            "required": list(args.required),
            "findings": [
                {
                    "source": str(f.source.relative_to(root)) if f.source.is_relative_to(root) else str(f.source),
                    "severity": f.severity,
                    "message": f.message,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        for finding in report.findings:
            print(finding.format(root))
        print(
            f"\nScanned {report.files_scanned} file(s), "
            f"{len(report.findings)} finding(s)."
        )

    if args.strict and report.findings:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
