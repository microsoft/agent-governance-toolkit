#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security scan for agent governance code.

Runs all security skill checks against Python source files.
Can be used as a standalone CLI tool, pre-commit hook, or CI step.

Usage:
    # Scan a directory
    python scripts/security_scan.py agent-governance-python/agent-os/src/

    # Scan specific files
    python scripts/security_scan.py path/to/file.py

    # Scan staged Git files (pre-commit mode)
    python scripts/security_scan.py --staged

    # JSON output for CI
    python scripts/security_scan.py . --format json

    # Fail only on critical/high
    python scripts/security_scan.py . --min-severity high
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Allow running from repo root without installing
REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_OS_SRC = REPO_ROOT / "packages" / "agent-os" / "src"
if AGENT_OS_SRC.exists():
    sys.path.insert(0, str(AGENT_OS_SRC))

from agent_os.security_skills import (
    SecurityFinding,
    Severity,
    format_findings,
    scan_directory,
    scan_file,
    scan_source,
)

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def get_staged_files() -> list[str]:
    """Get Python files staged for commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [f for f in result.stdout.strip().split("\n") if f.endswith(".py")]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def findings_to_json(findings: list[SecurityFinding]) -> str:
    """Serialize findings to JSON for CI integration."""
    return json.dumps(
        [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "suggestion": f.suggestion,
                "owasp_risks": list(f.owasp_risks),
            }
            for f in findings
        ],
        indent=2,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Security scan for agent governance code",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to scan",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan Git staged files (pre-commit mode)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Minimum severity to fail on (default: high)",
    )
    parser.add_argument(
        "--exclude-tests",
        action="store_true",
        help="Skip test files",
    )

    args = parser.parse_args()

    all_findings: list[SecurityFinding] = []

    if args.staged:
        files = get_staged_files()
        if not files:
            print("No staged Python files to scan.", file=sys.stderr)
            return 0
        for f in files:
            all_findings.extend(scan_file(f))
    elif args.paths:
        for path_str in args.paths:
            p = Path(path_str)
            if p.is_dir():
                all_findings.extend(
                    scan_directory(p, exclude_tests=args.exclude_tests)
                )
            elif p.is_file():
                all_findings.extend(scan_file(p))
            else:
                print(f"Warning: {path_str} not found", file=sys.stderr)
    else:
        # Default: scan all packages
        pkg_dir = REPO_ROOT / "packages"
        if pkg_dir.exists():
            all_findings.extend(
                scan_directory(pkg_dir, exclude_tests=args.exclude_tests)
            )

    # Output
    if args.format == "json":
        print(findings_to_json(all_findings))
    else:
        print(format_findings(all_findings))

    # Determine exit code based on min-severity threshold
    min_sev = Severity(args.min_severity)
    threshold_idx = SEVERITY_ORDER.index(min_sev)
    blocking = [
        f for f in all_findings
        if SEVERITY_ORDER.index(f.severity) <= threshold_idx
    ]

    if blocking:
        print(
            f"\n{len(blocking)} finding(s) at or above "
            f"{args.min_severity} severity.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
