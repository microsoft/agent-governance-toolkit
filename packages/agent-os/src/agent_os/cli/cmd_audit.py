# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``agentos audit`` command implementation."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from .output import (
    Colors,
    get_output_format,
    handle_missing_config,
    get_config_path,
)


def cmd_audit(args: argparse.Namespace) -> int:
    """Audit agent security configuration."""
    root = Path(get_config_path(getattr(args, "path", None)))
    agents_dir = root / ".agents"
    output_format = get_output_format(args)

    if not agents_dir.exists():
        if output_format == "json":
            print(json.dumps({"error": "Config directory not found", "passed": False}, indent=2))
        else:
            print(handle_missing_config(str(root)))
        return 1

    files = {
        "agents.md": agents_dir / "agents.md",
        "security.md": agents_dir / "security.md",
    }

    findings: list[dict[str, str]] = []
    file_status: dict[str, bool] = {}

    for name, path in files.items():
        exists = path.exists()
        file_status[name] = exists
        if not exists:
            findings.append({"severity": "error", "message": f"Missing {name}"})

    security_md = files["security.md"]
    if security_md.exists():
        content = security_md.read_text()

        dangerous = [
            ("effect: allow", "Permissive allow - consider adding constraints"),
        ]

        for pattern, warning in dangerous:
            if pattern in content and "action: *" in content:
                findings.append({"severity": "warning", "message": warning})

        required = ["kernel:", "signals:", "policies:"]
        for section in required:
            if section not in content:
                findings.append({"severity": "error", "message": f"Missing required section: {section}"})

    passed = all(f["severity"] != "error" for f in findings)

    # CSV export
    export_format = getattr(args, "export", None)
    if export_format == "csv":
        output_path = getattr(args, "output", None) or "audit.csv"
        _export_audit_csv(root, file_status, findings, passed, output_path)
        if output_format != "json":
            print(f"{Colors.GREEN}✓{Colors.RESET} Audit exported to {output_path}")

    if output_format == "json":
        result = {
            "path": str(root),
            "files": file_status,
            "findings": findings,
            "passed": passed,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Auditing {root}...")
        print()

        for name, exists in file_status.items():
            if exists:
                print(f"  {Colors.GREEN}✓{Colors.RESET} {name}")
            else:
                print(f"  {Colors.RED}✗{Colors.RESET} {name}")

        print()

        if findings:
            print("Findings:")
            for f in findings:
                if f["severity"] == "warning":
                    print(f"  {Colors.YELLOW}⚠{Colors.RESET} {f['message']}")
                else:
                    print(f"  {Colors.RED}✗{Colors.RESET} {f['message']}")
        else:
            print(f"{Colors.GREEN}✓{Colors.RESET} No issues found.")

        print()

    return 0 if passed else 1


def _export_audit_csv(
    root: Path,
    file_status: dict[str, bool],
    findings: list[dict[str, str]],
    passed: bool,
    output_path: str,
) -> None:
    """Export audit results to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "name", "severity", "message"])
        for name, exists in file_status.items():
            writer.writerow([
                "file",
                name,
                "ok" if exists else "error",
                "Present" if exists else "Missing",
            ])
        for finding in findings:
            writer.writerow(["finding", "", finding["severity"], finding["message"]])
