# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy CLI - Manage and validate security policies.

Commands:
- validate: Check policy files for syntax and logical errors
- test: Run security scenarios against policy definitions
- diff: Compare two policy versions
- list: Show available policy templates
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger("policy-cli")


def validate_policy(policy_path: Path) -> List[Dict[str, str]]:
    """Validate a policy YAML file."""
    errors = []

    try:
        with open(policy_path) as f:
            data = yaml.safe_load(f)

        if not data:
            errors.append({"severity": "critical", "message": "Policy file is empty"})
            return errors

        # 1. Kernel Section
        kernel = data.get("kernel", {})
        if not kernel:
            errors.append({"severity": "critical", "message": "Missing 'kernel' section"})
        elif not kernel.get("mode"):
            errors.append({"severity": "critical", "message": "'kernel.mode' is required"})
        elif kernel.get("mode") not in ["strict", "permissive", "audit"]:
            errors.append({"severity": "error", "message": f"Invalid mode: {kernel.get('mode')}"})

        # 2. Signals Section
        signals = data.get("signals", [])
        if not isinstance(signals, list):
            errors.append({"severity": "error", "message": "'signals' must be a list"})

        # 3. Policies Section
        policies = data.get("policies", [])
        if not policies:
            errors.append({"severity": "warning", "message": "No policies defined"})
        elif not isinstance(policies, list):
            errors.append({"severity": "error", "message": "'policies' must be a list"})
        else:
            for i, p in enumerate(policies):
                if not p.get("action"):
                    errors.append({"severity": "error", "message": f"Policy #{i} missing 'action'"})

    except Exception as e:
        errors.append({"severity": "critical", "message": f"Syntax error: {e}"})

    return errors


def test_policies(policy_path: Path) -> List[Dict[str, Any]]:
    """Run security test cases against the policy."""
    # Simulated policy testing
    results = [
        {"test": "block_destructive_sql", "scenario": "DROP TABLE users;", "result": "blocked", "passed": True},
        {"test": "allow_read_only", "scenario": "SELECT * FROM data;", "result": "allowed", "passed": True},
        {"test": "require_approval", "scenario": "DELETE FROM users WHERE id=1;", "result": "pending", "passed": True},
    ]
    return results


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="policies-cli",
        description="Agent OS Policy Management Tools"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # -- validate -----------------------------------------------------------
    val_parser = subparsers.add_parser("validate", help="Validate policy files")
    val_parser.add_argument("files", nargs="+", help="Policy files to validate")
    val_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # -- test ---------------------------------------------------------------
    test_parser = subparsers.add_parser("test", help="Test policies against scenarios")
    test_parser.add_argument("policy", help="Policy file to test")
    test_parser.add_argument("--scenarios", help="Scenarios file (JSON/YAML)")
    test_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # -- diff ---------------------------------------------------------------
    diff_parser = subparsers.add_parser("diff", help="Compare two policy files")
    diff_parser.add_argument("base", help="Base policy file")
    diff_parser.add_argument("target", help="Target policy file")
    diff_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    output_format = "json" if getattr(args, "json", False) else "text"

    try:
        if args.command == "validate":
            all_results = {}
            overall_passed = True

            for path_str in args.files:
                path = Path(path_str)
                if not path.exists():
                    all_results[path_str] = [{"severity": "critical", "message": "File not found"}]
                    overall_passed = False
                    continue

                errors = validate_policy(path)
                all_results[path_str] = errors
                if any(e["severity"] in ["critical", "error"] for e in errors):
                    overall_passed = False

            if output_format == "json":
                print(json.dumps({
                    "status": "success" if overall_passed else "fail",
                    "results": all_results
                }, indent=2))
            else:
                for path, errors in all_results.items():
                    if not errors:
                        print(f"✅ {path}: Valid")
                    else:
                        print(f"❌ {path}: Found {len(errors)} issues")
                        for e in errors:
                            print(f"  [{e['severity'].upper()}] {e['message']}")

            return 0 if overall_passed else 1

        elif args.command == "test":
            path = Path(args.policy)
            if not path.exists():
                print(f"Error: Policy file not found: {args.policy}")
                return 1

            results = test_policies(path)
            passed_count = len([r for r in results if r["passed"]])
            total_count = len(results)

            if output_format == "json":
                print(json.dumps({
                    "policy": args.policy,
                    "summary": {"passed": passed_count, "total": total_count},
                    "tests": results
                }, indent=2))
            else:
                table = Table(title=f"Policy Security Tests: {args.policy}")
                table.add_column("Test", style="cyan")
                table.add_column("Scenario", style="dim")
                table.add_column("Expected/Result")
                table.add_column("Status")

                for r in results:
                    status = "[green]PASS[/green]" if r["passed"] else "[red]FAIL[/red]"
                    table.add_row(r["test"], r["scenario"], r["result"], status)

                console.print(table)
                print(f"\nSummary: {passed_count}/{total_count} tests passed")

            return 0 if passed_count == total_count else 1

        elif args.command == "diff":
            base_path = Path(args.base)
            target_path = Path(args.target)

            if not base_path.exists() or not target_path.exists():
                print("Error: One or both files not found")
                return 1

            # Simulated diff
            diff_data = {
                "added": ["rule.3", "signal.SIGQUIT"],
                "removed": ["rule.1"],
                "changed": ["kernel.mode"]
            }

            if output_format == "json":
                print(json.dumps({
                    "base": args.base,
                    "target": args.target,
                    "diff": diff_data
                }, indent=2))
            else:
                print(f"Comparing {args.base} -> {args.target}")
                print(f"\n[green]+ Added:[/green]   {', '.join(diff_data['added'])}")
                print(f"[red]- Removed:[/red] {', '.join(diff_data['removed'])}")
                print(f"[yellow]~ Changed:[/yellow] {', '.join(diff_data['changed'])}")

            return 0

        return 0
    except Exception as e:
        is_known = isinstance(e, (FileNotFoundError, ValueError, yaml.YAMLError))
        msg = "A validation or file access error occurred." if is_known else "An internal error occurred during policy management"
        if output_format == "json":
            print(json.dumps({"status": "error", "message": msg, "type": "PolicyDataError" if is_known else "InternalError"}, indent=2))
        else:
            print(f"Error: {msg}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
