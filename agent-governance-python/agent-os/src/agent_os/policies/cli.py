# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy CLI - Manage and validate security policies.

Commands:
- validate: Check a policy file against the PolicyDocument schema
- test: Run security scenarios against policy definitions
- diff: Compare two policy versions structurally
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, List

import yaml
from pydantic import ValidationError

from agent_os.policies.schema import PolicyDocument


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_file(path: Path) -> dict:
    """Load a YAML or JSON file and return the parsed dict."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _evaluate_condition(condition: dict, context: dict) -> bool:
    """Evaluate a single policy condition against a context dict."""
    field = condition.get("field", "")
    operator = condition.get("operator", "eq")
    value = condition.get("value")

    if field not in context:
        return False

    ctx_value = context[field]

    if operator == "eq":
        return ctx_value == value
    if operator == "ne":
        return ctx_value != value
    if operator == "gt":
        return ctx_value > value
    if operator == "lt":
        return ctx_value < value
    if operator == "gte":
        return ctx_value >= value
    if operator == "lte":
        return ctx_value <= value
    if operator == "in":
        return ctx_value in value
    if operator == "contains":
        return value in ctx_value
    if operator == "matches":
        return bool(re.match(str(value), str(ctx_value)))

    return False


def _resolve_action(rules: list[dict], defaults: dict | None, context: dict) -> str:
    """Find the first matching rule (highest priority) and return its action."""
    sorted_rules = sorted(rules, key=lambda r: r.get("priority", 0), reverse=True)

    for rule in sorted_rules:
        condition = rule.get("condition", {})
        if _evaluate_condition(condition, context):
            return rule.get("action", "allow")

    if defaults:
        return defaults.get("action", "allow")
    return "allow"


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------


def _cmd_validate(args: argparse.Namespace) -> int:
    """Validate a policy file against the PolicyDocument Pydantic schema."""
    path = Path(args.file)

    if not path.exists():
        print("ERROR: File not found: " + str(path), file=sys.stderr)
        return 2

    try:
        data = _load_file(path)
    except Exception:
        print("ERROR: Could not parse file: " + str(path), file=sys.stderr)
        return 2

    if data is None:
        data = {}

    try:
        PolicyDocument.model_validate(data)
    except ValidationError as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1

    print("OK")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    """Run test scenarios against a policy."""
    policy_path = Path(args.policy)
    scenarios_path = Path(args.scenarios)

    if not policy_path.exists():
        print("ERROR: Policy file not found: " + str(policy_path), file=sys.stderr)
        return 2

    if not scenarios_path.exists():
        print("ERROR: Scenarios file not found: " + str(scenarios_path), file=sys.stderr)
        return 2

    try:
        policy_data = _load_file(policy_path)
        scenarios_data = _load_file(scenarios_path)
    except Exception:
        print("ERROR: Could not parse files", file=sys.stderr)
        return 2

    rules = (policy_data or {}).get("rules", [])
    defaults = (policy_data or {}).get("defaults", {})
    scenarios: list[dict[str, Any]] = (scenarios_data or {}).get("scenarios", [])

    if not scenarios:
        print("ERROR: No scenarios provided", file=sys.stderr)
        return 2

    passed = 0
    total = len(scenarios)

    for scenario in scenarios:
        context = scenario.get("context", {})
        expected_action = scenario.get("expected_action")
        expected_allowed = scenario.get("expected_allowed")

        actual_action = _resolve_action(rules, defaults, context)
        actual_allowed = actual_action == "allow"

        ok = True
        if expected_action is not None and actual_action != expected_action:
            ok = False
        if expected_allowed is not None and actual_allowed != expected_allowed:
            ok = False

        if ok:
            passed += 1
        else:
            print(
                f"FAIL: {scenario.get('name', 'unnamed')}: "
                f"expected {expected_action}, got {actual_action}",
                file=sys.stderr,
            )

    print(f"{passed}/{total} scenarios passed")
    return 0 if passed == total else 1


def _cmd_diff(args: argparse.Namespace) -> int:
    """Compare two policy files structurally."""
    base_path = Path(args.base)
    target_path = Path(args.target)

    if not base_path.exists():
        print("ERROR: File not found: " + str(base_path), file=sys.stderr)
        return 2
    if not target_path.exists():
        print("ERROR: File not found: " + str(target_path), file=sys.stderr)
        return 2

    try:
        base_data = _load_file(base_path)
        target_data = _load_file(target_path)
    except Exception:
        print("ERROR: Could not parse files", file=sys.stderr)
        return 2

    if base_data == target_data:
        print("No differences")
        return 0

    diffs: list[str] = []

    # --- rules ---
    base_rules = {r["name"]: r for r in (base_data.get("rules") or [])}
    target_rules = {r["name"]: r for r in (target_data.get("rules") or [])}

    for name in target_rules:
        if name not in base_rules:
            diffs.append(f"rule added: {name}")

    for name in base_rules:
        if name not in target_rules:
            diffs.append(f"rule removed: {name}")

    for name in base_rules:
        if name in target_rules:
            br = base_rules[name]
            tr = target_rules[name]
            all_keys = set(br.keys()) | set(tr.keys())
            for key in sorted(all_keys):
                if br.get(key) != tr.get(key):
                    diffs.append(f"rule {name}: {key}: {br.get(key)} -> {tr.get(key)}")

    # --- defaults ---
    base_defaults = (base_data.get("defaults") or {})
    target_defaults = (target_data.get("defaults") or {})
    all_def_keys = set(base_defaults.keys()) | set(target_defaults.keys())
    for key in sorted(all_def_keys):
        if base_defaults.get(key) != target_defaults.get(key):
            diffs.append(f"defaults: {key}: {base_defaults.get(key)} -> {target_defaults.get(key)}")

    # --- other top-level fields ---
    for key in sorted(set(base_data.keys()) | set(target_data.keys())):
        if key in ("rules", "defaults"):
            continue
        if base_data.get(key) != target_data.get(key):
            diffs.append(f"{key}: {base_data.get(key)} -> {target_data.get(key)}")

    for d in diffs:
        print(d)

    return 1 if diffs else 0


# ---------------------------------------------------------------------------
# Parser / entry-point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="policies-cli",
        description="Agent OS Policy Management Tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # -- validate -----------------------------------------------------------
    val_parser = subparsers.add_parser("validate", help="Validate a policy file")
    val_parser.add_argument("file", help="Policy file to validate")

    # -- test ---------------------------------------------------------------
    test_parser = subparsers.add_parser("test", help="Test policy against scenarios")
    test_parser.add_argument("policy", help="Policy file to test")
    test_parser.add_argument("scenarios", help="Scenarios file (YAML/JSON)")

    # -- diff ---------------------------------------------------------------
    diff_parser = subparsers.add_parser("diff", help="Compare two policy files")
    diff_parser.add_argument("base", help="Base policy file")
    diff_parser.add_argument("target", help="Target policy file")

    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "validate":
        return _cmd_validate(args)
    if args.command == "test":
        return _cmd_test(args)
    if args.command == "diff":
        return _cmd_diff(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
