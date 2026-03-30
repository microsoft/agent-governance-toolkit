# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy-as-code CLI for Agent-OS governance.

Provides commands to validate, test, and diff declarative policy documents
without external dependencies beyond the standard library and pydantic/pyyaml.

Usage:
    python -m agent_os.policies.cli validate <path>
    python -m agent_os.policies.cli test <policy_path> <test_scenarios_path>
    python -m agent_os.policies.cli diff <path1> <path2>

Exit codes:
    0 - Success
    1 - Validation failure / test failure
    2 - Runtime error (file not found, parse error, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Lazy imports — keep startup fast and give clear messages when deps missing.
# ---------------------------------------------------------------------------


def _import_yaml() -> Any:
    try:
        import yaml

        return yaml
    except ImportError:
        print("ERROR: pyyaml is required — pip install pyyaml", file=sys.stderr)
        sys.exit(2)

def _import_console(no_color: bool = False, use_stderr: bool = False):
    '''Lazy import for rich.console.Console.'''
    try:
        from rich.console import Console
        
        return Console(stderr=use_stderr, no_color=no_color)
    except (ModuleNotFoundError, ImportError):
        print("WARNING: rich library not installed, using plain text output", file=sys.stderr)
        return None 

def _import_rich_text() ->Any:
    '''Lazy import for rich.text.Text.'''
    try:
        from rich.text import Text
        
        return Text
    except ImportError as e:
        print(f"WARNING: {e}", file=sys.stderr)
        return None       

def _load_file(path: Path) -> dict[str, Any]:
    """Load a YAML or JSON file and return the parsed dict."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        yaml = _import_yaml()
        data = yaml.safe_load(text)
    elif path.suffix == ".json":
        data = json.loads(text)
    else:
        # Try YAML first, fall back to JSON
        yaml = _import_yaml()
        try:
            data = yaml.safe_load(text)
        except Exception:
            data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a mapping at top level, got {type(data).__name__}")
    return data


# ---------------------------------------------------------------------------
# Colored output helpers — use rich when available, fall back to plain text.
# ---------------------------------------------------------------------------


def error(msg: str, no_color: bool = False) -> None:
    """Print an error message in red to stderr."""
    console = _import_console(no_color, use_stderr=True)  
    Text = _import_rich_text()
    if console and Text:
        console.print(Text(msg), style="red")
    else:
        print(msg, file=sys.stderr)

def success(msg: str, no_color: bool = False) -> None:
    """Print a success message in green to stdout."""
    console = _import_console(no_color, use_stderr=False) 
    Text = _import_rich_text()
    if console and Text:
        console.print(Text(msg), style="green")
    else:
        print(msg)

def warn(msg: str, no_color: bool = False) -> None:
    """Print a warning message in yellow to stdout."""
    console = _import_console(no_color, use_stderr=False)
    Text = _import_rich_text()
    if console and Text:
        console.print(Text(msg), style="yellow")
    else:
        print(msg)

def policy_violation(msg: str, no_color: bool = False) -> None:
    """Print a policy violation message in bold red to stdout."""
    console = _import_console(no_color, use_stderr=True)
    Text = _import_rich_text()
    if console and Text:
        console.print(Text(msg), style="bold red")
    else:
        print(msg)

def passed_check(msg: str, no_color: bool = False) -> None:
    """Print a passed-check message with a green checkmark to stdout."""
    console = _import_console(no_color, use_stderr=False)
    Text = _import_rich_text()
    if console and Text:
        console.print(Text(f"\u2714 {msg}"), style="green")
    else:
        print(f"\u2714 {msg}")


# ============================================================================
# validate
# ============================================================================


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a policy YAML/JSON file against the PolicyDocument schema."""
    from .schema import PolicyDocument  # noqa: E402

    path = Path(args.path)
    if not path.exists():
        error(f"ERROR: file not found: {path}")
        return 2

    try:
        data = _load_file(path)
    except Exception as exc:
        error(f"ERROR: failed to parse {path}: {exc}")
        return 2

    # --- Optional JSON-Schema validation (best-effort) --------------------
    schema_path = Path(__file__).with_name("policy_schema.json")
    if schema_path.exists():
        try:
            import jsonschema  # type: ignore[import-untyped]

            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=data, schema=schema)
        except ImportError:
            pass  # jsonschema not installed — skip, rely on Pydantic
        except jsonschema.ValidationError as ve:
            policy_violation(f"FAIL: {path}")
            policy_violation(f"  JSON-Schema error: {ve.message}")
            if ve.absolute_path:
                policy_violation(f"  Location: {' -> '.join(str(p) for p in ve.absolute_path)}")
            return 1

    # --- Pydantic validation (authoritative) ------------------------------
    try:
        PolicyDocument.model_validate(data)
    except Exception as exc:
        policy_violation(f"FAIL: {path}")
        for line in str(exc).splitlines():
            policy_violation(f"  {line}")
        return 1

    success(f"OK: {path}")
    return 0


# ============================================================================
# test
# ============================================================================


def cmd_test(args: argparse.Namespace) -> int:
    """Test a policy against a set of scenarios."""
    from .evaluator import PolicyEvaluator  # noqa: E402
    from .schema import PolicyDocument  # noqa: E402

    policy_path = Path(args.policy_path)
    scenarios_path = Path(args.test_scenarios_path)

    for p in (policy_path, scenarios_path):
        if not p.exists():
            error(f"ERROR: file not found: {p}")
            return 2

    # Load the policy
    try:
        doc = PolicyDocument.from_yaml(policy_path)
    except Exception as exc:
        try:
            doc = PolicyDocument.from_json(policy_path)
        except Exception:
            error(f"ERROR: failed to load policy {policy_path}: {exc}")
            return 2

    # Load scenarios
    try:
        scenarios_data = _load_file(scenarios_path)
    except Exception as exc:
        error(f"ERROR: failed to parse scenarios {scenarios_path}: {exc}")
        return 2

    scenarios = scenarios_data.get("scenarios", [])
    if not scenarios:
        error("ERROR: no scenarios found in test file")
        return 2

    evaluator = PolicyEvaluator(policies=[doc])
    passed = 0
    failed = 0
    total = len(scenarios)

    for scenario in scenarios:
        name = scenario.get("name", "<unnamed>")
        context = scenario.get("context", {})
        expected_allowed = scenario.get("expected_allowed")
        expected_action = scenario.get("expected_action")

        decision = evaluator.evaluate(context)
        errors: list[str] = []

        if expected_allowed is not None and decision.allowed != expected_allowed:
            errors.append(
                f"expected allowed={expected_allowed}, got allowed={decision.allowed}"
            )
        if expected_action is not None and decision.action != expected_action:
            errors.append(
                f"expected action='{expected_action}', got action='{decision.action}'"
            )

        if errors:
            failed += 1
            policy_violation(f"  FAIL: {name}")
            for err in errors:
                policy_violation(f"    - {err}")
        else:
            passed += 1
            passed_check(f"  PASS: {name}")

    summary = f"\n{passed}/{total} scenarios passed."
    if failed > 0:
        warn(summary)
    else:
        success(summary)

    return 1 if failed > 0 else 0


# ============================================================================
# diff
# ============================================================================


def cmd_diff(args: argparse.Namespace) -> int:
    """Show differences between two policy files."""
    from .schema import PolicyDocument  # noqa: E402

    path1 = Path(args.path1)
    path2 = Path(args.path2)

    for p in (path1, path2):
        if not p.exists():
            error(f"ERROR: file not found: {p}")
            return 2

    try:
        doc1 = PolicyDocument.model_validate(_load_file(path1))
        doc2 = PolicyDocument.model_validate(_load_file(path2))
    except Exception as exc:
        error(f"ERROR: failed to load policies: {exc}")
        return 2

    differences: list[str] = []

    # Metadata changes
    if doc1.version != doc2.version:
        differences.append(f"  version: '{doc1.version}' -> '{doc2.version}'")
    if doc1.name != doc2.name:
        differences.append(f"  name: '{doc1.name}' -> '{doc2.name}'")
    if doc1.description != doc2.description:
        differences.append("  description changed")

    # Default changes
    if doc1.defaults.action != doc2.defaults.action:
        differences.append(
            f"  defaults.action: '{doc1.defaults.action.value}' -> '{doc2.defaults.action.value}'"
        )
    if doc1.defaults.max_tokens != doc2.defaults.max_tokens:
        differences.append(
            f"  defaults.max_tokens: {doc1.defaults.max_tokens} -> {doc2.defaults.max_tokens}"
        )
    if doc1.defaults.max_tool_calls != doc2.defaults.max_tool_calls:
        differences.append(
            f"  defaults.max_tool_calls: "
            f"{doc1.defaults.max_tool_calls} -> {doc2.defaults.max_tool_calls}"
        )
    if doc1.defaults.confidence_threshold != doc2.defaults.confidence_threshold:
        differences.append(
            f"  defaults.confidence_threshold: "
            f"{doc1.defaults.confidence_threshold} -> {doc2.defaults.confidence_threshold}"
        )

    # Rule changes
    rules1 = {r.name: r for r in doc1.rules}
    rules2 = {r.name: r for r in doc2.rules}
    names1 = set(rules1.keys())
    names2 = set(rules2.keys())

    for name in sorted(names1 - names2):
        r = rules1[name]
        differences.append(f"  rule removed: '{name}' (action={r.action.value}, priority={r.priority})")

    for name in sorted(names2 - names1):
        r = rules2[name]
        differences.append(f"  rule added: '{name}' (action={r.action.value}, priority={r.priority})")

    for name in sorted(names1 & names2):
        r1 = rules1[name]
        r2 = rules2[name]
        if r1.action != r2.action:
            differences.append(
                f"  rule '{name}' action: '{r1.action.value}' -> '{r2.action.value}'"
            )
        if r1.priority != r2.priority:
            differences.append(
                f"  rule '{name}' priority: {r1.priority} -> {r2.priority}"
            )
        if r1.condition != r2.condition:
            differences.append(f"  rule '{name}' condition changed")
        if r1.message != r2.message:
            differences.append(f"  rule '{name}' message changed")

    if differences:
        warn(f"Differences between {path1} and {path2}:")
        for diff in differences:
            warn(diff)
        return 1
    else:
        success(f"No differences between {path1} and {path2}.")
        return 0


# ============================================================================
# Main entry point
# ============================================================================


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the appropriate subcommand."""
    parser = argparse.ArgumentParser(
        prog="policy-cli",
        description="Agent-OS policy-as-code CLI for validation, testing, and diffing.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- validate ----------------------------------------------------------
    p_validate = subparsers.add_parser(
        "validate",
        help="Validate a policy YAML/JSON file against the schema.",
    )
    p_validate.add_argument("path", help="Path to the policy file to validate.")

    # -- test --------------------------------------------------------------
    p_test = subparsers.add_parser(
        "test",
        help="Test a policy against a set of scenarios.",
    )
    p_test.add_argument("policy_path", help="Path to the policy file.")
    p_test.add_argument("test_scenarios_path", help="Path to the test scenarios YAML.")

    # -- diff --------------------------------------------------------------
    p_diff = subparsers.add_parser(
        "diff",
        help="Show differences between two policy files.",
    )
    p_diff.add_argument("path1", help="Path to the first policy file.")
    p_diff.add_argument("path2", help="Path to the second policy file.")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    dispatch = {
        "validate": cmd_validate,
        "test": cmd_test,
        "diff": cmd_diff,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())