# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``agentos validate`` command implementation.

Validates policy YAML files against the bundled JSON Schema and performs
structural checks with human-readable error reporting.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .output import Colors, get_output_format


# ============================================================================
# Schema & Structural Validation Helpers
# ============================================================================


def _load_json_schema() -> "dict | None":
    """Load the bundled policy JSON schema, returning None if unavailable."""
    schema_path = Path(__file__).parent.parent / "policies" / "policy_schema.json"
    if schema_path.exists():
        return json.loads(schema_path.read_text(encoding="utf-8"))
    return None


def _validate_yaml_with_line_numbers(filepath: Path, content: dict, strict: bool) -> "tuple[list, list]":
    """Validate a parsed YAML policy dict and return (errors, warnings).

    Performs three validation passes in order:
    1. JSON Schema validation via ``jsonschema`` (best-effort, skipped if not installed).
    2. Required-field checks (``version``, ``name``).
    3. Rule structure checks and strict-mode unknown-field warnings.

    Args:
        filepath: Path to the source YAML file (used in error messages).
        content: Parsed YAML content as a plain dict.
        strict: When True, unknown top-level fields are reported as warnings.

    Returns:
        A tuple of (errors, warnings) where each element is a list of
        human-readable strings prefixed with the filepath and location.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # ── Pass 1: JSON Schema validation (best-effort) ──────────────────────
    schema = _load_json_schema()
    if schema is not None:
        try:
            import jsonschema  # type: ignore[import-untyped]

            validator = jsonschema.Draft7Validator(schema)
            for ve in sorted(validator.iter_errors(content), key=lambda e: list(e.absolute_path)):
                # Build a human-readable location string from the JSON path
                location = " -> ".join(str(p) for p in ve.absolute_path) or "<root>"
                error_msg = f"{filepath}: [{location}] {ve.message}"
                # Downgrade rule-level schema errors to warnings for legacy rules with 'type'
                path_parts = list(ve.absolute_path)
                rules_list = content.get('rules')
                if (len(path_parts) >= 2 and path_parts[0] == 'rules'
                        and isinstance(path_parts[1], int)
                        and isinstance(rules_list, list)
                        and path_parts[1] < len(rules_list)
                        and isinstance(rules_list[path_parts[1]], dict)
                        and 'type' in rules_list[path_parts[1]]):
                    warnings.append(error_msg)
                else:
                    errors.append(error_msg)
        except ImportError:
            pass  # jsonschema not installed — fall through to manual checks

    # ── Pass 2: Required field checks ────────────────────────────────────
    REQUIRED_FIELDS = ["version", "name"]
    for field in REQUIRED_FIELDS:
        if field not in content:
            errors.append(f"{filepath}: Missing required field: '{field}'")

    # Validate version format
    if "version" in content:
        version = str(content["version"])
        if not re.match(r"^\d+(\.\d+)*$", version):
            warnings.append(
                f"{filepath}: Version '{version}' should be numeric (e.g., '1.0')"
            )

    # ── Pass 3: Rule structure checks ────────────────────────────────────
    VALID_RULE_TYPES = ["allow", "deny", "audit", "require"]
    VALID_ACTIONS = ["allow", "deny", "audit", "block"]

    if "rules" in content:
        rules = content["rules"]
        if not isinstance(rules, list):
            errors.append(f"{filepath}: 'rules' must be a list, got {type(rules).__name__}")
        else:
            for i, rule in enumerate(rules):
                rule_ref = f"rules[{i + 1}]"
                if not isinstance(rule, dict):
                    errors.append(f"{filepath}: {rule_ref} must be a mapping, got {type(rule).__name__}")
                    continue
                # action must be a valid value
                if "action" in rule and rule["action"] not in VALID_ACTIONS:
                    errors.append(
                        f"{filepath}: {rule_ref} invalid action '{rule['action']}' "
                        f"(valid: {VALID_ACTIONS})"
                    )
                # legacy 'type' field warning
                if "type" in rule and rule["type"] not in VALID_RULE_TYPES:
                    warnings.append(
                        f"{filepath}: {rule_ref} unknown type '{rule['type']}' "
                        f"(valid: {VALID_RULE_TYPES})"
                    )

    # ── Pass 4: Strict mode — unknown top-level fields ───────────────────
    if strict:
        KNOWN_FIELDS = [
            "version", "name", "description", "rules", "defaults",
            "constraints", "signals", "allowed_actions", "blocked_actions",
            "a2a_conversation_policy",
        ]
        for field in content.keys():
            if field not in KNOWN_FIELDS:
                warnings.append(f"{filepath}: Unknown top-level field '{field}'")

    return errors, warnings


# ============================================================================
# Command
# ============================================================================


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate policy YAML files against the policy schema.

    Parses each file, runs JSON Schema and structural validation, and
    reports errors with field locations. Exits with a non-zero code when
    any file fails validation (CI-friendly).

    Args:
        args: Parsed CLI arguments. Expects ``args.files`` (list of paths)
            and ``args.strict`` (bool).

    Returns:
        0 if all files are valid, 1 if any errors were found.
    """
    import yaml

    print(f"\n{Colors.BOLD}Validating Policy Files{Colors.RESET}\n")

    # ── Discover files ────────────────────────────────────────────────────
    files_to_check: list[Path] = []
    if args.files:
        # Support both direct file paths and glob-style patterns
        for f in args.files:
            p = Path(f)
            if "*" in f or "?" in f:
                files_to_check.extend(sorted(Path(".").glob(f)))
            else:
                files_to_check.append(p)
    else:
        # Default: validate all YAML files in .agents/
        agents_dir = Path(".agents")
        if agents_dir.exists():
            files_to_check = (
                sorted(agents_dir.glob("*.yaml")) + sorted(agents_dir.glob("*.yml"))
            )
        if not files_to_check:
            print(f"{Colors.YELLOW}No policy files found.{Colors.RESET}")
            print("Run 'agentos init' to create default policies, or specify files directly.")
            return 0

    all_errors: list[str] = []
    all_warnings: list[str] = []
    valid_count = 0

    for filepath in files_to_check:
        if not filepath.exists():
            all_errors.append(f"{filepath}: File not found")
            print(f"  {Colors.RED}✗{Colors.RESET} {filepath} — not found")
            continue

        print(f"  Checking {filepath}...", end=" ", flush=True)

        try:
            # ── Step 1: Parse YAML (captures syntax errors with line numbers)
            with open(filepath, encoding="utf-8") as f:
                raw_text = f.read()

            try:
                content = yaml.safe_load(raw_text)
            except yaml.YAMLError as exc:
                # yaml.YAMLError includes line/column info in its string repr
                msg = f"{filepath}: YAML syntax error — {exc}"
                all_errors.append(msg)
                print(f"{Colors.RED}PARSE ERROR{Colors.RESET}")
                continue

            if content is None:
                all_errors.append(f"{filepath}: File is empty")
                print(f"{Colors.RED}EMPTY{Colors.RESET}")
                continue

            if not isinstance(content, dict):
                all_errors.append(
                    f"{filepath}: Top-level value must be a mapping, got {type(content).__name__}"
                )
                print(f"{Colors.RED}INVALID{Colors.RESET}")
                continue

            # ── Step 2: Schema + structural validation ─────────────────────
            file_errors, file_warnings = _validate_yaml_with_line_numbers(
                filepath, content, strict=getattr(args, "strict", False)
            )

            if file_errors:
                all_errors.extend(file_errors)
                print(f"{Colors.RED}INVALID{Colors.RESET}")
            elif file_warnings:
                all_warnings.extend(file_warnings)
                print(f"{Colors.YELLOW}OK (warnings){Colors.RESET}")
                valid_count += 1
            else:
                print(f"{Colors.GREEN}OK{Colors.RESET}")
                valid_count += 1

        except Exception as exc:
            all_errors.append(f"{filepath}: Unexpected error — {exc}")
            print(f"{Colors.RED}ERROR{Colors.RESET}")

    print()

    # ── Summary output ────────────────────────────────────────────────────
    if all_warnings:
        print(f"{Colors.YELLOW}Warnings:{Colors.RESET}")
        for w in all_warnings:
            print(f"  [!] {w}")
        print()

    if all_errors:
        print(f"{Colors.RED}Errors:{Colors.RESET}")
        for e in all_errors:
            print(f"  [x] {e}")
        print()
        print(
            f"{Colors.RED}Validation failed.{Colors.RESET} "
            f"{valid_count}/{len(files_to_check)} file(s) valid."
        )
        return 1


    print(f"{Colors.GREEN}All {valid_count} policy file(s) valid.{Colors.RESET}")
    return 0
