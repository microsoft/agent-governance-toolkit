# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy linter for Agent Governance Toolkit.

Validates YAML policy files for common mistakes: missing required fields,
unknown operators/actions, conflicting rules, deprecated field names,
empty rule lists, and invalid priority values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Known values — union of schema.py (PolicyOperator/PolicyAction) and
# shared.py (VALID_OPERATORS/VALID_ACTIONS) so the linter accepts every
# operator and action recognised anywhere in the governance stack.
# ---------------------------------------------------------------------------

KNOWN_OPERATORS = frozenset({
    "eq", "ne", "gt", "lt", "gte", "lte", "in", "not_in", "matches", "contains",
})

KNOWN_ACTIONS = frozenset({
    "allow", "deny", "audit", "block", "escalate", "rate_limit",
})

REQUIRED_FIELDS = ("version", "name", "rules")

DEPRECATED_FIELDS: dict[str, str] = {
    "type": "action",
    "op": "operator",
    "policy_name": "name",
    "policy_version": "version",
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class LintMessage:
    """A single lint finding with severity, message, and file location."""

    severity: str  # "error" or "warning"
    message: str
    file: str
    line: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.severity}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class LintResult:
    """Aggregated lint results for one or more policy files."""

    messages: list[LintMessage] = field(default_factory=list)

    @property
    def errors(self) -> list[LintMessage]:
        return [m for m in self.messages if m.severity == "error"]

    @property
    def warnings(self) -> list[LintMessage]:
        return [m for m in self.messages if m.severity == "warning"]

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        n_err = len(self.errors)
        n_warn = len(self.warnings)
        parts: list[str] = []
        if n_err:
            parts.append(f"{n_err} error(s)")
        if n_warn:
            parts.append(f"{n_warn} warning(s)")
        if not parts:
            return "No issues found."
        return ", ".join(parts) + " found."

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "messages": [m.to_dict() for m in self.messages],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_line(lines: list[str], needle: str, start: int = 0) -> int:
    """Return the 1-based line number where *needle* first appears."""
    for i, raw in enumerate(lines[start:], start=start + 1):
        if needle in raw:
            return i
    return 1


# ---------------------------------------------------------------------------
# Core linting logic
# ---------------------------------------------------------------------------


def lint_file(path: str | Path) -> LintResult:
    """Lint a single YAML policy file and return structured results."""
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("pyyaml is required: pip install pyyaml") from exc

    path = Path(path)
    result = LintResult()

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.messages.append(
            LintMessage("error", f"Cannot read file: {exc}", str(path), 1)
        )
        return result

    lines = raw.splitlines()

    # ── YAML parsing ──────────────────────────────────────────
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        line = 1
        if hasattr(exc, "problem_mark") and exc.problem_mark is not None:
            line = exc.problem_mark.line + 1
        result.messages.append(
            LintMessage("error", f"Invalid YAML: {exc}", str(path), line)
        )
        return result

    if not isinstance(data, dict):
        result.messages.append(
            LintMessage("error", "Policy file must be a YAML mapping", str(path), 1)
        )
        return result

    # ── Required top-level fields ─────────────────────────────
    for field_name in REQUIRED_FIELDS:
        if field_name not in data:
            result.messages.append(
                LintMessage(
                    "error",
                    f"Missing required field '{field_name}'",
                    str(path),
                    1,
                )
            )

    # ── Deprecated top-level fields ───────────────────────────
    for old, new in DEPRECATED_FIELDS.items():
        if old in data:
            line = _find_line(lines, old + ":")
            result.messages.append(
                LintMessage(
                    "warning",
                    f"Deprecated field '{old}'; use '{new}' instead",
                    str(path),
                    line,
                )
            )

    # ── Rules validation ──────────────────────────────────────
    rules = data.get("rules")
    if isinstance(rules, list) and len(rules) == 0:
        line = _find_line(lines, "rules:")
        result.messages.append(
            LintMessage("warning", "Rules list is empty", str(path), line)
        )

    if isinstance(rules, list):
        _lint_rules(rules, lines, str(path), result)

    return result


def _lint_rules(
    rules: list[Any],
    lines: list[str],
    filepath: str,
    result: LintResult,
) -> None:
    """Validate individual rules and detect conflicts."""
    # Track (field, operator, value) -> action for conflict detection
    seen: dict[tuple[str, str, str], str] = {}

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            result.messages.append(
                LintMessage("error", f"Rule {idx} is not a mapping", filepath, 1)
            )
            continue

        rule_name = rule.get("name", f"rule[{idx}]")
        search_hint = rule_name if rule_name != f"rule[{idx}]" else "- name:"
        rule_line = _find_line(lines, search_hint)

        # ── Deprecated fields inside rules ────────────────────
        for old, new in DEPRECATED_FIELDS.items():
            if old in rule:
                line = _find_line(lines, old + ":", max(rule_line - 1, 0))
                result.messages.append(
                    LintMessage(
                        "warning",
                        f"Rule '{rule_name}': deprecated field '{old}'; "
                        f"use '{new}' instead",
                        filepath,
                        line,
                    )
                )

        # ── Action validation ─────────────────────────────────
        action = rule.get("action")
        if action is not None and action not in KNOWN_ACTIONS:
            line = _find_line(lines, str(action), max(rule_line - 1, 0))
            result.messages.append(
                LintMessage(
                    "error",
                    f"Rule '{rule_name}': unknown action '{action}'",
                    filepath,
                    line,
                )
            )

        # ── Condition / conditions validation ─────────────────
        condition = rule.get("condition")
        conditions = rule.get("conditions", [])
        all_conditions: list[dict[str, Any]] = []
        if isinstance(condition, dict):
            all_conditions.append(condition)
        if isinstance(conditions, list):
            all_conditions.extend(c for c in conditions if isinstance(c, dict))

        for cond in all_conditions:
            operator = cond.get("operator")
            if operator is not None and operator not in KNOWN_OPERATORS:
                line = _find_line(lines, str(operator), max(rule_line - 1, 0))
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Rule '{rule_name}': unknown operator '{operator}'",
                        filepath,
                        line,
                    )
                )

            for old, new in DEPRECATED_FIELDS.items():
                if old in cond:
                    line = _find_line(lines, old + ":", max(rule_line - 1, 0))
                    result.messages.append(
                        LintMessage(
                            "warning",
                            f"Rule '{rule_name}': deprecated field '{old}' "
                            f"in condition; use '{new}' instead",
                            filepath,
                            line,
                        )
                    )

        # ── Priority validation ───────────────────────────────
        priority = rule.get("priority")
        if priority is not None and not isinstance(priority, int):
            line = _find_line(lines, "priority:", max(rule_line - 1, 0))
            result.messages.append(
                LintMessage(
                    "error",
                    f"Rule '{rule_name}': priority must be an integer, "
                    f"got {type(priority).__name__}",
                    filepath,
                    line,
                )
            )

        # ── Conflict detection ────────────────────────────────
        if action in ("allow", "deny") and all_conditions:
            for cond in all_conditions:
                key = (
                    cond.get("field", ""),
                    cond.get("operator", ""),
                    str(cond.get("value", "")),
                )
                prev_action = seen.get(key)
                if prev_action is not None and prev_action != action:
                    result.messages.append(
                        LintMessage(
                            "warning",
                            f"Rule '{rule_name}': conflicts with a prior rule "
                            f"— same condition has both '{prev_action}' and "
                            f"'{action}'",
                            filepath,
                            rule_line,
                        )
                    )
                elif prev_action is None:
                    seen[key] = action


def lint_path(path: str | Path) -> LintResult:
    """Lint a file or directory of YAML policy files."""
    path = Path(path)
    if path.is_file():
        return lint_file(path)

    result = LintResult()
    if path.is_dir():
        files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml"))
        if not files:
            result.messages.append(
                LintMessage(
                    "warning", "No YAML policy files found", str(path), 0
                )
            )
            return result
        for f in files:
            sub = lint_file(f)
            result.messages.extend(sub.messages)
    else:
        result.messages.append(
            LintMessage("error", f"Path does not exist: {path}", str(path), 0)
        )

    return result
