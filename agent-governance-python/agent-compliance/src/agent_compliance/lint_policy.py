# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy linter for Agent Governance Toolkit.

Handles two file kinds:

* **ACS manifests** — identified by ``agent_control_specification_version``
  at the top level. Validated via the ``agent_control_specification``
  library; dangling bundle/path references are reported as errors.

* **Governance policy YAML** — identified by a top-level ``rules`` list
  *without* ``agent_control_specification_version``. Validated for
  impossible conditions: an ``in`` or ``not_in`` operator whose ``value``
  list is empty can never match any context, so every rule containing one
  is a silent no-op that masks the configured default action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Membership operators whose value list must be non-empty to be satisfiable
# ---------------------------------------------------------------------------

_MEMBERSHIP_OPERATORS: frozenset[str] = frozenset({"in", "not_in"})


@dataclass
class LintMessage:
    """A single lint finding."""

    severity: str
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
    """Aggregated lint results for one or more manifests."""

    messages: list[LintMessage] = field(default_factory=list)

    @property
    def errors(self) -> list[LintMessage]:
        return [message for message in self.messages if message.severity == "error"]

    @property
    def warnings(self) -> list[LintMessage]:
        return [
            message for message in self.messages if message.severity == "warning"
        ]

    @property
    def passed(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        if not self.messages:
            return "No issues found."
        return (
            f"{len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s) found."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "messages": [message.to_dict() for message in self.messages],
        }


# ---------------------------------------------------------------------------
# Governance policy YAML linting
# ---------------------------------------------------------------------------


def _conditions_from_rule(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all condition dicts from a rule, handling both singular
    ``condition`` and plural ``conditions`` keys."""
    out: list[dict[str, Any]] = []
    c = rule.get("condition")
    if isinstance(c, dict):
        out.append(c)
    cs = rule.get("conditions")
    if isinstance(cs, list):
        out.extend(item for item in cs if isinstance(item, dict))
    return out


def _lint_governance_conditions(
    data: dict[str, Any],
    filepath: str,
    result: LintResult,
) -> None:
    """Check a governance policy document for impossible conditions.

    Currently detects:

    * ``in`` / ``not_in`` operator with an empty ``value`` list.
      Such a condition can never match any context value, so the rule is
      a silent no-op: the evaluator falls through to the default action
      without logging a match or a miss against that rule.

    The ``field`` typo case (e.g. ``toolname`` instead of ``tool_name``) is
    context-dependent and cannot be checked without a schema that enumerates
    every valid field for the target evaluator.  If you add a
    ``KNOWN_CONTEXT_FIELDS`` vocabulary to your project, a straightforward
    extension of this function can warn on unrecognised field names.
    """
    rules = data.get("rules")
    if not isinstance(rules, list):
        return

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        rule_name = rule.get("name", f"rule[{idx}]")

        for cond in _conditions_from_rule(rule):
            operator = cond.get("operator", "")
            if operator not in _MEMBERSHIP_OPERATORS:
                continue

            value = cond.get("value")
            if value is None or (isinstance(value, list) and len(value) == 0):
                field_hint = cond.get("field", "")
                field_clause = f" on field '{field_hint}'" if field_hint else ""
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Rule '{rule_name}': operator '{operator}'{field_clause} "
                        f"has an empty value list — condition can never match; "
                        f"the evaluator will always apply the default action instead",
                        filepath,
                        1,
                    )
                )


def _is_governance_policy(data: Any) -> bool:
    """Return True when *data* looks like a governance policy document.

    A governance policy document has a ``rules`` list but does *not* carry
    the ``agent_control_specification_version`` key that marks ACS manifests.
    """
    return (
        isinstance(data, dict)
        and "rules" in data
        and "agent_control_specification_version" not in data
    )


# ---------------------------------------------------------------------------
# ACS manifest linting
# ---------------------------------------------------------------------------


def _lint_acs_manifest(
    manifest_text: str,
    manifest_path: Path,
    result: LintResult,
) -> None:
    """Validate an ACS manifest using the ``agent_control_specification`` library."""
    try:
        from agent_control_specification import parse_manifest, validate_manifest
    except ImportError as exc:
        result.messages.append(
            LintMessage(
                "error",
                f"agent_control_specification is not installed: {exc}",
                str(manifest_path),
                1,
            )
        )
        return

    try:
        validate_manifest(manifest_text)
        manifest = parse_manifest(manifest_text)
    except Exception as exc:
        result.messages.append(
            LintMessage(
                "error",
                str(exc),
                str(manifest_path),
                1,
            )
        )
        return

    for policy_id, policy in (manifest.get("policies") or {}).items():
        references = [
            policy.get("bundle"),
            policy.get("policy_path"),
            policy.get("entities_path"),
            policy.get("schema_path"),
            *(policy.get("data_paths") or []),
        ]
        for reference in references:
            if (
                reference
                and "://" not in reference
                and not (manifest_path.parent / reference).exists()
            ):
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Policy {policy_id!r} references missing path {reference!r}",
                        str(manifest_path),
                        1,
                    )
                )

    if not manifest.get("intervention_points"):
        result.messages.append(
            LintMessage(
                "warning",
                "Manifest defines no intervention points",
                str(manifest_path),
                1,
            )
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def lint_file(path: str | Path) -> LintResult:
    """Validate one policy file.

    Governance YAML policy documents (files with a ``rules`` list but no
    ``agent_control_specification_version``) are linted for impossible
    conditions.  ACS manifests are validated via the
    ``agent_control_specification`` library.
    """
    import yaml

    manifest_path = Path(path)
    result = LintResult()

    if not manifest_path.is_file():
        result.messages.append(
            LintMessage(
                "error",
                f"File not found: {manifest_path}",
                str(manifest_path),
                1,
            )
        )
        return result

    if manifest_path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        result.messages.append(
            LintMessage(
                "error",
                "Policy file must be YAML or JSON",
                str(manifest_path),
                1,
            )
        )
        return result

    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        result.messages.append(
            LintMessage("error", f"Cannot read file: {exc}", str(manifest_path), 1)
        )
        return result

    try:
        data = yaml.safe_load(manifest_text)
    except yaml.YAMLError as exc:
        result.messages.append(
            LintMessage("error", f"Invalid YAML: {exc}", str(manifest_path), 1)
        )
        return result

    if _is_governance_policy(data):
        _lint_governance_conditions(data, str(manifest_path), result)
        return result

    _lint_acs_manifest(manifest_text, manifest_path, result)
    return result


def lint_path(path: str | Path) -> LintResult:
    """Lint one manifest or every manifest under a directory."""

    target = Path(path)
    if target.is_file():
        return lint_file(target)
    if not target.exists():
        return LintResult(
            [
                LintMessage(
                    "error",
                    f"Path does not exist: {target}",
                    str(target),
                    0,
                )
            ]
        )
    if not target.is_dir():
        return LintResult(
            [
                LintMessage(
                    "error",
                    f"Unsupported path: {target}",
                    str(target),
                    0,
                )
            ]
        )

    files = sorted(
        file
        for pattern in ("*.yaml", "*.yml", "*.json")
        for file in target.rglob(pattern)
    )
    if not files:
        return LintResult(
            [
                LintMessage(
                    "warning",
                    "No manifest files found",
                    str(target),
                    0,
                )
            ]
        )

    result = LintResult()
    for file in files:
        result.messages.extend(lint_file(file).messages)
    return result
