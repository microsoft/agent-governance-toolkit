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
  unsafe empty membership conditions: ``in []`` never matches, while
  ``not_in []`` matches every resolved field value.
"""

from __future__ import annotations

import ast
import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Condition operators supported by the in-repo governance evaluators
# ---------------------------------------------------------------------------

_MEMBERSHIP_OPERATORS: frozenset[str] = frozenset({"in", "not_in"})

_CONDITION_OPERATOR_MODULES = (
    "agent_control_plane.policy_engine",
    "agentmesh.governance.trust_policy",
    "agt.cli._migrate_resolution.build",
)
_CONDITION_OPERATOR_SOURCE_PATHS = (
    Path("agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/policy_engine.py"),
    Path("agent-governance-python/agent-mesh/src/agentmesh/governance/trust_policy.py"),
    Path("agent-governance-python/agt-policies/src/agt/cli/_migrate_resolution/build.py"),
)


def _operator_expression(node: ast.AST) -> bool:
    """Return whether an AST expression refers to a condition operator."""
    if isinstance(node, ast.Name):
        return node.id == "operator"
    return isinstance(node, ast.Attribute) and node.attr == "operator"


def _string_values(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
        return {
            value
            for item in node.elts
            for value in _string_values(item)
        }
    return set()


def _operators_from_source(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        # ``UnicodeDecodeError`` subclasses ``ValueError``, not ``OSError``, so a
        # source file that is not valid UTF-8 escapes the first two arms. This
        # derivation runs at module scope, so an uncaught error here does not
        # degrade one source -- it makes ``lint_policy`` itself unimportable.
        # Skip the undecodable source the same way an unreadable one is skipped;
        # a derivation that ends up empty is caught by the vocabulary guard test.
        return set()

    operators: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ConditionOperator":
            for member in node.body:
                if isinstance(member, (ast.Assign, ast.AnnAssign)) and member.value:
                    operators.update(_string_values(member.value))
        elif isinstance(node, ast.Compare) and _operator_expression(node.left):
            for comparator in node.comparators:
                operators.update(_string_values(comparator))
    return operators


def _repository_roots() -> list[Path]:
    """Return the checkout roots to resolve evaluator sources against.

    Climbing every parent up to ``/`` would let a directory tree outside the
    checkout satisfy one of the relative source paths, deriving the operator
    vocabulary -- a guard list -- from a file this repository does not own.
    Stop at the first ancestor that looks like this checkout instead.
    """
    roots: list[Path] = []
    for start in (Path(__file__).resolve(), Path.cwd().resolve()):
        for candidate in (start, *start.parents):
            roots.append(candidate)
            if (candidate / "agent-governance-python").is_dir():
                break
    return list(dict.fromkeys(roots))


def _condition_operator_sources() -> tuple[Path, ...]:
    roots = _repository_roots()
    sources = [
        root / relative_path
        for root in dict.fromkeys(roots)
        for relative_path in _CONDITION_OPERATOR_SOURCE_PATHS
    ]
    for module_name in _CONDITION_OPERATOR_MODULES:
        try:
            spec = importlib.util.find_spec(module_name)
        except (ImportError, ModuleNotFoundError, ValueError):
            spec = None
        if spec and spec.origin and spec.origin not in {"built-in", "frozen"}:
            sources.append(Path(spec.origin))
    return tuple(dict.fromkeys(source for source in sources if source.is_file()))


_KNOWN_CONDITION_OPERATORS: frozenset[str] = frozenset(
    operator
    for source in _condition_operator_sources()
    for operator in _operators_from_source(source)
)


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
    """Check a governance policy document for invalid or unsafe conditions.

    Currently detects:

    * An operator unsupported by every in-repo governance evaluator.
    * ``in`` with an empty ``value`` list, which never matches.
    * ``not_in`` with an empty ``value`` list, which matches every resolved
      field value and therefore imposes no restriction on the rule.

    The ``field`` typo case (e.g. ``toolname`` instead of ``tool_name``) is
    context-dependent and cannot be checked without a schema that enumerates
    every valid field for the target evaluator.  If you add a
    ``KNOWN_CONTEXT_FIELDS`` vocabulary to your project, a straightforward
    extension of this function can warn on unrecognised field names.
    """
    rules = data.get("rules")
    if not isinstance(rules, list):
        return

    if not _KNOWN_CONDITION_OPERATORS:
        result.messages.append(
            LintMessage(
                "warning",
                "Operator vocabulary could not be derived from any evaluator "
                "source; operator names in this document were not checked. "
                "Run the linter from a full checkout to enable that check.",
                filepath,
                1,
            )
        )

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        rule_name = rule.get("name", f"rule[{idx}]")
        action = str(rule.get("action", "configured")).lower()

        for cond in _conditions_from_rule(rule):
            operator = cond.get("operator", "")
            if not isinstance(operator, str):
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Rule '{rule_name}': unknown operator {operator!r}",
                        filepath,
                        1,
                    )
                )
                continue

            # An empty vocabulary means the evaluator sources could not be read
            # (an installed wheel, a partial checkout), not that every operator
            # in the document is unknown. Reporting one per condition would be a
            # verdict derived from no evidence, and the ``continue`` below it
            # would skip the empty-membership check for the whole document --
            # silently disabling the check this linter exists to run. Report the
            # broken derivation once, then keep checking what is still checkable.
            if _KNOWN_CONDITION_OPERATORS and operator not in _KNOWN_CONDITION_OPERATORS:
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Rule '{rule_name}': unknown operator {operator!r}",
                        filepath,
                        1,
                    )
                )
                continue

            if operator not in _MEMBERSHIP_OPERATORS:
                continue

            value = cond.get("value")
            if isinstance(value, list) and len(value) == 0:
                field_hint = cond.get("field", "")
                field_clause = f" on field '{field_hint}'" if field_hint else ""
                if operator == "in":
                    diagnosis = "condition can never match, so this rule can never apply"
                else:
                    consequence = {
                        "allow": "allows everything",
                        "deny": "denies everything",
                    }.get(action, f"always applies the '{action}' action")
                    diagnosis = (
                        "condition always matches, so this rule always fires and "
                        f"{consequence}"
                    )
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Rule '{rule_name}': operator '{operator}'{field_clause} "
                        f"has an empty value list — {diagnosis}",
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
        result.messages.append(
            LintMessage(
                "error",
                "Governance policy is missing agent_control_specification_version",
                str(manifest_path),
                1,
            )
        )
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
