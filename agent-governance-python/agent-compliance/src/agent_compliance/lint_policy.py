# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy linter for Agent Governance Toolkit.

Validates YAML policy files for common mistakes: missing required fields,
unknown operators/actions, conflicting rules, deprecated field names,
empty rule lists, and invalid priority values.
"""

from __future__ import annotations

import json
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
# AST-based line lookup
# ---------------------------------------------------------------------------


class _LineMap:
    """Resolve `(rule_index, key)` -> source line number from a yaml AST.

    The previous implementation called `_find_line(lines, needle)` and
    grep-walked the raw text. That worked for unambiguous needles but
    blew up on benign collisions: searching for the literal substring
    `"op:"` (deprecated key) inside a file that also contains an
    unrelated comment, value, or anchor name containing `op:` returned
    the wrong line. More broadly, value-based searches (e.g., locating
    the line for `operator: nope` by searching for `"nope"`) match the
    first textual occurrence rather than the structural one.

    pyyaml's `compose` produces a node tree with `start_mark.line` on
    every node, which is the correct source for line numbers. We walk
    the tree once at construction time and cache the key positions we
    care about. `pyyaml` is already a required dependency so no new
    library is introduced; the resulting line numbers are exact rather
    than best-effort.
    """

    def __init__(self, root_node: Any) -> None:
        # Top-level mapping: key -> 1-based line of the key token.
        self._top: dict[str, int] = {}
        # Per-rule: idx -> {key -> line}
        self._rule_keys: dict[int, dict[str, int]] = {}
        # Per-rule: idx -> rule_line (the `- name:` / dash line)
        self._rule_lines: dict[int, int] = {}
        # Per-rule, per-condition-branch ("condition" or "conditions"):
        # idx -> [{key -> line}, ...] indexed by condition position
        # (single-condition branches still occupy slot 0).
        self._rule_cond_keys: dict[int, dict[str, list[dict[str, int]]]] = {}
        if root_node is None:
            return
        self._index(root_node)

    @staticmethod
    def _line(node: Any) -> int:
        # pyyaml uses 0-based line numbers; the linter and human eyes
        # want 1-based.
        return node.start_mark.line + 1

    def _index(self, root: Any) -> None:
        import yaml

        if not isinstance(root, yaml.MappingNode):
            return

        for key_node, value_node in root.value:
            if not isinstance(key_node, yaml.ScalarNode):
                continue
            key = key_node.value
            self._top[key] = self._line(key_node)

            if key == "rules" and isinstance(value_node, yaml.SequenceNode):
                self._index_rules(value_node)

    def _index_rules(self, rules_node: Any) -> None:
        import yaml

        for idx, rule_node in enumerate(rules_node.value):
            self._rule_lines[idx] = self._line(rule_node)
            if not isinstance(rule_node, yaml.MappingNode):
                continue

            keys: dict[str, int] = {}
            cond_branches: dict[str, list[dict[str, int]]] = {
                "condition": [],
                "conditions": [],
            }

            for key_node, value_node in rule_node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    continue
                key = key_node.value
                keys[key] = self._line(key_node)

                if key == "condition" and isinstance(value_node, yaml.MappingNode):
                    cond_branches["condition"].append(
                        self._index_condition(value_node)
                    )
                elif key == "conditions" and isinstance(value_node, yaml.SequenceNode):
                    for cond_node in value_node.value:
                        if isinstance(cond_node, yaml.MappingNode):
                            cond_branches["conditions"].append(
                                self._index_condition(cond_node)
                            )

            self._rule_keys[idx] = keys
            self._rule_cond_keys[idx] = cond_branches

    def _index_condition(self, cond_node: Any) -> dict[str, int]:
        import yaml

        out: dict[str, int] = {}
        for key_node, _value_node in cond_node.value:
            if isinstance(key_node, yaml.ScalarNode):
                out[key_node.value] = self._line(key_node)
        return out

    # ── Public accessors ──────────────────────────────────────────

    def top_key_line(self, key: str) -> int:
        """Return the source line of a top-level key, or 1 if missing."""
        return self._top.get(key, 1)

    def rule_line(self, idx: int) -> int:
        """Return the dash/start line of the *idx*-th rule, or 1."""
        return self._rule_lines.get(idx, 1)

    def rule_key_line(self, idx: int, key: str) -> int:
        """Return the source line of a key inside the *idx*-th rule.

        Falls back to the rule's own line if the key is not in the AST
        (e.g., when the rule isn't a mapping). Never returns 0.
        """
        rule = self._rule_keys.get(idx, {})
        if key in rule:
            return rule[key]
        return self._rule_lines.get(idx, 1)

    def condition_key_line(
        self, idx: int, branch: str, cond_idx: int, key: str
    ) -> int:
        """Return the source line of a key inside a condition.

        *branch* is either ``"condition"`` or ``"conditions"``. *cond_idx*
        is the position within that branch (single-condition rules use
        slot 0). Falls back to the rule's own line on any lookup miss.
        """
        rule_branches = self._rule_cond_keys.get(idx, {})
        branch_list = rule_branches.get(branch, [])
        if 0 <= cond_idx < len(branch_list):
            cond_keys = branch_list[cond_idx]
            if key in cond_keys:
                return cond_keys[key]
        return self.rule_key_line(idx, branch)


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

    # ── YAML parsing (data + AST) ─────────────────────────────
    try:
        data = yaml.safe_load(raw)
        # compose() rebuilds the tree from scratch for line info; we
        # need both the Python data structure (for fast key lookups
        # and value-shape checks) and the AST (for source line
        # numbers). The cost is one extra parse pass — negligible for
        # policy-file scale.
        root_node = yaml.compose(raw)
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

    line_map = _LineMap(root_node)

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
            result.messages.append(
                LintMessage(
                    "warning",
                    f"Deprecated field '{old}'; use '{new}' instead",
                    str(path),
                    line_map.top_key_line(old),
                )
            )

    # ── Rules validation ──────────────────────────────────────
    rules = data.get("rules")
    if isinstance(rules, list) and len(rules) == 0:
        result.messages.append(
            LintMessage(
                "warning",
                "Rules list is empty",
                str(path),
                line_map.top_key_line("rules"),
            )
        )

    if isinstance(rules, list):
        _lint_rules(rules, line_map, str(path), result)

    return result


def _lint_rules(
    rules: list[Any],
    line_map: _LineMap,
    filepath: str,
    result: LintResult,
) -> None:
    """Validate individual rules and detect conflicts."""
    # Track every (field, operator, value) -> [(rule_name, action), ...]
    # so conflict detection sees every prior rule against the same key,
    # not just the first one. The previous implementation stored only
    # the first action per key and skipped seen[key] = action after a
    # conflict was reported, so a third rule against the same key was
    # silently swallowed.
    seen: dict[tuple[str, str, str], list[tuple[str, str]]] = {}

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            result.messages.append(
                LintMessage(
                    "error",
                    f"Rule {idx} is not a mapping",
                    filepath,
                    line_map.rule_line(idx),
                )
            )
            continue

        rule_name = rule.get("name", f"rule[{idx}]")
        rule_line = line_map.rule_line(idx)

        # ── Deprecated fields inside rules ────────────────────
        for old, new in DEPRECATED_FIELDS.items():
            if old in rule:
                result.messages.append(
                    LintMessage(
                        "warning",
                        f"Rule '{rule_name}': deprecated field '{old}'; "
                        f"use '{new}' instead",
                        filepath,
                        line_map.rule_key_line(idx, old),
                    )
                )

        # ── Action validation ─────────────────────────────────
        action = rule.get("action")
        if action is not None and action not in KNOWN_ACTIONS:
            result.messages.append(
                LintMessage(
                    "error",
                    f"Rule '{rule_name}': unknown action '{action}'",
                    filepath,
                    line_map.rule_key_line(idx, "action"),
                )
            )

        # ── Condition / conditions validation ─────────────────
        condition = rule.get("condition")
        conditions = rule.get("conditions", [])
        # Pair each condition dict with the branch + position it came
        # from so we can resolve the structural line for every key
        # rather than scanning the raw text.
        all_conditions: list[tuple[dict[str, Any], str, int]] = []
        if isinstance(condition, dict):
            all_conditions.append((condition, "condition", 0))
        if isinstance(conditions, list):
            cond_idx = 0
            for c in conditions:
                if isinstance(c, dict):
                    all_conditions.append((c, "conditions", cond_idx))
                    cond_idx += 1

        for cond, branch, cond_idx in all_conditions:
            operator = cond.get("operator")
            if operator is not None and operator not in KNOWN_OPERATORS:
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Rule '{rule_name}': unknown operator '{operator}'",
                        filepath,
                        line_map.condition_key_line(
                            idx, branch, cond_idx, "operator"
                        ),
                    )
                )

            for old, new in DEPRECATED_FIELDS.items():
                if old in cond:
                    result.messages.append(
                        LintMessage(
                            "warning",
                            f"Rule '{rule_name}': deprecated field '{old}' "
                            f"in condition; use '{new}' instead",
                            filepath,
                            line_map.condition_key_line(
                                idx, branch, cond_idx, old
                            ),
                        )
                    )

        # ── Priority validation ───────────────────────────────
        priority = rule.get("priority")
        if priority is not None and not isinstance(priority, int):
            result.messages.append(
                LintMessage(
                    "error",
                    f"Rule '{rule_name}': priority must be an integer, "
                    f"got {type(priority).__name__}",
                    filepath,
                    line_map.rule_key_line(idx, "priority"),
                )
            )

        # ── Conflict detection ────────────────────────────────
        if action in ("allow", "deny") and all_conditions:
            for cond, _branch, _cond_idx in all_conditions:
                # JSON-canonical form for the value key — collapses
                # equivalent dicts/lists with reordered members and
                # preserves int-vs-string distinctions that str()
                # would lose. Falls back to repr() for objects that
                # aren't JSON-serialisable (rare in YAML, but defended
                # against rather than crashing).
                try:
                    canonical_value = json.dumps(
                        cond.get("value"), sort_keys=True, default=str
                    )
                except (TypeError, ValueError):
                    canonical_value = repr(cond.get("value"))

                key = (
                    cond.get("field", ""),
                    cond.get("operator", ""),
                    canonical_value,
                )
                history = seen.setdefault(key, [])
                # Compare against EVERY prior rule that targets this
                # key so the third, fourth, ... rule each surface as
                # individual conflict warnings rather than being
                # silently swallowed.
                for prior_name, prior_action in history:
                    if prior_action != action:
                        result.messages.append(
                            LintMessage(
                                "warning",
                                f"Rule '{rule_name}': conflicts with rule "
                                f"'{prior_name}' — same condition has both "
                                f"'{prior_action}' and '{action}'",
                                filepath,
                                rule_line,
                            )
                        )
                history.append((rule_name, action))


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
