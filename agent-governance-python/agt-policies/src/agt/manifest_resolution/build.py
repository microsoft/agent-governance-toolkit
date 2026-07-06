# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end resolve_manifest, per AGT-RESOLUTION §2.

Glues discovery + scope filter + merge + Rego-bundle translation, and
returns a flat ACS manifest dict ready to pass to the engine.

The translation to Rego is intentionally minimal in this milestone:
the merged rule list is turned into a single Rego rule that scans for
the first matching rule (priority-sorted) and emits a verdict. M5
expands the translation to cover the full spec of AGT v4 conditions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Optional

import yaml

try:
    import re2 as _re2

    _RE2_OPTIONS = _re2.Options()
    # Do not let RE2's C++ layer echo the (user-supplied) pattern to stderr;
    # invalid patterns are surfaced as a redacted ResolutionError instead.
    _RE2_OPTIONS.log_errors = False
except Exception:  # pragma: no cover - platform without a google-re2 wheel
    _re2 = None
    _RE2_OPTIONS = None

from .discover import discover_policies
from .errors import ResolutionError
from .merge import merge_documents, merge_top_level_section
from .scope import filter_by_scope

logger = logging.getLogger(__name__)

ACS_VERSION = "0.3.0-alpha-agt"


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        raise ResolutionError.invalid_governance(
            f"failed to read/parse {path}: {exc}"
        ) from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ResolutionError.invalid_governance(
            f"governance file {path} must be a mapping at top level"
        )
    return data


def _apply_inheritance(documents: list[tuple[Path, dict[str, Any]]]) -> list[tuple[Path, dict[str, Any]]]:
    """Trim the chain at the first ``inherit: false`` document, per §2.2.

    Walks from most-specific (last) toward root.
    """
    for i in range(len(documents) - 1, -1, -1):
        if documents[i][1].get("inherit") is False:
            return documents[i:]
    return documents


def resolve_manifest(
    root: Path,
    action_path: Path,
    *,
    bundle_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Resolve a governance chain into a flat ACS manifest.

    Args:
        root: Workspace root that bounds discovery.
        action_path: Path the agent action originates from.
        bundle_dir: Where to materialize the generated Rego bundle.
            Defaults to a unique temporary directory outside ``root``.

    Returns:
        A dict-shaped ACS manifest with ``extends: []`` and a
        ``policies.agt_legacy_rules`` entry pointing at the generated
        Rego bundle.

    Raises:
        ResolutionError: When discovery, parsing, or merging fails.
    """
    chain_paths = discover_policies(action_path, root)

    if not chain_paths:
        raise ResolutionError.invalid_governance(
            f"no governance.yaml found from {action_path} up to {root}; "
            "AGT v5 requires at least one governance file in the chain"
        )

    raw_docs: list[tuple[Path, dict[str, Any]]] = [
        (p, _load_yaml(p)) for p in chain_paths
    ]

    raw_docs = _apply_inheritance(raw_docs)

    scoped_docs: list[tuple[Path, dict[str, Any]]] = []
    for path, doc in raw_docs:
        scope_pattern = doc.get("scope")
        if filter_by_scope(path, scope_pattern, action_path, root):
            scoped_docs.append((path, doc))

    docs_only = [doc for _, doc in scoped_docs]

    merged_rules = merge_documents(docs_only)

    intervention_points = _collect_intervention_points(docs_only)
    if merged_rules and not _binds_legacy_rules(intervention_points):
        raise ResolutionError.invalid_governance(
            "governance rules must bind policy id 'agt_legacy_rules' at one or more intervention points"
        )

    created_bundle = bundle_dir is None
    bundle_path: Path | None = None
    try:
        bundle_path = (
            Path(tempfile.mkdtemp(prefix="agt_resolved_bundle_"))
            if created_bundle
            else Path(bundle_dir)
        )
        rego_path = _materialize_rego_bundle(bundle_path, merged_rules)

        manifest: dict[str, Any] = {
            "agent_control_specification_version": ACS_VERSION,
            "metadata": {
                "name": "agt_resolved",
                "resolved_from": {
                    "root": str(root),
                    "action_path": str(action_path),
                    "chain": [str(p) for p in chain_paths],
                },
            },
            "extends": [],
            "policies": {
                "agt_legacy_rules": {
                    "type": "rego",
                    "bundle": str(rego_path),
                    "query": "data.agt.legacy.verdict",
                },
            },
            "intervention_points": intervention_points,
        }

        for section in ("tools", "annotators", "limits", "approval"):
            value = merge_top_level_section(section, docs_only)
            if value is not None:
                manifest[section] = value

        return manifest
    except Exception:
        if created_bundle and bundle_path is not None:
            shutil.rmtree(bundle_path, ignore_errors=True)
        raise


def _binds_legacy_rules(intervention_points: dict[str, Any]) -> bool:
    for config in intervention_points.values():
        if not isinstance(config, dict):
            continue
        policy = config.get("policy")
        if isinstance(policy, dict) and policy.get("id") == "agt_legacy_rules":
            return True
    return False


def _collect_intervention_points(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Last-writer-wins union of intervention_points across documents.

    AGT-RESOLUTION does not introduce custom merge logic for
    intervention point bindings; the most-specific document wins.
    Annotations within a binding ARE unioned per upstream ACS §2.2.
    """
    merged: dict[str, Any] = {}
    for doc in documents:
        for ip, config in (doc.get("intervention_points") or {}).items():
            if ip in merged and isinstance(merged[ip], dict) and isinstance(config, dict):
                base = dict(merged[ip])
                base_annotations = dict(base.get("annotations") or {})
                base_annotations.update(config.get("annotations") or {})
                base.update(config)
                if base_annotations:
                    base["annotations"] = base_annotations
                merged[ip] = base
            else:
                merged[ip] = config
    return merged


def _materialize_rego_bundle(bundle_root: Path, rules: list[dict[str, Any]]) -> Path:
    """Write a generated Rego file to disk and return the bundle path.

    The generated rule package is ``agt.legacy`` and exposes a single
    ``verdict`` rule that scans the priority-sorted rules in order and
    returns the first matching verdict shape. Per AGT-RESOLUTION §2.5
    the AGT host points the engine at this bundle, not at inline rego.
    """
    policy_dir = bundle_root / "policy"
    try:
        bundle_root = bundle_root.resolve()
        policy_dir = bundle_root / "policy"
        policy_dir.mkdir(parents=True, exist_ok=True)

        body = _render_rego(rules)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        rego_file = policy_dir / "agt_legacy.rego"
        sidecar_file = policy_dir / "agt_legacy.rego.sha256"
        _atomic_write_text(rego_file, body)
        _atomic_write_text(sidecar_file, digest)
    except OSError as exc:
        raise ResolutionError.invalid_governance(
            f"failed to materialize bundle in {policy_dir}: {exc}"
        ) from exc

    return policy_dir


def _atomic_write_text(path: Path, body: str) -> None:
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temp_path.write_text(body, encoding="utf-8")
        os.replace(temp_path, path)
    except OSError:
        if temp_path.exists():
            temp_path.unlink()
        raise


def _render_rego(rules: list[dict[str, Any]]) -> str:
    """Render a Rego module emitting an AGT verdict from rule conditions.

    Each rule becomes one ``verdict`` branch keyed on its index. Field
    paths are inlined per-rule to avoid Rego recursion limits.
    """
    header = (
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        "# AUTO-GENERATED by agt.manifest_resolution.build._render_rego\n"
        "# Source rules are merged from the host-side governance chain.\n"
        "package agt.legacy\n"
        "import rego.v1\n\n"
        "default verdict := {\"decision\": \"allow\"}\n\n"
    )

    branches: list[str] = []
    matchers: list[str] = []
    for idx, rule in enumerate(rules):
        cond = rule.get("condition") or {}
        field = str(cond.get("field", ""))
        operator = str(cond.get("operator", "")).lower()
        value = cond.get("value")
        name = str(rule.get("name", f"rule_{idx}"))
        action = str(rule.get("action", "allow")).lower()
        message = str(rule.get("message", ""))

        accessor = _rego_field_accessor(field)
        if accessor is None:
            raise ResolutionError.invalid_governance(
                f"rule {name!r} has invalid field {field!r}"
            )
        op_clause = _rego_op_clause(operator, accessor, value)
        if op_clause is None:
            raise ResolutionError.invalid_governance(
                f"rule {name!r} has unsupported operator {operator!r}"
            )

        matchers.append(
            f"_match_{idx} if {{\n"
            f"{op_clause}\n"
            f"}}"
        )
        previous_negations = "".join(
            f"    not _match_{j}\n" for j in range(idx)
        )
        verdict_dict = (
            "{"
            f"\"decision\": {json.dumps(action)}, "
            f"\"reason\": {json.dumps(name)}, "
            f"\"message\": {json.dumps(message)}"
            "}"
        )
        branches.append(
            f"verdict := {verdict_dict} if {{\n"
            f"    _match_{idx}\n"
            f"{previous_negations}"
            f"}}"
        )

    return header + "\n\n".join(matchers) + ("\n\n" if matchers else "") + "\n\n".join(branches) + "\n"


def _rego_field_accessor(field: str) -> str | None:
    """Build an inline Rego accessor for a dot-separated snapshot field.

    Args:
        field: dotted path such as ``tool_call.args.amount_usd`` or
            ``envelope.budgets.tool_call_count``.

    Returns:
        Rego source like ``object.get(input.snapshot, ["tool_call",
        "args", "amount_usd"], null)``. OPA's path-aware
        ``object.get`` returns ``null`` when any path segment is absent
        or has the wrong container type, which keeps missing fields as
        normal non-matches under ``--strict-builtin-errors``.
    """
    parts = [p for p in field.split(".") if p]
    if not parts:
        return "input.snapshot"
    for part in parts:
        # Validate the part is a simple identifier; reject anything
        # weird to avoid Rego injection from policy authors.
        if not part.replace("_", "").isalnum():
            return None
    return f"object.get(input.snapshot, {json.dumps(parts)}, null)"


def _is_json_literal(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    if value is None or isinstance(value, (str, int, bool)):
        return True
    if isinstance(value, list):
        return all(_is_json_literal(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_literal(item)
            for key, item in value.items()
        )
    return False


def _is_escaped(pattern: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and pattern[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _has_unsupported_re2_group(pattern: str, marker: str) -> bool:
    in_class = False
    for index, char in enumerate(pattern):
        if char == "[" and not in_class and not _is_escaped(pattern, index):
            in_class = True
            continue
        if char == "]" and in_class and not _is_escaped(pattern, index):
            in_class = False
            continue
        if not in_class and char == "(" and not _is_escaped(pattern, index):
            if pattern.startswith(marker, index):
                return True
    return False


def _has_unsupported_re2_escape(pattern: str, marker: str) -> bool:
    index = 0
    while index < len(pattern):
        if pattern[index] != "\\":
            index += 1
            continue

        run_start = index
        while index < len(pattern) and pattern[index] == "\\":
            index += 1
        if (index - run_start) % 2 == 1 and pattern.startswith(marker, index):
            return True
    return False


def _has_possessive_quantifier(pattern: str) -> bool:
    in_class = False
    for index, char in enumerate(pattern[:-1]):
        if char == "[" and not in_class and not _is_escaped(pattern, index):
            in_class = True
            continue
        if char == "]" and in_class and not _is_escaped(pattern, index):
            in_class = False
            continue
        if in_class or _is_escaped(pattern, index):
            continue
        if char in {"*", "+", "?", "}"} and pattern[index + 1] == "+":
            return True
    return False


def _validate_re2_regex(pattern: str) -> None:
    """Reject any pattern Go RE2 (used by OPA) would not accept.

    Prefers the real RE2 engine (``google-re2``) so the accept/reject set
    matches OPA exactly, eliminating both fail-open false negatives (Python
    ``re``-valid but RE2-invalid patterns rendering into Rego that evaluates
    undefined -> default allow) and over-deny false positives (RE2-valid octal
    or Unicode-property patterns that Python ``re`` rejects). Falls back to a
    conservative heuristic when the native engine is unavailable.
    """
    if _re2 is not None:
        try:
            _re2.compile(pattern, _RE2_OPTIONS)
        except _re2.error as exc:
            raise ResolutionError.invalid_governance(
                "regex pattern is not a valid RE2 pattern"
            ) from exc
        return
    _validate_re2_regex_fallback(pattern)


def _validate_re2_regex_fallback(pattern: str) -> None:
    """Conservative RE2 validation for hosts without a ``google-re2`` wheel.

    Rejects the RE2-unsupported constructs that Python ``re`` accepts so the
    fail-open direction stays closed; the ``--strict-builtin-errors`` flag on
    ``opa eval`` is the eval-time backstop for anything this misses.
    """
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ResolutionError.invalid_governance(
            "regex pattern is invalid"
        ) from exc

    for marker, label in (
        ("(?=", "lookahead"),
        ("(?!", "lookahead"),
        ("(?<=", "lookbehind"),
        ("(?<!", "lookbehind"),
        ("(?>", "atomic group"),
        ("(?(", "conditional group"),
        ("(?P=", "named backreference"),
    ):
        if _has_unsupported_re2_group(pattern, marker):
            raise ResolutionError.invalid_governance(
                f"regex pattern uses unsupported RE2 construct {label}"
            )

    for digit in "123456789":
        if _has_unsupported_re2_escape(pattern, digit):
            raise ResolutionError.invalid_governance(
                "regex pattern uses unsupported RE2 construct backreference"
            )

    for marker, label in (("k<", "named backreference"), ("Z", r"\Z anchor")):
        if _has_unsupported_re2_escape(pattern, marker):
            raise ResolutionError.invalid_governance(
                f"regex pattern uses unsupported RE2 construct {label}"
            )

    if _has_possessive_quantifier(pattern):
        raise ResolutionError.invalid_governance(
            "regex pattern uses unsupported RE2 construct possessive quantifier"
        )


def _rego_op_clause(operator: str, accessor: str, value: Any) -> Optional[str]:
    """Render the body of a `_match[i]` rule for a given operator.

    Returns None for unsupported operators; the caller rejects the manifest.
    """
    if not _is_json_literal(value):
        raise ResolutionError.invalid_governance(
            "condition value is not a finite JSON primitive"
        )
    literal = json.dumps(value)
    indent = "    "
    if operator == "eq":
        return f"{indent}{accessor} == {literal}"
    if operator == "ne":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v != {literal}"
    if operator == "gt":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v > {literal}"
    if operator == "lt":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v < {literal}"
    if operator == "gte":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v >= {literal}"
    if operator == "lte":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v <= {literal}"
    if operator == "in":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v in {literal}"
    if operator == "not_in":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}not _v in {literal}"
    if operator == "exists":
        return f"{indent}{accessor} != null"
    if operator == "contains":
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}contains(_v, {literal})"
        )
    if operator == "startswith":
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}startswith(_v, {literal})"
        )
    if operator == "endswith":
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}endswith(_v, {literal})"
        )
    if operator in {"matches", "regex"}:
        if not isinstance(value, str):
            raise ResolutionError.invalid_governance(
                "regex condition value must be a string"
            )
        _validate_re2_regex(value)
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}regex.match({literal}, _v)"
        )
    return None
