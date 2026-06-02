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
from pathlib import Path
import tempfile
from typing import Any, Optional

import yaml

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
    except yaml.YAMLError as exc:
        raise ResolutionError.invalid_governance(
            f"failed to parse {path}: {exc}"
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

    bundle_path = bundle_dir or Path(tempfile.mkdtemp(prefix="agt_resolved_bundle_"))
    rego_path = _materialize_rego_bundle(bundle_path, merged_rules)

    intervention_points = _collect_intervention_points(docs_only)
    if merged_rules and not _binds_legacy_rules(intervention_points):
        raise ResolutionError.invalid_governance(
            "governance rules must bind policy id 'agt_legacy_rules' at one or more intervention points"
        )

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
    bundle_root = bundle_root.resolve()
    policy_dir = bundle_root / "policy"
    policy_dir.mkdir(parents=True, exist_ok=True)

    body = _render_rego(rules)
    rego_file = policy_dir / "agt_legacy.rego"
    rego_file.write_text(body, encoding="utf-8")

    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    (policy_dir / "agt_legacy.rego.sha256").write_text(digest, encoding="utf-8")

    return policy_dir


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
    unsupported_drops: list[str] = []

    for idx, rule in enumerate(rules):
        cond = rule.get("condition") or {}
        field = str(cond.get("field", ""))
        operator = str(cond.get("operator", "")).lower()
        value = cond.get("value")
        name = str(rule.get("name", f"rule_{idx}"))
        action = str(rule.get("action", "allow")).lower()
        message = str(rule.get("message", ""))

        accessor = _rego_field_accessor(field)
        op_clause = _rego_op_clause(operator, accessor, value) if accessor is not None else None
        if op_clause is None:
            # Unsupported operators or invalid field paths MUST fail
            # closed. Render an always-matching deny rule so evaluation
            # never silently falls through to default-allow. The merge
            # layer should ideally catch this at validation, but this is
            # the last line of defense.
            invalid_detail = (
                f"invalid field {field!r}"
                if accessor is None
                else f"unsupported operator {operator!r}"
            )
            unsupported_drops.append(name)
            matchers.append(
                f"_match_{idx} if {{\n"
                f"    true\n"
                f"}}"
            )
            branches.append(
                f"verdict := {{\"decision\": \"deny\", "
                f"\"reason\": \"runtime_error:manifest_invalid\", "
                f"\"message\": {json.dumps(f'rule {name!r} has {invalid_detail}; fail-closed deny')}}} if {{\n"
                f"    _match_{idx}\n"
                + "".join(f"    not _match_{j}\n" for j in range(idx))
                + "}"
            )
            continue

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

    if unsupported_drops:
        import logging
        logging.getLogger(__name__).warning(
            "agt.manifest_resolution: %d invalid rule(s) now fail-closed: %s",
            len(unsupported_drops),
            unsupported_drops,
        )

    return header + "\n\n".join(matchers) + ("\n\n" if matchers else "") + "\n\n".join(branches) + "\n"


def _rego_field_accessor(field: str) -> str | None:
    """Build an inline Rego accessor for a dot-separated snapshot field.

    Args:
        field: dotted path such as ``tool_call.args.amount_usd`` or
            ``envelope.budgets.tool_call_count``.

    Returns:
        Rego source like ``input.snapshot.tool_call.args.amount_usd``.
        Each segment is checked with ``object.get`` so missing fields
        evaluate to undefined (matches §5.2 of the ACS spec on missing
        fields).
    """
    parts = [p for p in field.split(".") if p]
    if not parts:
        return "input.snapshot"
    # Use chained object.get with a sentinel undefined value so each
    # level fails closed when the field is absent.
    expr = "input.snapshot"
    for part in parts:
        # Validate the part is a simple identifier; reject anything
        # weird to avoid Rego injection from policy authors.
        if not part.replace("_", "").isalnum():
            return None
        expr = f"object.get({expr}, {json.dumps(part)}, null)"
    return expr


def _rego_op_clause(operator: str, accessor: str, value: Any) -> Optional[str]:
    """Render the body of a `_match[i]` rule for a given operator.

    Returns None for unsupported operators; the caller turns the rule into a fail-closed deny.
    """
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
            f"{indent}contains(_v, {literal})"
        )
    if operator == "startswith":
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}startswith(_v, {literal})"
        )
    if operator == "endswith":
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}endswith(_v, {literal})"
        )
    if operator in {"matches", "regex"}:
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}regex.match({literal}, _v)"
        )
    return None
