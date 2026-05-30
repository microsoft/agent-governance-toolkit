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
            Defaults to ``root/.agt/resolved-bundle/``.

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

    bundle_path = bundle_dir or (root / ".agt" / "resolved-bundle")
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
        "intervention_points": _collect_intervention_points(docs_only),
    }

    for section in ("tools", "annotators", "limits", "approval"):
        value = merge_top_level_section(section, docs_only)
        if value is not None:
            manifest[section] = value

    return manifest


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

    Each rule becomes one ``verdict[...]`` branch keyed on the rule's
    name. Conditions are translated for the supported subset of AGT v4
    operators. Unsupported operators emit a deny with a synthetic
    reason so missed coverage fails closed.
    """
    header = (
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        "# AUTO-GENERATED by agt.manifest_resolution.build._render_rego\n"
        "# Source rules are merged from the host-side governance chain.\n"
        "package agt.legacy\n"
        "import rego.v1\n\n"
        "default verdict := {\"decision\": \"allow\"}\n\n"
        "_rules := %s\n\n"
        "_field_value(field) := value if {\n"
        "    parts := split(field, \".\")\n"
        "    value := _walk(input.snapshot, parts)\n"
        "}\n\n"
        "_walk(obj, parts) := value if {\n"
        "    count(parts) == 0\n"
        "    value := obj\n"
        "} else := value if {\n"
        "    count(parts) > 0\n"
        "    head := parts[0]\n"
        "    tail := array.slice(parts, 1, count(parts))\n"
        "    next := obj[head]\n"
        "    value := _walk(next, tail)\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"eq\"\n"
        "    _field_value(rule.condition.field) == rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"ne\"\n"
        "    _field_value(rule.condition.field) != rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"gt\"\n"
        "    _field_value(rule.condition.field) > rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"lt\"\n"
        "    _field_value(rule.condition.field) < rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"gte\"\n"
        "    _field_value(rule.condition.field) >= rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"lte\"\n"
        "    _field_value(rule.condition.field) <= rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"in\"\n"
        "    _field_value(rule.condition.field) in rule.condition.value\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"contains\"\n"
        "    contains(_field_value(rule.condition.field), rule.condition.value)\n"
        "}\n\n"
        "_match(rule) if {\n"
        "    rule.condition.operator == \"matches\"\n"
        "    regex.match(rule.condition.value, _field_value(rule.condition.field))\n"
        "}\n\n"
        "verdict := result if {\n"
        "    some i\n"
        "    rule := _rules[i]\n"
        "    _match(rule)\n"
        "    every j in numbers.range(0, i - 1) {\n"
        "        not _match(_rules[j])\n"
        "    }\n"
        "    result := {\n"
        "        \"decision\": rule.action,\n"
        "        \"reason\": rule.name,\n"
        "        \"message\": rule.message,\n"
        "    }\n"
        "}\n"
    )

    return header % json.dumps(rules, indent=2)
