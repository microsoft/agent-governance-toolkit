#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Check that example rego manifests bind every adapter-evaluated intervention point.

Usage:
    python scripts/check_example_intervention_points.py

The engine denies an intervention point that an adapter evaluates but the
manifest does not bind (``runtime_error:intervention_point_unknown``), so an
agent loading such a manifest fails on its first tool call. Sixteen of the
nineteen in-repo adapters evaluate ``pre_tool_call`` and twelve evaluate
``output`` (every adapter evaluates ``input``). Requiring ``output`` as well as
``input`` and ``pre_tool_call`` is deliberately stricter than the bare minimum:
a shipped example that omits a point is broken for the adapters that evaluate it,
and the extra points deny-by-default rather than fail, so requiring them is the
safe direction (issue #3540).

Scope: manifests under ``examples/policies/`` and ``examples/policy-templates/``
that declare ``intervention_points`` and use at least one ``type: rego`` policy.
Manifests with no intervention points (non-agent-control configs) and
custom-adapter manifests (which define their own point semantics) are exempt.
Framework example manifests elsewhere in the tree (for example ``deerflow`` and
``maf-integration``) are out of scope here; they need per-adapter decisions about
``output`` and are checked separately.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_DIRS = [
    REPO_ROOT / "examples" / "policies",
    REPO_ROOT / "examples" / "policy-templates",
]
REQUIRED_POINTS = ("input", "output", "pre_tool_call")


def _uses_rego(manifest: dict) -> bool:
    policies = manifest.get("policies") or {}
    if not isinstance(policies, dict):
        return False
    return any((p or {}).get("type") == "rego" for p in policies.values())


def check_file(path: Path) -> list[str]:
    try:
        manifest = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return [f"{path}: YAML parse error: {exc}"]
    if not isinstance(manifest, dict):
        return []
    points = manifest.get("intervention_points") or {}
    if not points:
        return []  # not an agent-control manifest
    if not _uses_rego(manifest):
        return []  # custom-adapter manifests define their own point semantics
    missing = [p for p in REQUIRED_POINTS if p not in points]
    if missing:
        try:
            rel = path.relative_to(REPO_ROOT)
        except ValueError:
            rel = path
        return [
            f"{rel}: rego manifest binds {sorted(points)} but omits "
            f"adapter-evaluated point(s) {missing}; the engine denies unbound "
            f"points, breaking the manifest on the first matching interception"
        ]
    return []


def main() -> int:
    manifests = sorted(
        p
        for d in EXAMPLE_DIRS
        if d.is_dir()
        for p in d.rglob("*.yaml")
    )
    errors: list[str] = []
    for path in manifests:
        errors.extend(check_file(path))
    print(f"Checked {len(manifests)} example manifests for intervention-point coverage.")
    for err in errors:
        print(f"ERROR: {err}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
