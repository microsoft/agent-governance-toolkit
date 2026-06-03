#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Optional agentic proposer for CI workflow manifest updates.

This tool NEVER writes workflow YAML. It analyzes changed paths and proposes a
constrained JSON edit to the reviewed manifest ``.github/ci/workflows.toml``.
The deterministic ``generate_workflows.py`` script remains the only component
that renders YAML, and the ``--check`` CI job is the gate, so any proposal must
be reviewed by a maintainer and applied to the manifest before it affects CI.

Guardrails enforced on every proposal, whether produced by the deterministic
heuristic or by a model:

* output paths must live under ``.github/workflows`` and end in ``.yml``
* toolchains must be a subset of the known set
* every referenced action key must exist in the pinned ``actions.toml`` registry
* workflow permissions stay at ``contents: read`` (the proposer cannot widen them)
* the proposal carries no raw YAML or shell outside the approved step shape

A model, when configured, only refines the JSON proposal. Its output is passed
back through the same validation, then a human applies it. With no model
credentials the deterministic heuristic runs and the tool still works.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = Path(__file__).resolve().parent / "generate_workflows.py"

# Map a changed top level area to the workflow job it should be covered by.
AREA_COVERAGE = {
    "policy-engine": "policy-engine-ci",
}


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_workflows", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def _changed_paths(explicit: str | None) -> list[str]:
    if explicit:
        return [p.strip() for p in explicit.split(",") if p.strip()]
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return [line for line in out.stdout.splitlines() if line]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _covered_paths(manifest: dict) -> list[str]:
    paths: list[str] = []
    for workflow in manifest.get("workflow", []):
        paths.extend(workflow.get("pull_request_paths", []))
    return paths


def _matches(path: str, pattern: str) -> bool:
    prefix = pattern.split("**", 1)[0].rstrip("/")
    return path == pattern or (bool(prefix) and path.startswith(prefix))


def detect_gaps(changed: list[str], manifest: dict) -> list[str]:
    """Return changed areas that no workflow path filter currently covers."""
    covered = _covered_paths(manifest)
    gaps: set[str] = set()
    for path in changed:
        if any(_matches(path, pattern) for pattern in covered):
            continue
        top = path.split("/", 1)[0]
        if top in AREA_COVERAGE:
            gaps.add(top)
    return sorted(gaps)


def build_proposal(gaps: list[str]) -> dict:
    suggestions = []
    for area in gaps:
        suggestions.append(
            {
                "kind": "extend_pull_request_paths",
                "workflow": AREA_COVERAGE[area],
                "add_path": f"{area}/**",
                "rationale": f"Changes under {area}/ are not covered by any workflow path filter.",
            }
        )
    return {"version": 1, "suggestions": suggestions}


def validate_proposal(proposal: dict, actions: dict[str, str], manifest: dict) -> list[str]:
    """Return a list of guardrail violations. Empty list means the proposal is safe."""
    errors: list[str] = []
    known_workflows = {w.get("id") for w in manifest.get("workflow", [])}
    for suggestion in proposal.get("suggestions", []):
        kind = suggestion.get("kind")
        if kind not in {"extend_pull_request_paths", "add_job", "add_workflow"}:
            errors.append(f"unsupported suggestion kind: {kind}")
            continue
        if kind in {"extend_pull_request_paths", "add_job"}:
            if suggestion.get("workflow") not in known_workflows:
                errors.append(f"references unknown workflow: {suggestion.get('workflow')}")
        if kind in {"add_job", "add_workflow"}:
            for toolchain in suggestion.get("toolchains", []):
                if toolchain not in gen.KNOWN_TOOLCHAINS:
                    errors.append(f"unknown toolchain: {toolchain}")
            for action_key in suggestion.get("actions", []):
                if action_key not in actions:
                    errors.append(f"references unpinned/unknown action key: {action_key}")
        if kind == "add_workflow":
            output = suggestion.get("output", "")
            if not output.startswith(".github/workflows/") or not output.endswith(".yml"):
                errors.append(f"output must be a .github/workflows/*.yml path: {output}")
        if suggestion.get("permissions") not in (None, {"contents": "read"}):
            errors.append("proposal may not widen permissions beyond contents: read")
        if "yaml" in suggestion or "run" in suggestion:
            errors.append("proposal must not carry raw YAML or shell; describe intent only")
    return errors


def refine_with_model(proposal: dict) -> dict:
    """Optional model refinement. Fenced: the model only returns JSON, which the
    caller re validates. With no credentials configured this is a no op so the
    deterministic proposal is used unchanged."""
    # A real implementation would call an OpenAI compatible endpoint with a
    # constrained, JSON only prompt (see the design doc). It is intentionally a
    # no op here so the tool never depends on model availability in CI.
    return proposal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed", help="comma separated changed paths (default: git diff vs origin/main)")
    parser.add_argument("--use-model", action="store_true", help="refine the proposal with a model if configured")
    parser.add_argument("--json", action="store_true", help="print the raw JSON proposal only")
    args = parser.parse_args(argv)

    actions = gen._load_actions(gen.ACTIONS_PATH)
    manifest = gen._load_toml(gen.MANIFEST_PATH)

    changed = _changed_paths(args.changed)
    gaps = detect_gaps(changed, manifest)
    proposal = build_proposal(gaps)
    if args.use_model:
        proposal = refine_with_model(proposal)

    violations = validate_proposal(proposal, actions, manifest)
    if violations:
        print("error: proposal failed guardrails:", file=sys.stderr)
        for item in violations:
            print(f"  - {item}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(proposal, indent=2))
        return 0

    if not proposal["suggestions"]:
        print("No coverage gaps detected. CI manifest needs no changes.")
        return 0

    print("Proposed CI manifest updates (review and apply to .github/ci/workflows.toml):\n")
    for suggestion in proposal["suggestions"]:
        print(f"- workflow '{suggestion['workflow']}': add pull_request path '{suggestion['add_path']}'")
        print(f"  rationale: {suggestion['rationale']}")
    print("\nThis tool does not edit YAML. After applying the manifest edit, run:")
    print("  python3 scripts/ci/generate_workflows.py --write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
