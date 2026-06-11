# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OPA-based test harness for scenario tests.

Loads a governance.yaml chain plus AGT stock Rego library, runs the
agt.manifest_resolution layer to produce an ACS manifest, builds the
intervention-point policy input shape per spec §7, and shells to
``opa eval`` to compute the verdict. Returns a normalized
``ScenarioResult``.

The harness is intentionally a thin wrapper. M3.S3 will replace the
OPA subprocess call with the Rust core dispatcher; the scenario tests
above this layer will not need to change.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from agt.manifest_resolution import resolve_manifest


@dataclass
class ScenarioResult:
    """Decision returned by the OPA evaluator after applying a resolved
    AGT manifest to a snapshot.

    Mirrors the verdict shape from
    ``policy-engine/spec/SPECIFICATION.md`` §13 and §14.
    """

    decision: str
    reason: Optional[str] = None
    message: Optional[str] = None
    transform: Optional[dict[str, Any]] = None
    evidence: Optional[dict[str, Any]] = None
    result_labels: list[str] | None = None
    raw: Optional[dict[str, Any]] = None

    @property
    def is_allow(self) -> bool:
        return self.decision == "allow"

    @property
    def is_deny(self) -> bool:
        return self.decision == "deny"

    @property
    def is_warn(self) -> bool:
        return self.decision == "warn"

    @property
    def is_escalate(self) -> bool:
        return self.decision == "escalate"

    @property
    def is_transform(self) -> bool:
        return self.decision == "transform"


def _find_stock_rego_root() -> Path:
    """Locate the AGT stock Rego library directory inside the repo."""
    here = Path(__file__).resolve()
    # Walk up to the repo root, then descend into policy-engine/policy/lib
    for parent in here.parents:
        candidate = parent / "policy-engine" / "policy" / "lib"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("could not locate policy-engine/policy/lib stock Rego root")


def _project_tool_from_manifest(manifest: dict[str, Any], tool_name: str) -> dict[str, Any]:
    """Project the named tool entry from the manifest catalog.

    Matches the engine's tool projection at tool intervention points.
    """
    return dict((manifest.get("tools") or {}).get(tool_name) or {"name": tool_name})


def _build_policy_input(
    *,
    intervention_point: str,
    policy_target: Any,
    policy_target_kind: str | None,
    snapshot: dict[str, Any],
    annotations: dict[str, Any] | None,
    tool: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the canonical policy input per SPECIFICATION.md §7."""
    return {
        "intervention_point": intervention_point,
        "policy_target": {
            "kind": policy_target_kind,
            "path": "$policy_target",
            "value": policy_target,
        },
        "snapshot": snapshot,
        "annotations": annotations or {},
        "tool": tool,
    }


def _resolve_path(snapshot: dict[str, Any], path: str) -> Any:
    """Resolve a simple ``$snap.x.y[0]`` path against the snapshot.

    Supports `$snap` / `$` roots and `.name` / `[n]` segments. Matches
    what the engine does for ``policy_target`` resolution.
    """
    if path.startswith("$snap."):
        rest = path[len("$snap.") :]
    elif path.startswith("$."):
        rest = path[len("$.") :]
    elif path == "$snap" or path == "$":
        return snapshot
    else:
        raise ValueError(f"unsupported policy_target path root: {path!r}")

    obj: Any = snapshot
    parts: list[str] = []
    cur = ""
    i = 0
    while i < len(rest):
        ch = rest[i]
        if ch == ".":
            if cur:
                parts.append(cur)
                cur = ""
            i += 1
            continue
        if ch == "[":
            if cur:
                parts.append(cur)
                cur = ""
            j = rest.index("]", i)
            parts.append(rest[i : j + 1])
            i = j + 1
            continue
        cur += ch
        i += 1
    if cur:
        parts.append(cur)

    for part in parts:
        if part.startswith("[") and part.endswith("]"):
            idx = int(part[1:-1])
            obj = obj[idx]
        else:
            obj = obj[part]
    return obj


def run_scenario(
    *,
    workspace_root: Path,
    governance_yaml: dict[str, dict[str, Any]],
    intervention_point: str,
    snapshot: dict[str, Any],
    annotations: dict[str, Any] | None = None,
) -> ScenarioResult:
    """End-to-end scenario evaluation.

    Args:
        workspace_root: Tempdir that will host the synthesized governance
            tree. Must be an existing directory the test owns.
        governance_yaml: Map of relative path under ``workspace_root`` to
            parsed YAML dict. Each path is written as a governance.yaml
            and the agt.manifest_resolution layer is run against them.
        intervention_point: Which hook to evaluate.
        snapshot: Full snapshot per AGT-SNAPSHOT-1.0 for that hook.
        annotations: Optional pre-computed annotations map. In production
            these come from annotator dispatchers; tests pass them
            directly.

    Returns:
        :class:`ScenarioResult` carrying the decoded verdict.

    Raises:
        FileNotFoundError: When the OPA binary is not on PATH.
        RuntimeError: When opa eval fails or produces no result.
    """
    if shutil.which("opa") is None:
        raise FileNotFoundError(
            "opa binary is required on PATH for scenario tests; install OPA 0.69+"
        )

    import yaml

    # 1. Write governance files
    for rel_path, doc in governance_yaml.items():
        target = workspace_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(doc), encoding="utf-8")

    # 2. Resolve via the M3.S1 layer (also copies stock Rego library into the bundle)
    bundle_dir = workspace_root / ".agt" / "resolved-bundle"
    manifest = resolve_manifest(workspace_root, workspace_root, bundle_dir=bundle_dir)
    bundle_policy_dir = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])

    # 3. Copy stock Rego library next to the generated agt_legacy.rego
    stock_root = _find_stock_rego_root()
    for rego in stock_root.glob("*.rego"):
        if rego.name.endswith("_test.rego"):
            continue
        dest = bundle_policy_dir / rego.name
        if not dest.exists():
            dest.write_text(rego.read_text(encoding="utf-8"), encoding="utf-8")

    # 4. Build policy input
    ip_config = manifest["intervention_points"].get(intervention_point)
    if ip_config is None:
        raise RuntimeError(
            f"manifest does not bind intervention point {intervention_point!r}"
        )
    policy_target_path = ip_config.get("policy_target", "$")
    policy_target_kind = ip_config.get("policy_target_kind")
    policy_target = _resolve_path(snapshot, policy_target_path)

    tool: dict[str, Any] | None = None
    if intervention_point in {"pre_tool_call", "post_tool_call"}:
        tool_name = _resolve_path(snapshot, ip_config["tool_name_from"])
        if not isinstance(tool_name, str):
            raise RuntimeError("tool_name_from did not resolve to a string")
        tool = _project_tool_from_manifest(manifest, tool_name)

    policy_input = _build_policy_input(
        intervention_point=intervention_point,
        policy_target=policy_target,
        policy_target_kind=policy_target_kind,
        snapshot=snapshot,
        annotations=annotations,
        tool=tool,
    )

    # 5. Run opa eval
    query = manifest["policies"]["agt_legacy_rules"]["query"]
    cmd = [
        "opa",
        "eval",
        "--format",
        "json",
        "--stdin-input",
        "--data",
        str(bundle_policy_dir),
        query,
    ]
    proc = subprocess.run(  # noqa: S603 — trusted OPA call in tests
        cmd,
        input=json.dumps(policy_input),
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed: {proc.stderr.strip()}")

    response = json.loads(proc.stdout)
    expressions = response.get("result", [{}])[0].get("expressions", [{}])
    value = expressions[0].get("value") if expressions else None
    if not isinstance(value, dict):
        raise RuntimeError(f"opa returned non-object verdict: {value!r}")

    return ScenarioResult(
        decision=str(value.get("decision", "allow")),
        reason=value.get("reason"),
        message=value.get("message"),
        transform=value.get("transform"),
        evidence=value.get("evidence"),
        result_labels=value.get("result_labels"),
        raw=value,
    )
