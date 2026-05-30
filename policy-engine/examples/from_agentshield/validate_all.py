#!/usr/bin/env python3
"""Static "writable as ACS" gate for every ported AgentShield example.

For each port directory (one containing a manifest.yaml) under this tree it:
  1. JSON-schema validates the manifest against spec/schema/manifest.schema.json.
  2. Loads it through the real ACS core (AgentControl.from_path) — this resolves
     and parses the Rego bundle, proving the core accepts the artifacts.
  3. Runs `opa eval` for every intervention point's query against a synthetic
     input and asserts the result is a single, well-formed verdict object.
  4. If an app/run_demo.py exists, runs it and requires "demo verification: PASS".

Usage:
  python validate_all.py            # validate + run demos
  python validate_all.py --no-demos # static validation only
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import yaml

from agent_control_specification import AgentControl
from acs_generator.vocabulary import DECISIONS, EFFECT_TYPES

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
SCHEMA = json.loads((REPO_ROOT / "spec" / "schema" / "manifest.schema.json").read_text(encoding="utf-8"))


def synthetic_input(point: str, cfg: dict) -> dict:
    tool = {"name": ""} if point in {"pre_tool_call", "post_tool_call"} else None
    return {
        "intervention_point": point,
        "snapshot": {},
        "annotations": {},
        "policy_target": {
            "kind": cfg.get("policy_target_kind", ""),
            "path": cfg["policy_target"],
            "value": {},
        },
        "tool": tool,
    }


def opa_eval(bundle: Path, point: str, cfg: dict) -> dict:
    scratch = bundle.parent / ".validate_input.json"
    scratch.write_text(json.dumps(synthetic_input(point, cfg)), encoding="utf-8")
    query = cfg["policy"]["query"]
    try:
        proc = subprocess.run(
            ["opa", "eval", "--format", "json", "-d", str(bundle), "-i", str(scratch), query],
            capture_output=True,
            text=True,
            timeout=20,
        )
    finally:
        scratch.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed for {point}: {proc.stderr.strip() or proc.stdout.strip()}")
    payload = json.loads(proc.stdout)
    expressions = payload["result"][0]["expressions"]
    value = expressions[0]["value"]
    if not isinstance(value, dict):
        raise RuntimeError(f"opa eval for {point} did not resolve to a verdict object")
    return value


def validate_verdict(point: str, verdict: dict) -> None:
    if verdict.get("decision") not in DECISIONS:
        raise RuntimeError(f"{point}: unsupported decision {verdict.get('decision')!r}")
    for effect in verdict.get("effects", []):
        if not isinstance(effect, dict) or effect.get("type") not in EFFECT_TYPES:
            raise RuntimeError(f"{point}: unsupported effect {effect!r}")
        path = str(effect.get("path", ""))
        if path != "$policy_target" and not path.startswith("$policy_target."):
            raise RuntimeError(f"{point}: effect path outside $policy_target: {effect.get('path')!r}")


class _NoopAnnotator:
    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        return {}


def validate_port(manifest_path: Path) -> None:
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    jsonschema.validate(manifest, SCHEMA)
    AgentControl.from_path(str(manifest_path), annotator_dispatcher=_NoopAnnotator())  # core load + bundle parse
    bundle = manifest_path.parent / "policy"
    for point, cfg in manifest["intervention_points"].items():
        validate_verdict(point, opa_eval(bundle, point, cfg))


def run_demo(demo_path: Path) -> None:
    proc = subprocess.run([sys.executable, str(demo_path)], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or "demo verification: PASS" not in proc.stdout:
        raise RuntimeError(f"demo failed:\n{proc.stdout}\n{proc.stderr}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-demos", action="store_true", help="skip running app/run_demo.py")
    parser.add_argument("--only", default=None, help="only validate ports whose path contains this substring")
    args = parser.parse_args()

    manifests = sorted(p for p in HERE.rglob("manifest.yaml") if ".validate" not in str(p))
    if args.only:
        manifests = [p for p in manifests if args.only in str(p.parent.relative_to(HERE))]
    if not manifests:
        print("no ports found")
        return 0

    failures: list[str] = []
    for manifest_path in manifests:
        rel = manifest_path.parent.relative_to(HERE)
        try:
            validate_port(manifest_path)
            demo = manifest_path.parent / "app" / "run_demo.py"
            if demo.exists() and not args.no_demos:
                run_demo(demo)
                print(f"OK   {rel}  (validated + demo PASS)")
            else:
                print(f"OK   {rel}  (validated)")
        except Exception as exc:  # noqa: BLE001 - surface the diagnostic verbatim
            print(f"FAIL {rel}\n     {exc}")
            failures.append(str(rel))

    print()
    if failures:
        print(f"{len(failures)}/{len(manifests)} ports FAILED: {failures}")
        return 1
    print(f"all {len(manifests)} ports OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
