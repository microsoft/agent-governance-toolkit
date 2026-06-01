from __future__ import annotations

import json
from importlib import resources
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .vocabulary import (
    DECISIONS,
    DEPRECATED_INPUT_REFS,
    EFFECT_TYPES,
    INTERVENTION_POINT_BY_NAME,
    POLICY_INPUT_ANNOTATIONS_KEY,
    POLICY_INPUT_POINT_KEY,
)

OPA_TIMEOUT_SECONDS = 10
SCHEMA_PACKAGE = "acs_generator.schema"
SCHEMA_NAME = "manifest.schema.json"
VALIDATION_DIR_NAME = ".acs_generator_validation"


@dataclass
class ValidationResult:
    warnings: list[str] = field(default_factory=list)


class ValidationError(RuntimeError):
    pass


class _NoopAnnotator:
    def dispatch(self, annotator_name: str, annotator_config: dict[str, Any], preliminary_policy_input: dict[str, Any]) -> dict[str, Any]:
        return {}


class _NoopPolicy:
    def evaluate(self, invocation: dict[str, Any]) -> dict[str, Any]:
        return {"decision": "allow"}


def validate_artifacts(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
    out_dir: Path,
    *,
    strict: bool = False,
) -> ValidationResult:
    warnings: list[str] = []
    _validate_schema(manifest)
    _validate_core(manifest_yaml)
    _reject_deprecated_refs(rego)
    opa = shutil.which("opa")
    if opa is None:
        message = "opa not found on PATH; skipped Rego syntax and eval validation"
        if strict:
            raise ValidationError(message)
        warnings.append(message)
        return ValidationResult(warnings)
    _validate_opa(opa, rego, slug, manifest, out_dir)
    return ValidationResult(warnings)


def _validate_schema(manifest: dict[str, Any]) -> None:
    with resources.files(SCHEMA_PACKAGE).joinpath(SCHEMA_NAME).open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    try:
        jsonschema.validate(manifest, schema)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ValidationError(f"manifest schema validation failed at {path}: {exc.message}") from exc


def _validate_core(manifest_yaml: str) -> None:
    try:
        from agent_control_specification import NativeRuntimeClient

        NativeRuntimeClient(manifest_yaml, _NoopAnnotator(), _NoopPolicy())
    except Exception as exc:  # noqa: BLE001 - preserve core diagnostics verbatim.
        raise ValidationError(f"core semantic validation failed: {exc}") from exc


def _validate_opa(opa: str, rego: str, slug: str, manifest: dict[str, Any], out_dir: Path) -> None:
    scratch = out_dir / VALIDATION_DIR_NAME
    if scratch.exists():
        shutil.rmtree(scratch)
    policy_dir = scratch / "policy"
    input_dir = scratch / "input"
    policy_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    rego_path = policy_dir / f"{slug}.rego"
    rego_path.write_text(rego, encoding="utf-8")
    try:
        _run_opa([opa, "parse", str(rego_path)])
        for point_name, config in manifest["intervention_points"].items():
            policy_input = _synthetic_input(point_name, config)
            input_path = input_dir / f"{point_name}.json"
            input_path.write_text(json.dumps(policy_input), encoding="utf-8")
            query = config["policy"]["query"]
            completed = _run_opa([opa, "eval", "--format", "json", "-d", str(policy_dir), "-i", str(input_path), query])
            verdict = _extract_single_object(completed.stdout, query)
            _validate_verdict(verdict, query)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)


def _run_opa(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=OPA_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ValidationError(f"opa timed out running {' '.join(args[1:])}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise ValidationError(f"opa validation failed running {' '.join(args[1:])}: {detail}") from exc


def _reject_deprecated_refs(rego: str) -> None:
    for ref in DEPRECATED_INPUT_REFS:
        if ref in rego:
            raise ValidationError(
                f"generated Rego references deprecated policy input key '{ref}'; "
                f"use input.{POLICY_INPUT_POINT_KEY} and input.{POLICY_INPUT_ANNOTATIONS_KEY}"
            )


def _synthetic_input(point_name: str, config: dict[str, Any]) -> dict[str, Any]:
    tool = {"id": "", "name": ""} if point_name in {"pre_tool_call", "post_tool_call"} else None
    return {
        POLICY_INPUT_POINT_KEY: point_name,
        "snapshot": {},
        POLICY_INPUT_ANNOTATIONS_KEY: {},
        "policy_target": {
            "kind": config.get("policy_target_kind", ""),
            "path": config["policy_target"],
            "value": {},
        },
        "tool": tool,
    }


def _extract_single_object(stdout: str, query: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
        expressions = payload["result"][0]["expressions"]
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        raise ValidationError(f"opa eval for {query} returned no result") from exc
    if len(expressions) != 1 or not isinstance(expressions[0].get("value"), dict):
        raise ValidationError(f"opa eval for {query} must resolve to exactly one object")
    return expressions[0]["value"]


def _validate_verdict(verdict: dict[str, Any], query: str) -> None:
    decision = verdict.get("decision")
    if decision not in DECISIONS:
        raise ValidationError(f"opa eval for {query} returned unsupported decision: {decision}")
    for effect in verdict.get("effects", []):
        if not isinstance(effect, dict):
            raise ValidationError(f"opa eval for {query} returned non-object effect")
        if effect.get("type") not in EFFECT_TYPES:
            raise ValidationError(f"opa eval for {query} returned unsupported effect type: {effect.get('type')}")
        path = str(effect.get("path", ""))
        if not path.startswith("$policy_target"):
            raise ValidationError(f"opa eval for {query} returned effect path outside $policy_target: {path}")


def dump_manifest_yaml(manifest: dict[str, Any]) -> str:
    return yaml.safe_dump(manifest, sort_keys=False)
