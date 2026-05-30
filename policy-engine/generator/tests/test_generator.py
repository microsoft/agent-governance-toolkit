from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from acs_generator import FakeLanguageModel, GenerationEngine, GenerationError
from acs_generator.validation import validate_artifacts

BASE_OUT = Path("generator/.test-output")


def valid_plan() -> dict:
    return {
        "name": "bank agent guardrails",
        "guarded_points": ["input", "pre_tool_call", "output"],
        "annotators": [
            {"name": "prompt_classifier", "type": "classifier", "labels": ["finance_intent", "sensitive_data"]},
            {"name": "output_classifier", "type": "classifier", "labels": ["account_identifier"]},
        ],
        "annotations": [
            {"point": "input", "annotator": "prompt_classifier", "from": "$.input.text"},
            {"point": "output", "annotator": "output_classifier", "from": "$policy_target.text"},
        ],
        "tools": ["wire_transfer"],
        "rules": [
            {
                "point": "input",
                "decision": "deny",
                "reason": "high_risk_input",
                "message": "The request is too risky.",
                "conditions": ["input.annotations.prompt_classifier.risk_score >= 0.95"],
            },
            {
                "point": "pre_tool_call",
                "decision": "escalate",
                "reason": "large_wire_transfer",
                "message": "Large wire transfers require review.",
                "conditions": ['input.tool.name == "wire_transfer"', "input.policy_target.value.amount >= 10000"],
            },
            {
                "point": "output",
                "decision": "warn",
                "reason": "redact_account_identifier",
                "message": "Account identifier redacted.",
                "conditions": ["input.annotations.output_classifier.contains_account_identifier == true"],
                "effects": [{"type": "replace", "path": "$policy_target.text", "value": "[REDACTED]"}],
            },
        ],
    }


def tool_inventory() -> dict:
    return {
        "wire_transfer": {
            "type": "Tool",
            "id": "wire_transfer",
            "clearance": ["banking", "payments"],
            "security_labels": ["payment_instruction"],
        }
    }


def out_dir(name: str) -> Path:
    path = BASE_OUT / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def teardown_module() -> None:
    if BASE_OUT.exists():
        shutil.rmtree(BASE_OUT)


def test_golden_happy_path_generates_valid_artifacts() -> None:
    out = out_dir("golden")
    result = GenerationEngine(FakeLanguageModel([valid_plan()])).generate(
        prompt="Protect a bank agent from risky transfers and account identifiers.",
        out_dir=out,
        tool_inventory=tool_inventory(),
        strict=True,
    )

    assert (out / "manifest.yaml").exists()
    assert (out / "policy" / f"{result.slug}.rego").exists()
    assert result.manifest["intervention_points"]["pre_tool_call"]["tool_name_from"] == "$.tool_call.name"
    # Generated Rego must read the core's real policy-input keys, never the pre-rename ones.
    assert "input.intervention_point" in result.rego
    assert "input.stage" not in result.rego
    assert "input.evidence" not in result.rego


def test_empty_annotation_from_defaults_to_policy_target() -> None:
    plan = valid_plan()
    plan["annotations"] = [{"point": "input", "annotator": "prompt_classifier", "from": ""}]
    out = out_dir("empty-from")

    result = GenerationEngine(FakeLanguageModel([plan])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True
    )

    assert result.manifest["intervention_points"]["input"]["annotations"]["prompt_classifier"]["from"] == "$policy_target"


def test_tools_are_derived_from_tool_name_conditions() -> None:
    plan = valid_plan()
    # The escalate rule gates on input.tool.name == "wire_transfer"; no inventory is passed.
    out = out_dir("derived-tools")

    result = GenerationEngine(FakeLanguageModel([plan])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory={}, strict=True
    )

    assert result.manifest["tools"]["wire_transfer"] == {"type": "Tool", "id": "wire_transfer"}


def test_unconditional_blocking_rule_is_rejected_and_repaired() -> None:
    invalid = valid_plan()
    invalid["rules"] = [{"point": "input", "decision": "deny", "reason": "deny", "message": "", "conditions": []}]
    out = out_dir("unconditional-rule")

    result = GenerationEngine(FakeLanguageModel([invalid, valid_plan()])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True
    )

    # The repaired plan keeps a real condition on the input deny rule rather than firing unconditionally.
    assert "input.annotations.prompt_classifier" in result.rego


def test_retry_recovers_from_schema_invalid_plan() -> None:
    invalid = {**valid_plan(), "guarded_points": []}
    out = out_dir("schema-retry")

    result = GenerationEngine(FakeLanguageModel([invalid, valid_plan()])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True
    )

    assert result.manifest["intervention_points"]


def test_retry_recovers_from_invalid_rego() -> None:
    invalid = valid_plan()
    invalid["rules"] = [{**invalid["rules"][0], "conditions": ["input.policy_target.value =="]}]
    out = out_dir("rego-retry")

    result = GenerationEngine(FakeLanguageModel([invalid, valid_plan()])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True
    )

    assert "pre_tool_call_verdict" in result.rego


def test_undefined_annotator_surfaces_core_error() -> None:
    plan = {**valid_plan(), "annotations": [{"point": "input", "annotator": "ghost", "from": "$.input.text"}]}
    out = out_dir("semantic-error")

    with pytest.raises(GenerationError, match="unknown annotator 'ghost'"):
        GenerationEngine(FakeLanguageModel([plan])).generate(
            prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True, write=False
        )


def test_opa_missing_warns_and_strict_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    out = out_dir("opa-missing")
    result = GenerationEngine(FakeLanguageModel([valid_plan()])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True, write=False
    )
    monkeypatch.setattr("acs_generator.validation.shutil.which", lambda name: None)

    warning_result = validate_artifacts(
        result.manifest, result.manifest_yaml, result.rego, result.slug, out, strict=False
    )
    assert "opa not found" in warning_result.warnings[0]
    with pytest.raises(Exception, match="opa not found"):
        validate_artifacts(result.manifest, result.manifest_yaml, result.rego, result.slug, out, strict=True)


def test_package_imports_without_credentials_or_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACS_GENERATOR_API_KEY", raising=False)
    import acs_generator

    assert acs_generator.FakeLanguageModel
