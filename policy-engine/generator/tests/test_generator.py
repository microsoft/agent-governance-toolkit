from __future__ import annotations

import io
import json
import shutil
import subprocess
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from acs_generator import FakeLanguageModel, GenerationEngine, GenerationError, validate_acs_artifacts
from acs_generator.llm import OpenAICompatibleLanguageModel
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
                "conditions": [
                    'object.get(input.tool, "id", object.get(input.tool, "name", "")) == "wire_transfer"',
                    "input.policy_target.value.amount >= 10000",
                ],
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


def test_openai_compatible_model_detects_azure_by_hostname_only() -> None:
    assert OpenAICompatibleLanguageModel(
        api_base="https://customer.openai.azure.com",
        api_key="unused",
    ).is_azure
    assert not OpenAICompatibleLanguageModel(
        api_base="https://api.example.test/.azure.com",
        api_key="unused",
    ).is_azure
    assert not OpenAICompatibleLanguageModel(
        api_base="https://azure.com.example.test",
        api_key="unused",
    ).is_azure


def test_openai_compatible_model_api_version_forces_azure_mode() -> None:
    assert OpenAICompatibleLanguageModel(
        api_base="https://api.example.test",
        api_key="unused",
        api_version="2024-12-01-preview",
    ).is_azure


def test_generator_package_includes_wire_schemas() -> None:
    schema_names = {
        "effect.schema.json",
        "policy-input.schema.json",
        "request.schema.json",
        "result.schema.json",
        "snapshot.schema.json",
        "verdict.schema.json",
    }

    schema_dir = resources.files("acs_generator.schema.wire")
    packaged_names = {path.name for path in schema_dir.iterdir() if path.name.endswith(".schema.json")}
    assert schema_names <= packaged_names
    for schema_name in schema_names:
        with schema_dir.joinpath(schema_name).open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_packaged_schemas_match_canonical_spec_schemas() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    pairs = [
        ("spec/schema/approval.schema.json", "generator/acs_generator/schema/approval.schema.json"),
        ("spec/schema/manifest.schema.json", "generator/acs_generator/schema/manifest.schema.json"),
    ]
    pairs.extend(
        (
            f"spec/schema/wire/{name}",
            f"generator/acs_generator/schema/wire/{name}",
        )
        for name in (
            "effect.schema.json",
            "policy-input.schema.json",
            "request.schema.json",
            "result.schema.json",
            "snapshot.schema.json",
            "verdict.schema.json",
        )
    )

    for canonical, packaged in pairs:
        assert (repo_root / packaged).read_bytes() == (repo_root / canonical).read_bytes(), packaged


def test_manifest_schema_matches_extends_composition_contract() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    with (repo_root / "spec/schema/manifest.schema.json").open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    validator = Draft202012Validator(schema)
    extends_only = {
        "agent_control_specification_version": "0.3.1-beta",
        "metadata": {"name": "composition root"},
        "extends": ["layers/base.yaml", {"url": "https://example.test/remote.yaml", "sha256": "a" * 64}],
    }
    validator.validate(extends_only)

    for invalid in (
        {"agent_control_specification_version": "0.3.1-beta"},
        {"agent_control_specification_version": "0.3.1-beta", "extends": ["http://example.test/base.yaml"]},
        {
            "agent_control_specification_version": "0.3.1-beta",
            "extends": [{"url": "http://example.test/base.yaml"}],
        },
        {
            "agent_control_specification_version": "0.3.1-beta",
            "extends": [
                {
                    "url": "https://example.test/base.yaml",
                    "integrity": "sha256-abc",
                    "sha256": "a" * 64,
                }
            ],
        },
    ):
        with pytest.raises(Exception):
            validator.validate(invalid)

    annotation_only_overlay = {
        "agent_control_specification_version": "0.3.1-beta",
        "extends": ["base/manifest.yaml"],
        "annotators": {"overlay": {"type": "classifier"}},
        "intervention_points": {
            "input": {
                "annotations": {
                    "overlay": {"from": "$policy_target.text"},
                },
            },
        },
    }
    validator.validate(annotation_only_overlay)

    annotation_alias_overlay = {
        "agent_control_specification_version": "0.3.1-beta",
        "extends": ["base/manifest.yaml"],
        "annotators": {"overlay": {"type": "classifier"}},
        "intervention_points": {
            "input": {
                "annotations": {
                    "review_signal": {
                        "from": "$policy_target.text",
                        "annotator": "overlay",
                    },
                },
            },
        },
    }
    with pytest.raises(Exception):
        validator.validate(annotation_alias_overlay)


def test_empty_annotation_from_defaults_to_policy_target() -> None:
    plan = valid_plan()
    plan["annotations"] = [{"point": "input", "annotator": "prompt_classifier", "from": ""}]
    out = out_dir("empty-from")

    result = GenerationEngine(FakeLanguageModel([plan])).generate(
        prompt="Protect a bank agent.", out_dir=out, tool_inventory=tool_inventory(), strict=True
    )

    assert result.manifest["intervention_points"]["input"]["annotations"]["prompt_classifier"]["from"] == "$policy_target"


def test_tools_are_derived_from_tool_identity_conditions() -> None:
    plan = valid_plan()
    # The escalate rule gates on input.tool.id == "wire_transfer"; no inventory is passed.
    out = out_dir("derived-tools")
    plan["tools"] = []
    plan["rules"][1]["conditions"] = ['input.tool.id == "wire_transfer"', "input.policy_target.value.amount >= 10000"]

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


def test_string_validation_api_returns_json_ready_success() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: validation-api
policies:
  guard:
    type: rego
    query: data.acs.guard.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: guard
      query: data.acs.guard.verdict
""",
        """
package acs.guard

import rego.v1

default verdict := {"decision": "allow"}
""",
    )

    assert report.valid
    assert report.to_dict() == {"valid": True, "diagnostics": []}


def test_string_validation_api_aggregates_manifest_and_rego_diagnostics() -> None:
    report = validate_acs_artifacts(
        """
metadata: []
""",
        {
            "../../unsafe-name.rego": """
package acs.guard

allow if { value := }
""",
        },
    )

    assert not report.valid
    codes = {diagnostic.code for diagnostic in report.diagnostics}
    assert "manifest_schema_error" in codes
    assert "rego_parse_error" in codes
    rego_diagnostic = next(
        diagnostic for diagnostic in report.diagnostics if diagnostic.code == "rego_parse_error"
    )
    assert rego_diagnostic.source == "../../unsafe-name.rego"
    assert rego_diagnostic.line == 4
    assert rego_diagnostic.column is not None
    assert rego_diagnostic.snippet == "allow if { value := }"
    assert "/tmp/" not in str(report.to_dict())


def test_string_validation_api_parses_rego_modules_independently() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: validation-api
""",
        {
            "one.rego": """
package acs.guard

import rego.v1

helper(value) := value
""",
            "two.rego": """
package acs.guard

import rego.v1

helper(left, right) := left
""",
        },
    )

    assert report.valid


def test_string_validation_api_rejects_duplicate_manifest_keys() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.0"
agent_control_specification_version: "0.3.1-beta"
metadata: {}
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"
    assert "duplicate key" in report.diagnostics[0].message


def test_string_validation_api_uses_yaml_12_boolean_keys() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
policies:
  on:
    type: rego
    query: data.on.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: on
""",
        "package on",
    )

    assert report.valid


def test_string_validation_api_does_not_coerce_mixed_case_boolean() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: tRuE
metadata: {}
""",
        {},
    )

    assert report.valid


def test_string_validation_api_rejects_yaml_merge_keys() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  base: &base
    name: base
  child:
    <<: *base
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"
    assert "merge keys are not supported" in report.diagnostics[0].message


@pytest.mark.parametrize("value", ["010", "1_000", "1:2:3"])
def test_string_validation_api_does_not_apply_yaml_11_numbers(value: str) -> None:
    report = validate_acs_artifacts(
        f"""
agent_control_specification_version: "0.3.1-beta"
metadata: {{}}
approval:
  timeout_seconds: {value}
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].path == "$.approval.timeout_seconds"


@pytest.mark.parametrize("value", ["0b1010", "0o12", "0xA"])
def test_string_validation_api_accepts_yaml_12_prefixed_integer(value: str) -> None:
    report = validate_acs_artifacts(
        f"""
agent_control_specification_version: "0.3.1-beta"
metadata: {{}}
approval:
  timeout_seconds: {value}
""",
        {},
    )

    assert report.valid


@pytest.mark.parametrize(
    "value",
    ["!!bool nope", "!!int 010", "!!null nope", "!!timestamp not-a-date"],
)
def test_string_validation_api_rejects_invalid_explicit_tags(value: str) -> None:
    report = validate_acs_artifacts(
        f"""
agent_control_specification_version: "0.3.1-beta"
metadata:
  value: {value}
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"


def test_string_validation_api_rechecks_aliases_at_deeper_paths() -> None:
    lines = [
        'agent_control_specification_version: "0.3.1-beta"',
        "metadata:",
        "  leaf: &leaf",
        "    child: ok",
        "  deep:",
    ]
    indent = "    "
    for index in range(62):
        lines.append(f"{indent}n{index}:")
        indent += "  "
    lines.append(f"{indent}*leaf")

    report = validate_acs_artifacts("\n".join(lines) + "\n", {})

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_depth_exceeded"


def test_string_validation_api_bounds_alias_expansion() -> None:
    labels = ", ".join(f'"label-{index}"' for index in range(1500))
    tools = "\n".join(
        f"  tool-{index}: {{security_labels: *labels}}" for index in range(1500)
    )
    manifest = f"""
agent_control_specification_version: "0.3.1-beta"
metadata:
  labels: &labels [{labels}]
tools:
{tools}
"""

    report = validate_acs_artifacts(manifest, {})

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_expansion_exceeded"


def test_string_validation_api_bounds_alias_expanded_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("acs_generator.validation.MAX_MANIFEST_EXPANDED_BYTES", 256)
    payload = "x" * 100

    report = validate_acs_artifacts(
        f"""
agent_control_specification_version: "0.3.1-beta"
metadata: &shared
  payload: "{payload}"
extends: [*shared, *shared, *shared]
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_expansion_exceeded"


def test_string_validation_api_bounds_yaml_source_nodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("acs_generator.validation.MAX_MANIFEST_SOURCE_NODES", 8)

    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  values: [one, two, three, four, five]
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"
    assert "manifest source exceeds" in report.diagnostics[0].message


def test_string_validation_api_returns_diagnostics_for_hostile_text() -> None:
    nested = '{"metadata":{"value":' + "[" * 600 + "]" * 600 + "}}"
    manifest_report = validate_acs_artifacts(nested, {})
    rego_report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        json.loads('"package invalid\\n\\ud800"'),
    )

    assert not manifest_report.valid
    assert manifest_report.diagnostics[0].code == "manifest_parse_error"
    assert not rego_report.valid
    assert rego_report.diagnostics[0].code == "rego_encoding_error"


def test_string_validation_api_rejects_non_json_yaml_values() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  payload: !!binary SGVsbG8=
""",
        {},
    )
    assert not report.valid
    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"


def test_string_validation_api_bounds_diagnostics_and_snippets() -> None:
    manifest_report = validate_acs_artifacts(
        json.dumps(
            {
                "agent_control_specification_version": "0.3.1-beta",
                "extends": [0] * 200,
            }
        ),
        {},
    )
    rego_report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        "package invalid\nallow if { " + "x" * 10_000 + " := }\n",
    )

    assert len(manifest_report.diagnostics) == 101
    assert manifest_report.diagnostics[-1].code == "validation_diagnostics_truncated"
    assert len(rego_report.diagnostics[0].snippet or "") <= 4099


def test_string_validation_api_requires_modules_for_rego_manifest() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
policies:
  guard:
    type: rego
    query: data.guard.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: guard
""",
        {},
    )

    assert not report.valid
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["rego_missing"]


def test_string_validation_api_rejects_non_opa_executable() -> None:
    report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        "package invalid",
        opa_path="/bin/true",
    )

    assert not report.valid
    assert report.diagnostics[0].code == "opa_invalid_executable"


def test_string_validation_api_bounds_mapping_iteration() -> None:
    class EndlessMapping(dict):
        def items(self):
            while True:
                yield "policy.rego", "package valid"

    report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        EndlessMapping(),
    )

    assert not report.valid
    assert report.diagnostics[0].code == "rego_module_limit_exceeded"


def test_string_validation_api_counts_empty_rego_toward_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("acs_generator.validation.MAX_REGO_BYTES", 8)

    report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        " " * 9,
    )

    assert not report.valid
    assert report.diagnostics[0].code == "rego_size_exceeded"


@pytest.mark.parametrize(
    ("manifest", "rego", "expected_code"),
    [
        (123, {}, "manifest_input_invalid"),
        ("[]", {}, "manifest_root_invalid"),
        (
            'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
            {1: "package invalid"},
            "rego_source_invalid",
        ),
        (
            'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
            {"invalid.rego": 1},
            "rego_input_invalid",
        ),
        (
            'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
            "",
            "rego_empty",
        ),
    ],
)
def test_string_validation_api_rejects_malformed_inputs(
    manifest: object,
    rego: object,
    expected_code: str,
) -> None:
    report = validate_acs_artifacts(manifest, rego)  # type: ignore[arg-type]

    assert not report.valid
    assert expected_code in {diagnostic.code for diagnostic in report.diagnostics}


def test_string_validation_api_bounds_opa_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, "Version: 0.70.0\n", "")
        raise subprocess.TimeoutExpired(args, timeout=1)

    monkeypatch.setattr("acs_generator.validation.subprocess.run", run)

    report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        "package invalid",
        opa_path="opa",
    )

    assert not report.valid
    assert report.diagnostics[0].code == "opa_timeout"


def test_string_validation_api_handles_unstructured_opa_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, "Version: 0.70.0\n", "")
        return subprocess.CompletedProcess(args, 1, None, "not json")

    monkeypatch.setattr("acs_generator.validation.subprocess.run", run)

    report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        "package invalid",
        opa_path="opa",
    )

    assert not report.valid
    assert report.diagnostics[0].code == "opa_validation_error"
    assert report.diagnostics[0].message == "not json"


def test_string_validation_api_handles_staging_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "acs_generator.validation.tempfile.TemporaryDirectory",
        lambda **kwargs: (_ for _ in ()).throw(OSError("read only")),
    )

    report = validate_acs_artifacts(
        'agent_control_specification_version: "0.3.1-beta"\nmetadata: {}\n',
        "package invalid",
    )

    assert not report.valid
    assert report.diagnostics[0].code == "rego_staging_error"


def test_string_validation_api_legacy_schema_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins

    real_import = builtins.__import__

    def without_referencing(
        name: str,
        globals: object = None,
        locals: object = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "referencing":
            raise ImportError("blocked for fallback test")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", without_referencing)

    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata: {}
approval:
  timeout_seconds: 0
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].path == "$.approval.timeout_seconds"


def test_string_validation_api_resolves_packaged_approval_schema() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: validation-api
approval:
  timeout_seconds: 0
""",
        {},
    )

    assert not report.valid
    diagnostic = next(
        diagnostic
        for diagnostic in report.diagnostics
        if diagnostic.path == "$.approval.timeout_seconds"
    )
    assert diagnostic.code == "manifest_schema_error"
    assert "minimum of 1" in diagnostic.message


def test_string_validation_api_requires_opa_for_rego(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("acs_generator.validation.shutil.which", lambda name: None)

    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: validation-api
""",
        "package acs.guard",
    )

    assert not report.valid
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["opa_unavailable"]


def test_package_imports_without_credentials_or_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACS_GENERATOR_API_KEY", raising=False)
    import acs_generator

    assert acs_generator.FakeLanguageModel


def test_init_cli_generates_guided_artifact_shape(capsys: pytest.CaptureFixture[str]) -> None:
    from acs_generator.cli import main

    out = out_dir("init-shape")
    out.rmdir()

    rc = main([
        "init",
        "--non-interactive",
        "--name",
        "Payments Agent",
        "--points",
        "input,pre_tool_call,output",
        "--tool",
        "wire_transfer:banking,payments",
        "--deny-keyword",
        "password",
        "--escalate-tool",
        "wire_transfer",
        "--redact-output-pattern",
        "acct_[0-9]+",
        "--sample-test",
        "--strict",
        "--out",
        str(out),
    ])

    assert rc == 0
    assert "Manifest preview" in capsys.readouterr().out
    manifest = (out / "manifest.yaml").read_text(encoding="utf-8")
    rego = (out / "policy" / "payments_agent.rego").read_text(encoding="utf-8")
    assert "pre_tool_call" in manifest
    assert "wire_transfer" in manifest
    assert "payments" in manifest
    assert 'object.get(input.tool, "id", object.get(input.tool, "name", "")) == "wire_transfer"' in rego
    assert (out / "snapshots" / "pre_tool_call.json").exists()
    assert (out / "test_policy.py").exists()

    policy_input = {
        "intervention_point": "pre_tool_call",
        "policy_target": {"path": "$.tool_call.args", "kind": "tool_args", "value": {}},
        "snapshot": {},
        "annotations": {},
        "tool": {"type": "Tool", "id": "wire_transfer"},
    }
    input_path = out / "id-only-tool-policy-input.json"
    input_path.write_text(json.dumps(policy_input), encoding="utf-8")
    completed = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "json",
            "--data",
            str(out / "policy"),
            "--input",
            str(input_path),
            "data.agent_control_specification.payments_agent.pre_tool_call_verdict",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    verdict = json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]
    assert verdict["decision"] == "escalate"


def test_init_cli_help_documents_output_layout_and_strict_opa() -> None:
    from acs_generator.init_flow import _parser

    help_text = _parser().format_help()

    assert "policy/<slug>.rego" in help_text
    assert "test_policy.py" in help_text
    assert "agent-control-specification-opa" in help_text
    assert "--strict requires an opa binary on PATH" in help_text


def test_init_cli_preserves_regex_commas_in_repeatable_flags() -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-regex-comma")
    out.rmdir()

    rc = init_main(
        [
            "--non-interactive",
            "--quiet",
            "--name",
            "Regex Agent",
            "--points",
            "output",
            "--redact-output-pattern",
            "acct_[0-9]{6,}",
            "--out",
            str(out),
        ],
        stdin=io.StringIO(""),
    )

    assert rc == 0
    rego = (out / "policy" / "regex_agent.rego").read_text(encoding="utf-8")
    assert 'regex.match("acct_[0-9]{6,}", input.policy_target.value)' in rego
    # AGT D1.1: redaction is a transform that computes the replaced value in the
    # rule body; the pattern (with its regex comma intact) appears in regex.replace.
    assert 'regex.replace(input.policy_target.value, "acct_[0-9]{6,}", "[REDACTED]")' in rego
    assert '"effects"' not in rego


def test_init_cli_reads_answers_from_stdin(capsys: pytest.CaptureFixture[str]) -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-stdin")
    out.rmdir()
    answers = json.dumps({
        "name": "Support Bot",
        "points": ["input", "output"],
        "deny_keywords": ["token"],
        "redact_output_patterns": ["tok_[a-z]+"],
    })

    rc = init_main(["--non-interactive", "--answers-file", "-", "--out", str(out), "--strict"], stdin=io.StringIO(answers))

    assert rc == 0
    assert "support_bot" in (out / "manifest.yaml").read_text(encoding="utf-8")
    assert "tok_[a-z]+" in (out / "policy" / "support_bot.rego").read_text(encoding="utf-8")
    assert "Designed ACS artifacts" in capsys.readouterr().out


def test_init_cli_dry_run_does_not_create_requested_output() -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-dry-run")
    out.rmdir()

    rc = init_main(
        [
            "--non-interactive",
            "--name",
            "Dry Run",
            "--points",
            "input,pre_tool_call",
            "--tool",
            "send_email:internal",
            "--deny-keyword",
            "secret",
            "--dry-run",
            "--strict",
            "--out",
            str(out),
        ],
        stdin=io.StringIO(""),
    )

    assert rc == 0
    assert not out.exists()
    assert not Path(".acs_generator_dry_run_validation").exists()


def test_init_cli_rejects_invalid_intervention_point() -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-invalid")
    out.rmdir()

    rc = init_main(["--non-interactive", "--name", "Bad", "--points", "input,bogus", "--out", str(out)], stdin=io.StringIO(""))

    assert rc == 1
    assert not out.exists()


def test_init_cli_rejects_empty_name_and_points() -> None:
    from acs_generator.init_flow import main as init_main

    name_out = out_dir("init-empty-name")
    name_out.rmdir()
    name_rc = init_main(["--non-interactive", "--name", "", "--out", str(name_out)], stdin=io.StringIO(""))

    points_out = out_dir("init-empty-points")
    points_out.rmdir()
    points_rc = init_main(
        ["--non-interactive", "--name", "Bad", "--points", "", "--out", str(points_out)],
        stdin=io.StringIO(""),
    )

    assert name_rc == 1
    assert points_rc == 1
    assert not name_out.exists()
    assert not points_out.exists()


def test_init_cli_rejects_repeated_singleton_flags() -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-repeated-singleton")
    out.rmdir()

    rc = init_main(
        [
            "--non-interactive",
            "--name",
            "First",
            "--name",
            "Second",
            "--out",
            str(out),
        ],
        stdin=io.StringIO(""),
    )

    assert rc == 1
    assert not out.exists()


def test_init_cli_rejects_unsupported_answer_keys() -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-unsupported-answers")
    out.rmdir()
    answers = json.dumps({
        "name": "Support Bot",
        "points": ["input"],
        "annotators": [{"name": "judge", "type": "endpoint"}],
        "extends": ["base.yaml"],
    })

    rc = init_main(["--non-interactive", "--answers-file", "-", "--out", str(out)], stdin=io.StringIO(answers))

    assert rc == 1
    assert not out.exists()


def test_init_cli_requires_empty_output_without_force() -> None:
    from acs_generator.init_flow import main as init_main

    out = out_dir("init-output")
    (out / "existing.txt").write_text("keep", encoding="utf-8")

    rc = init_main(["--non-interactive", "--name", "Existing", "--out", str(out)], stdin=io.StringIO(""))

    assert rc == 1
    assert (out / "existing.txt").read_text(encoding="utf-8") == "keep"
