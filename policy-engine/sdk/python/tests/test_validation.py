# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_control_specification.validation import validate_acs_artifacts

MANIFEST_HEADER = """agent_control_specification_version: "0.3.1-beta"
"""
MINIMAL_POLICY = """policies:
  minimal:
    type: custom
    adapter: test
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: minimal
"""
MINIMAL_MANIFEST = MANIFEST_HEADER + "metadata: {}\n" + MINIMAL_POLICY


def test_artifact_validation_matches_shared_parity_corpus() -> None:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "tests"
        / "parity"
        / "artifact-validation-cases.json"
    )
    corpus = json.loads(fixture.read_text(encoding="utf-8"))

    for case in corpus["cases"]:
        result = validate_acs_artifacts(case["manifest"], case["rego"])
        assert result.valid is case["valid"], case["name"]
        assert [diagnostic.code for diagnostic in result.diagnostics] == case["codes"], case["name"]


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
        MINIMAL_MANIFEST,
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
agent_control_specification_version: "0.3.0-alpha"
agent_control_specification_version: "0.3.1-beta"
metadata: {}
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"
    assert "duplicate manifest mapping key" in report.diagnostics[0].message


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
        MINIMAL_MANIFEST.replace("metadata: {}", "metadata:\n  value: tRuE"),
        {},
    )

    assert report.valid


def test_string_validation_api_uses_runtime_merge_key_semantics() -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST.replace(
            "metadata: {}",
            """metadata:
  base: &base
    name: base
  child:
    <<: *base""",
        ),
        {},
    )

    assert report.valid


def test_string_validation_api_rejects_non_string_mapping_keys() -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST.replace("metadata: {}", "metadata:\n  1: value"),
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_parse_error"


@pytest.mark.parametrize("value", ["010", "1_000", "1:2:3"])
def test_string_validation_api_does_not_apply_yaml_11_numbers(value: str) -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST
        + f"""approval:
  timeout_seconds: {value}
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].path == "/approval/timeout_seconds"


@pytest.mark.parametrize("value", ["0b1010", "0o12", "0xA"])
def test_string_validation_api_accepts_runtime_prefixed_integer(value: str) -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST
        + f"""approval:
  timeout_seconds: {value}
""",
        {},
    )

    assert report.valid


def test_string_validation_api_rechecks_aliases_at_deeper_paths() -> None:
    lines = [
        MANIFEST_HEADER.rstrip(),
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
    lines.append(MINIMAL_POLICY)

    report = validate_acs_artifacts("\n".join(lines) + "\n", {})

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_resource_limit"


def test_string_validation_api_bounds_alias_expansion() -> None:
    labels = ", ".join(f'"label-{index}"' for index in range(1500))
    tools = "\n".join(
        f"  tool-{index}: {{security_labels: *labels}}" for index in range(1500)
    )
    manifest = (
        MANIFEST_HEADER
        + f"""metadata:
  labels: &labels [{labels}]
tools:
{tools}
"""
        + MINIMAL_POLICY
    )

    report = validate_acs_artifacts(manifest, {})

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_resource_limit"


def test_string_validation_api_returns_diagnostics_for_hostile_text() -> None:
    nested = '{"metadata":{"value":' + "[" * 600 + "]" * 600 + "}}"
    manifest_report = validate_acs_artifacts(nested, {})
    rego_report = validate_acs_artifacts(
        MINIMAL_MANIFEST,
        json.loads('"package invalid\\n\\ud800"'),
    )

    assert not manifest_report.valid
    assert manifest_report.diagnostics[0].code in {
        "manifest_parse_error",
        "manifest_resource_limit",
    }
    assert not rego_report.valid
    assert rego_report.diagnostics[0].code == "rego_encoding_error"


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
        MINIMAL_MANIFEST,
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
        MINIMAL_MANIFEST,
        "package invalid",
        opa_path="/bin/true",
    )

    assert not report.valid
    assert report.diagnostics[0].code == "opa_invalid_executable"


def test_string_validation_api_rejects_invalid_opa_path() -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST,
        "package invalid",
        opa_path="\0",
    )

    assert not report.valid
    assert report.diagnostics[0].code == "opa_execution_error"


def test_string_validation_api_bounds_module_dictionary() -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST,
        {f"policy-{index}.rego": "package valid" for index in range(65)},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "rego_module_limit_exceeded"


def test_string_validation_api_rejects_custom_dictionary() -> None:
    class CustomDictionary(dict):
        pass

    report = validate_acs_artifacts(
        MINIMAL_MANIFEST,
        CustomDictionary(),
    )

    assert not report.valid
    assert report.diagnostics[0].code == "rego_input_invalid"


def test_string_validation_api_counts_empty_rego_toward_size_limit() -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST,
        " " * 1_048_577,
    )

    assert not report.valid
    assert report.diagnostics[0].code == "rego_size_exceeded"


@pytest.mark.parametrize(
    ("manifest", "rego", "expected_code"),
    [
        (123, {}, "manifest_input_invalid"),
        ("[]", {}, "manifest_root_invalid"),
        (
            MINIMAL_MANIFEST,
            {1: "package invalid"},
            "rego_input_invalid",
        ),
        (
            MINIMAL_MANIFEST,
            {"invalid.rego": 1},
            "rego_input_invalid",
        ),
        (
            MINIMAL_MANIFEST,
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


def test_string_validation_api_resolves_embedded_approval_schema() -> None:
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
        if diagnostic.path == "/approval/timeout_seconds"
    )
    assert diagnostic.code == "manifest_schema_error"
    assert "minimum of 1" in diagnostic.message


def test_string_validation_api_accepts_partial_extends_manifest() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: "0.3.1-beta"
extends:
  - base.yaml
""",
        {},
    )

    assert report.valid


def test_string_validation_api_rejects_invalid_partial_extends_version() -> None:
    report = validate_acs_artifacts(
        """
agent_control_specification_version: banana
extends:
  - base.yaml
""",
        {},
    )

    assert not report.valid
    assert report.diagnostics[0].code == "manifest_semantic_error"


def test_string_validation_api_reports_missing_opa() -> None:
    report = validate_acs_artifacts(
        MINIMAL_MANIFEST,
        "package acs.guard",
        opa_path="/does/not/exist/opa",
    )

    assert not report.valid
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["opa_execution_error"]
