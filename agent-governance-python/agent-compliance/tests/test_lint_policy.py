# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for policy file linting (ACS manifests and governance YAML)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_compliance.lint_policy import (
    LintMessage,
    LintResult,
    lint_file,
    lint_path,
)


def _write_manifest(path: Path, *, bundle: str | None = None) -> Path:
    policy = (
        {"type": "rego", "bundle": bundle, "query": "data.test.result"}
        if bundle
        else {"type": "custom", "adapter": "test"}
    )
    document = {
        "agent_control_specification_version": "0.3.1-beta",
        "metadata": {"name": "test", "version": "1.0"},
        "extends": [],
        "policies": {"test": policy},
        "intervention_points": {
            "input": {
                "policy_target": "$.input.body",
                "policy": {"id": "test"},
            }
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _write_governance_policy(path: Path, content: str) -> Path:
    """Write a governance policy YAML file and return its path."""
    path.write_text(content, encoding="utf-8")
    return path


def test_lint_message_and_result_serialization() -> None:
    message = LintMessage("error", "bad", "manifest.yaml", 5)
    result = LintResult([message])

    assert str(message) == "manifest.yaml:5: error: bad"
    assert not result.passed
    assert result.to_dict()["errors"] == 1


def test_empty_result_passes() -> None:
    result = LintResult()

    assert result.passed
    assert result.summary() == "No issues found."


def test_valid_native_manifest_passes(tmp_path: Path) -> None:
    pytest.importorskip("agent_control_specification")
    path = _write_manifest(tmp_path / "manifest.yaml")

    assert lint_file(path).passed


def test_json_manifest_passes(tmp_path: Path) -> None:
    pytest.importorskip("agent_control_specification")
    path = _write_manifest(tmp_path / "manifest.json")

    assert lint_file(path).passed


def test_governance_policy_without_acs_version_warns(tmp_path: Path) -> None:
    """A legacy governance document keeps its missing-version diagnostic."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: old\nrules: []\n",
    )

    result = lint_file(path)

    assert result.passed
    assert any(
        "agent_control_specification_version" in warning.message
        for warning in result.warnings
    )


def test_missing_bundle_is_rejected(tmp_path: Path) -> None:
    pytest.importorskip("agent_control_specification")
    path = _write_manifest(tmp_path / "manifest.yaml", bundle="missing")

    result = lint_file(path)

    assert not result.passed


def test_invalid_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text("policies: [\n", encoding="utf-8")

    assert not lint_file(path).passed


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    assert not lint_file(tmp_path / "missing.yaml").passed


def test_unsupported_extension_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.txt"
    path.write_text("{}", encoding="utf-8")

    assert not lint_file(path).passed


def test_directory_lints_all_manifests(tmp_path: Path) -> None:
    pytest.importorskip("agent_control_specification")
    _write_manifest(tmp_path / "one.yaml")
    _write_manifest(tmp_path / "two.json")

    assert lint_path(tmp_path).passed


def test_empty_directory_warns(tmp_path: Path) -> None:
    result = lint_path(tmp_path)

    assert result.passed
    assert len(result.warnings) == 1


def test_missing_path_errors(tmp_path: Path) -> None:
    result = lint_path(tmp_path / "missing")

    assert not result.passed


# ---------------------------------------------------------------------------
# Governance policy YAML — impossible-condition detection (issue #3661)
# ---------------------------------------------------------------------------


def test_governance_in_empty_value_is_error(tmp_path: Path) -> None:
    """An 'in' operator with an empty value list can never match — error.

    Reproduces the first failing case from issue #3661:
      run("empty value set:", "tool_name", [])  # evaluator returns allowed=True
    """
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: block\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: tool_name\n"
        "      operator: in\n"
        "      value: []\n",
    )

    result = lint_file(path)

    assert not result.passed
    errors = result.errors
    assert len(errors) == 1
    assert "block" in errors[0].message
    assert "in" in errors[0].message
    assert "empty" in errors[0].message
    assert "rule can never apply" in errors[0].message


def test_governance_not_in_empty_value_is_error(tmp_path: Path) -> None:
    """An empty 'not_in' list matches every resolved field value."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: restrict\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: tool_name\n"
        "      operator: not_in\n"
        "      value: []\n",
    )

    result = lint_file(path)

    assert not result.passed
    assert any(
        "not_in" in error.message
        and "empty" in error.message
        and "condition matches every resolved field value" in error.message
        and "does not constrain when the 'deny' action applies" in error.message
        for error in result.errors
    )


@pytest.mark.parametrize("operator", ["in", "not_in"])
@pytest.mark.parametrize("value_line", ["      value: null\n", ""])
def test_governance_null_membership_value_is_not_an_empty_list_error(
    tmp_path: Path,
    operator: str,
    value_line: str,
) -> None:
    """A missing/null value must not receive the empty-list diagnosis."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: null-value\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: tool_name\n"
        f"      operator: {operator}\n"
        f"{value_line}",
    )

    result = lint_file(path)

    assert all("empty value list" not in message.message for message in result.messages)


def test_governance_in_nonempty_value_passes(tmp_path: Path) -> None:
    """An 'in' operator with a non-empty value list is satisfiable — no error."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: block-delete\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: tool_name\n"
        "      operator: in\n"
        "      value:\n"
        "        - delete_file\n",
    )

    result = lint_file(path)

    assert result.passed


def test_governance_conditions_list_empty_in_is_error(tmp_path: Path) -> None:
    """Empty IN inside a 'conditions' list is also caught."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: multi-cond\n"
        "    action: deny\n"
        "    conditions:\n"
        "      - field: tool_name\n"
        "        operator: in\n"
        "        value: []\n",
    )

    result = lint_file(path)

    assert not result.passed
    assert any("multi-cond" in m.message for m in result.errors)


def test_governance_conditions_list_empty_not_in_is_composition_neutral(
    tmp_path: Path,
) -> None:
    """The diagnostic does not assume whether plural conditions use AND or OR."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: multi-cond\n"
        "    action: allow\n"
        "    conditions:\n"
        "      - field: tool_name\n"
        "        operator: not_in\n"
        "        value: []\n"
        "      - field: environment\n"
        "        operator: eq\n"
        "        value: production\n",
    )

    result = lint_file(path)

    assert any(
        "does not constrain when the 'allow' action applies" in error.message
        for error in result.errors
    )


def test_governance_non_membership_operator_empty_value_passes(tmp_path: Path) -> None:
    """Non-membership operators are not subject to the empty-value check."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: check-trust\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: trust_score\n"
        "      operator: lt\n"
        "      value: 700\n",
    )

    result = lint_file(path)

    assert result.passed


def test_governance_unknown_operator_is_error(tmp_path: Path) -> None:
    """An operator unsupported by every in-repo evaluator is rejected."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: typo\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: trust_score\n"
        "      operator: greater_than\n"
        "      value: 700\n",
    )

    result = lint_file(path)

    assert not result.passed
    assert any(
        "greater_than" in error.message and "unknown operator" in error.message
        for error in result.errors
    )


def test_governance_multiple_rules_independent_errors(tmp_path: Path) -> None:
    """Each rule with an empty membership set produces its own error."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: rule-a\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: tool_name\n"
        "      operator: in\n"
        "      value: []\n"
        "  - name: rule-b\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: agent.namespace\n"
        "      operator: not_in\n"
        "      value: []\n",
    )

    result = lint_file(path)

    assert not result.passed
    assert len(result.errors) == 2
    messages = {m.message for m in result.errors}
    assert any("rule-a" in m for m in messages)
    assert any("rule-b" in m for m in messages)


def test_governance_directory_with_impossible_condition(tmp_path: Path) -> None:
    """lint_path propagates governance condition errors from directory scans."""
    _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: never-fires\n"
        "    action: deny\n"
        "    condition:\n"
        "      field: tool_name\n"
        "      operator: in\n"
        "      value: []\n",
    )

    result = lint_path(tmp_path)

    assert not result.passed
    assert any("never-fires" in m.message for m in result.errors)
