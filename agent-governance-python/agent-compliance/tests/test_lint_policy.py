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


def test_governance_policy_without_acs_version_is_error(tmp_path: Path) -> None:
    """A governance document missing agent_control_specification_version is rejected."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: old\nrules: []\n",
    )

    result = lint_file(path)

    assert not result.passed
    assert any(
        "agent_control_specification_version" in error.message
        for error in result.errors
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
    condition_errors = [
        e for e in result.errors if "empty value list" in e.message
    ]
    assert len(condition_errors) == 1
    assert "block" in condition_errors[0].message
    assert "in" in condition_errors[0].message
    assert "condition can never match" in condition_errors[0].message
    assert "rule can never apply" in condition_errors[0].message


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
        and "condition always matches" in error.message
        and "denies everything" in error.message
        for error in result.errors
    )


def test_governance_not_in_empty_value_under_allow_is_diagnosed_as_allowing_everything(
    tmp_path: Path,
) -> None:
    """An empty 'not_in' list under allow is diagnosed as allowing everything."""
    path = _write_governance_policy(
        tmp_path / "policy.yaml",
        "version: '1.0'\nname: t\nrules:\n"
        "  - name: permit-all\n"
        "    action: allow\n"
        "    condition:\n"
        "      field: tool_name\n"
        "      operator: not_in\n"
        "      value: []\n",
    )

    result = lint_file(path)

    assert any(
        "condition always matches" in error.message
        and "allows everything" in error.message
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


def test_governance_in_nonempty_value_has_no_condition_error(tmp_path: Path) -> None:
    """An 'in' operator with a non-empty value list is satisfiable — no condition error."""
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

    assert not any("empty value list" in e.message for e in result.errors)


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
        "condition always matches" in error.message
        and "allows everything" in error.message
        for error in result.errors
    )


def test_governance_non_membership_operator_no_condition_error(tmp_path: Path) -> None:
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

    assert not any("empty value list" in e.message for e in result.errors)


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
    condition_errors = [
        e for e in result.errors if "empty value list" in e.message
    ]
    assert len(condition_errors) == 2
    messages = {m.message for m in condition_errors}
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


def test_known_operators_are_derived_from_every_evaluator_source() -> None:
    """The operator vocabulary must keep tracking the evaluators it protects.

    ``_KNOWN_CONDITION_OPERATORS`` is built by reading the evaluator modules
    rather than from a hand-written list, so a new operator cannot reach an
    evaluator without the linter learning it.  That derivation fails silently:
    if a module moves or the extraction stops matching, the set empties and
    every governance document reports ``unknown operator`` instead.  Assert the
    sources still resolve and the vocabulary still covers the operators this
    module itself branches on.
    """
    from agent_compliance.lint_policy import (
        _KNOWN_CONDITION_OPERATORS,
        _MEMBERSHIP_OPERATORS,
        _condition_operator_sources,
    )

    source_names = {path.name for path in _condition_operator_sources()}
    assert {"policy_engine.py", "trust_policy.py"} <= source_names, source_names

    assert _KNOWN_CONDITION_OPERATORS, (
        "operator derivation produced an empty set; every document would "
        "now fail with 'unknown operator'"
    )
    missing = _MEMBERSHIP_OPERATORS - _KNOWN_CONDITION_OPERATORS
    assert not missing, f"membership operators absent from vocabulary: {missing}"


def test_operator_known_to_an_evaluator_is_not_reported_unknown(
    tmp_path: Path,
) -> None:
    """Every derived operator must lint clean, or the guard is a false positive."""
    from agent_compliance.lint_policy import _KNOWN_CONDITION_OPERATORS

    # An empty vocabulary would make the loop below assert nothing at all --
    # the same vacuous pass that ``in []`` produces in a governance rule.
    assert _KNOWN_CONDITION_OPERATORS, "nothing to check; derivation is empty"

    for operator in sorted(_KNOWN_CONDITION_OPERATORS):
        policy = tmp_path / f"policy_{operator}.yaml"
        _write_governance_policy(
            policy,
            "version: '1.0'\nname: t\nrules:\n"
            "  - name: r\n"
            "    action: deny\n"
            "    condition:\n"
            "      field: tool_name\n"
            f"      operator: {operator}\n"
            "      value: 'x'\n",
        )

        result = lint_file(policy)

        assert not any("unknown operator" in m.message for m in result.errors), (
            f"{operator!r} is implemented by an evaluator but the linter "
            f"rejects it: {[m.message for m in result.errors]}"
        )
