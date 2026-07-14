# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native ACS manifest linting."""

from __future__ import annotations

import json
from pathlib import Path

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
    path = _write_manifest(tmp_path / "manifest.yaml")

    assert lint_file(path).passed


def test_json_manifest_passes(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path / "manifest.json")

    assert lint_file(path).passed


def test_old_rule_document_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "old.yaml"
    path.write_text(
        "version: '1.0'\nname: old\nrules: []\n",
        encoding="utf-8",
    )

    result = lint_file(path)

    assert not result.passed
    assert "agent_control_specification_version" in result.errors[0].message


def test_missing_bundle_is_rejected(tmp_path: Path) -> None:
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
