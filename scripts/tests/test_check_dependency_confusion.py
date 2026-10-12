#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_dependency_confusion.py."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from check_dependency_confusion import (
    check_cargo_toml,
    check_package_json,
    check_pyproject_toml,
)


def _write_pyproject(tmp_path, content: str) -> str:
    path = tmp_path / "pyproject.toml"
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_check_pyproject_standard_project_dependencies(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project]
dependencies = ["requests"]
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert findings == []


def test_check_pyproject_optional_dependencies(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project]
name = "demo"
version = "0.1.0"

[project.optional-dependencies]
dev = ["pytest", "ruff>=0.5"]
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert findings == []


def test_check_pyproject_unregistered_dependency_is_flagged(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project]
dependencies = ["fake-internal-package-xyz>=1.0"]
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert len(findings) == 1
    assert "fake-internal-package-xyz" in findings[0]


def test_check_pyproject_extras_and_version_specifiers(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project]
dependencies = ["uvicorn[standard]>=0.30"]
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert findings == []


def test_check_pyproject_multiline_dependency_arrays(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project]
dependencies = [
    "requests>=2.0",
    "uvicorn[standard]>=0.30",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "ruff>=0.5",
]
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert findings == []


def test_check_pyproject_legacy_project_dependencies_table_supported(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project.dependencies]
requests = ">=2.0"
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert findings == []


def test_check_pyproject_local_only_dependency_behavior_preserved(tmp_path):
    pyproject = _write_pyproject(
        tmp_path,
        """
[project]
dependencies = ["agent-primitives>=0.1"]
""",
    )

    findings = check_pyproject_toml(pyproject)

    assert findings == []


def test_registered_yaml_parser_is_accepted_in_cargo_dependencies(tmp_path):
    manifest = tmp_path / "Cargo.toml"
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        manifest.write_text(
            f'[{section}]\nserde-saphyr = "=1.2.0"\n', encoding="utf-8"
        )
        assert check_cargo_toml(str(manifest)) == []


def test_unregistered_cargo_names_are_still_rejected(tmp_path):
    manifest = tmp_path / "Cargo.toml"
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        manifest.write_text(
            f'[{section}]\nserde-saphyr-unregistered = "=1.2.0"\n', encoding="utf-8"
        )
        findings = check_cargo_toml(str(manifest))
        assert len(findings) == 1
        assert "serde-saphyr-unregistered" in findings[0]


def test_registered_swc_and_approved_typescript_aliases(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"devDependencies": {
        "@swc/core": "1.16.2", "@swc/jest": "0.2.39",
        "@typescript/native": "npm:typescript@7.0.2",
        "typescript": "npm:@typescript/typescript6@6.0.2",
    }}), encoding="utf-8")
    assert check_package_json(str(manifest)) == []


def test_unapproved_or_malformed_npm_alias_is_flagged(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"devDependencies": {
        "@typescript/native": "npm:evil-typescript@7.0.2",
        "typescript": "npm:@typescript/typescript6@^6",
        "@typescript/unknown": "npm:typescript@7.0.2",
    }}), encoding="utf-8")
    findings = check_package_json(str(manifest))
    assert len(findings) == 3
    assert all("invalid or unapproved alias" in finding for finding in findings)
