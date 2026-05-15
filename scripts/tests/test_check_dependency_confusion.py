#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_dependency_confusion.py."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from check_dependency_confusion import check_pyproject_toml


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
