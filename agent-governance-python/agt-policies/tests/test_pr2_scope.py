# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for deterministic scope filtering."""

from __future__ import annotations

import fnmatch as fnmatch_module
from pathlib import Path

import pytest

from agt.manifest_resolution import filter_by_scope


def _action(root: Path, relative_path: str) -> Path:
    action_path = root / relative_path
    action_path.parent.mkdir(parents=True, exist_ok=True)
    action_path.write_text("# code\n", encoding="utf-8")
    return action_path


def test_scope_globs_remain_case_sensitive_under_windows_normcase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def windows_normcase(path: str) -> str:
        return path.lower().replace("/", "\\")

    monkeypatch.setattr(fnmatch_module.os.path, "normcase", windows_normcase)

    assert (
        filter_by_scope(
            tmp_path / "governance.yaml",
            "foo/*",
            _action(tmp_path, "Foo/bar"),
            tmp_path,
        )
        is False
    )
    assert (
        filter_by_scope(
            tmp_path / "governance.yaml",
            "foo/*",
            _action(tmp_path, "foo/bar"),
            tmp_path,
        )
        is True
    )


def test_blank_scope_patterns_apply_to_document(tmp_path: Path) -> None:
    action_path = _action(tmp_path, "src/main.py")

    assert filter_by_scope(tmp_path / "governance.yaml", "", action_path, tmp_path) is True
    assert (
        filter_by_scope(tmp_path / "governance.yaml", "   ", action_path, tmp_path)
        is True
    )
