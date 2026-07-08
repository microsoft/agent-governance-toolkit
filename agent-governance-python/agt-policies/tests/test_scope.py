# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for manifest_resolution.scope: containment and deterministic matching."""

from __future__ import annotations

from pathlib import Path
import pytest
import fnmatch as fnmatch_module

from agt.manifest_resolution import ResolutionError, ResolutionReason, filter_by_scope


def _action(root: Path, relative_path: str) -> Path:
    action_path = root / relative_path
    action_path.parent.mkdir(parents=True, exist_ok=True)
    action_path.write_text("# code\n", encoding="utf-8")
    return action_path


def test_filter_by_scope_rejects_action_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    action = tmp_path / "outside" / "main.py"
    action.parent.mkdir()
    action.write_text("# code\n", encoding="utf-8")

    with pytest.raises(ResolutionError) as exc_info:
        filter_by_scope(root / "governance.yaml", "**/*.py", action, root)

    assert exc_info.value.reason == ResolutionReason.PATH_TRAVERSAL


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
