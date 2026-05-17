# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "no-stubs.sh"
HAS_GIT = shutil.which("git") is not None
HAS_BASH = shutil.which("bash") is not None
CAN_RUN_SHELL_GATE = HAS_GIT and HAS_BASH and os.name != "nt"


@pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")
def test_conflict_start_marker_fails(tmp_path: Path) -> None:
    result = _run_gate_with_added_line(tmp_path, "sample.py", "<<<<<<< HEAD")

    assert result.returncode == 1
    assert "unresolved merge conflict markers" in result.stdout
    assert "<<<<<<< HEAD" in result.stdout


@pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")
def test_conflict_separator_line_fails(tmp_path: Path) -> None:
    result = _run_gate_with_added_line(tmp_path, "sample.py", "=======")

    assert result.returncode == 1
    assert "unresolved merge conflict markers" in result.stdout
    assert "=======" in result.stdout


@pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")
def test_conflict_end_marker_fails(tmp_path: Path) -> None:
    result = _run_gate_with_added_line(tmp_path, "sample.py", ">>>>>>> feature-branch")

    assert result.returncode == 1
    assert "unresolved merge conflict markers" in result.stdout
    assert ">>>>>>> feature-branch" in result.stdout


@pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")
def test_markdown_separator_does_not_fail(tmp_path: Path) -> None:
    result = _run_gate_with_added_line(tmp_path, "README.md", "=======")

    assert result.returncode == 0
    assert "no new production lines to check" in result.stdout


@pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")
def test_existing_todo_stub_detection_preserved(tmp_path: Path) -> None:
    result = _run_gate_with_added_line(tmp_path, "sample.py", "# TODO: implement this")

    assert result.returncode == 1
    assert "found stub/TODO markers" in result.stdout
    assert "TODO" in result.stdout


@pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")
def test_non_conflict_separator_comment_does_not_fail(tmp_path: Path) -> None:
    result = _run_gate_with_added_line(tmp_path, "sample.py", "# =======")

    assert result.returncode == 0
    assert "no stub markers found in new code" in result.stdout


def _run_gate_with_added_line(tmp_path: Path, relative_file: str, added_line: str) -> subprocess.CompletedProcess[str]:
    _init_git_repo(tmp_path)

    target = tmp_path / relative_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("print('base')\n", encoding="utf-8")

    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")

    with target.open("a", encoding="utf-8") as handle:
        handle.write(f"{added_line}\n")

    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "change")

    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    script_path = _to_bash_path(SCRIPT_PATH)

    return subprocess.run(
        ["bash", "-lc", f"'{script_path}' HEAD~1"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _init_git_repo(repo_dir: Path) -> None:
    _git(repo_dir, "init")
    _git(repo_dir, "config", "user.name", "AGT Test")
    _git(repo_dir, "config", "user.email", "agt-test@example.com")


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _to_bash_path(path: Path) -> str:
    resolved = path.resolve()
    as_posix = resolved.as_posix()
    if resolved.drive:
        drive = resolved.drive.rstrip(":").lower()
        remainder = as_posix.split(":", 1)[1]
        return f"/{drive}{remainder}"
    return as_posix
