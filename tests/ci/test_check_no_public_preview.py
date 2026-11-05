# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Exit-path tests for scripts/ci/check_no_public_preview.sh.

The gate wraps ``git grep``. It must fail when the label is present, pass
when the tree is clean, and fail with the Git status when ``git grep``
itself breaks instead of reporting a clean tree.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "check_no_public_preview.sh"
HAS_GIT = shutil.which("git") is not None
HAS_BASH = shutil.which("bash") is not None
CAN_RUN_SHELL_GATE = HAS_GIT and HAS_BASH and os.name != "nt"

pytestmark = pytest.mark.skipif(not CAN_RUN_SHELL_GATE, reason="requires git/bash on non-Windows host")

# Built from parts so this test file does not itself trip the gate.
LABEL = "Public" + " " + "Preview"
HYPHENATED_LABEL = "public" + "-" + "preview"


def test_label_present_fails(tmp_path: Path) -> None:
    repo = _repo_with_file(tmp_path, "docs/guide.md", f"This feature is in {LABEL}.\n")

    result = _run_gate(repo)

    assert result.returncode == 1
    assert "the release-stage label is back" in result.stdout
    assert "docs/guide.md:1:" in result.stdout


def test_hyphenated_label_present_fails(tmp_path: Path) -> None:
    repo = _repo_with_file(tmp_path, "README.md", f"{HYPHENATED_LABEL} build\n")

    result = _run_gate(repo)

    assert result.returncode == 1
    assert "README.md:1:" in result.stdout


def test_label_in_allowed_file_passes(tmp_path: Path) -> None:
    repo = _repo_with_file(tmp_path, "CHANGELOG.md", f"## 1.0.0\n\nLeft {LABEL}.\n")

    result = _run_gate(repo)

    assert result.returncode == 0
    assert "no release-stage label outside release history" in result.stdout


def test_clean_tree_passes(tmp_path: Path) -> None:
    repo = _repo_with_file(tmp_path, "docs/guide.md", "Nothing to see here.\n")

    result = _run_gate(repo)

    assert result.returncode == 0
    assert "no release-stage label outside release history" in result.stdout


def test_git_grep_failure_fails_with_git_status(tmp_path: Path) -> None:
    repo = _repo_with_file(tmp_path, "docs/guide.md", "Nothing to see here.\n")
    shim_dir = _git_shim_failing_grep(tmp_path, exit_status=2)

    result = _run_gate(repo, path_prefix=shim_dir)

    assert result.returncode == 2
    assert "simulated git grep failure" in result.stderr
    assert "git grep failed with exit status 2" in result.stderr
    assert "no release-stage label" not in result.stdout
    assert "the release-stage label is back" not in result.stdout


def _repo_with_file(tmp_path: Path, relative_file: str, content: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AGT Test")
    _git(repo, "config", "user.email", "agt-test@example.com")

    target = repo / relative_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")

    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _git_shim_failing_grep(tmp_path: Path, exit_status: int) -> Path:
    """Put a ``git`` on PATH that fails ``git grep`` and delegates the rest."""
    real_git = shutil.which("git")
    assert real_git is not None
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "git"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "grep" ]; then\n'
        '  echo "fatal: simulated git grep failure" >&2\n'
        f"  exit {exit_status}\n"
        "fi\n"
        f'exec "{real_git}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim_dir


def _run_gate(repo: Path, path_prefix: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        ["bash", str(SCRIPT_PATH)],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
