# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the dependency-audit CI gate."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / "ci" / "vendored-patch-audit.sh"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repo_with_lockfile_change(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")

    lockfile = repo / "requirements.txt"
    lockfile.write_text("example==1.0.0\n", encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    lockfile.write_text("example==2.0.0\n", encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-m", "major bump")
    return repo, base


def test_major_dependabot_failure_prints_copyable_audit_template(tmp_path: Path) -> None:
    repo, base = _repo_with_lockfile_change(tmp_path)
    env = os.environ.copy()
    env.update(
        PR_ACTOR="dependabot[bot]",
        DEPENDABOT_UPDATE_TYPE="version-update:semver-major",
    )

    result = subprocess.run(
        ["bash", str(SCRIPT), base],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Dependency audit template" in result.stdout
    assert "## Which dependencies changed and why" in result.stdout
    assert "## Security advisory relevance" in result.stdout
    assert "## Breaking change risk assessment" in result.stdout
    assert "docs/dependency-audits/" in result.stdout


def test_failure_writes_template_to_github_step_summary(tmp_path: Path) -> None:
    repo, base = _repo_with_lockfile_change(tmp_path)
    summary = tmp_path / "summary.md"
    env = os.environ.copy()
    env.update(
        PR_ACTOR="dependabot[bot]",
        DEPENDABOT_UPDATE_TYPE="version-update:semver-major",
        GITHUB_STEP_SUMMARY=str(summary),
    )

    result = subprocess.run(
        ["bash", str(SCRIPT), base],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    summary_text = summary.read_text(encoding="utf-8")
    assert "Dependency audit template" in summary_text
    assert "owner: <github-handle>" in summary_text
