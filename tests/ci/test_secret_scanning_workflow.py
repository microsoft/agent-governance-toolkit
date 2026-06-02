# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the Secret Scanning workflow."""

from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "secret-scanning.yml"


def _run_gitleaks_step() -> dict:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["gitleaks"]["steps"]
    for step in steps:
        if step.get("name") == "Run Gitleaks":
            return step
    raise AssertionError("Run Gitleaks step not found")


def test_push_scans_only_pushed_commit_range() -> None:
    step = _run_gitleaks_step()
    env = step["env"]
    script = step["run"]

    assert env["PUSH_BEFORE_SHA"] == "${{ github.event.before }}"
    assert env["PUSH_HEAD_SHA"] == "${{ github.sha }}"
    assert '"$EVENT_NAME" = "push"' in script
    assert '${PUSH_BEFORE_SHA}..${PUSH_HEAD_SHA}' in script


def test_scheduled_and_manual_runs_keep_full_history_scan() -> None:
    script = _run_gitleaks_step()["run"]

    assert "else" in script
    assert "gitleaks detect --source . --verbose" in script
