# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Ensure Studio validation is independently gated in the existing workflow."""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_studio_path_filter_is_separate_from_existing_package_matrices() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    changes = workflow["jobs"]["changes"]
    filter_step = next(step for step in changes["steps"] if step.get("id") == "filter")
    filters = yaml.safe_load(filter_step["with"]["filters"])

    assert changes["outputs"]["studio"] == "${{ steps.filter.outputs.studio }}"
    assert filters["studio"] == ["agent-governance-studio/**", ".github/workflows/ci.yml"]
    for name in ("python", "typescript", "integrations", "dotnet", "rust", "go"):
        assert "agent-governance-studio/**" not in filters[name]
    assert "studio" not in changes["outputs"]["changed-py-pkgs"]
    assert "studio" not in changes["outputs"]["changed-ts-pkgs"]


def test_studio_job_runs_real_language_gates_and_reports_to_ci_complete() -> None:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    studio = workflow["jobs"]["studio"]
    commands = "\n".join(step.get("run", "") for step in studio["steps"])

    assert studio["needs"] == "changes"
    assert "needs.changes.outputs.studio == 'true'" in studio["if"]
    assert "studio" in workflow["jobs"]["ci-complete"]["needs"]
    assert workflow["permissions"] == {"contents": "read"}
    assert all(
        re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
        for step in studio["steps"]
        if "uses" in step
    )
    for command in (
        "ruff check agent-governance-studio/src agent-governance-studio/tests",
        "python -m pytest agent-governance-studio/tests -q",
        "python -m build --no-isolation agent-governance-studio",
        "python -m pip install --no-deps agent-governance-studio/dist/*.whl",
        "npm ci --ignore-scripts --prefix agent-governance-studio/web",
        "npm run lint --prefix agent-governance-studio/web",
        "npm test --prefix agent-governance-studio/web",
        "npm run build --prefix agent-governance-studio/web",
    ):
        assert command in commands
    assert "--junitxml=/tmp/agt-studio-python.xml" in commands
    assert "--reporter=junit --outputFile.junit=/tmp/agt-studio-frontend.xml" in commands
    assert "No Studio tests executed" in commands
    assert '".text-3xl" in styles[0].read_text(encoding="utf-8")' in commands


def test_studio_dependabot_inherits_the_existing_npm_policy() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    )
    npm = next(update for update in config["updates"] if update["package-ecosystem"] == "npm")

    assert "/agent-governance-studio/web" in npm["directories"]
    assert npm["schedule"]["interval"] == "weekly"
    assert npm["cooldown"]["default-days"] == 7
    assert "dependencies" in npm["labels"]
    assert npm["commit-message"]["prefix"] == "chore(deps)"


def test_studio_has_explicit_maintainer_ownership() -> None:
    owners = (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert (
        "/agent-governance-studio/ @MohammadHaroonAbuomar @liamcrumm @prayagupa"
        in owners.splitlines()
    )
