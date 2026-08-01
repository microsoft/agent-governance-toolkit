# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "changed_lines.py"
SPEC = importlib.util.spec_from_file_location("changed_lines", SCRIPT_PATH)
assert SPEC is not None
changed_lines = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(changed_lines)


def test_extract_added_lines_ignores_context_removed_and_file_headers() -> None:
    diff_text = """diff --git a/docs/example.md b/docs/example.md
index 1111111..2222222 100644
--- a/docs/example.md
+++ b/docs/example.md
@@ -1,3 +1,4 @@
 Existing typoo remains in context.
-Removed misspeled text.
+Added misspeled text.
+https://example.invalid/new-link
"""

    assert changed_lines.extract_added_lines(diff_text) == (
        "Added misspeled text.\nhttps://example.invalid/new-link\n"
    )


def test_extract_added_lines_combines_multiple_files_without_diff_metadata() -> None:
    diff_text = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
+New README tokenn.
diff --git a/src/example.py b/src/example.py
--- a/src/example.py
+++ b/src/example.py
@@ -10 +10,2 @@
+print(\"neew token\")
"""

    assert changed_lines.extract_added_lines(diff_text) == "New README tokenn.\nprint(\"neew token\")\n"


def test_extension_pathspecs_are_normalized_for_git_diff() -> None:
    extensions = changed_lines.normalize_extensions("md,.txt, py,,")

    assert extensions == [".md", ".txt", ".py"]
    assert changed_lines.pathspecs_for_extensions(extensions) == ["*.md", "*.txt", "*.py"]


def _capture_git_command(name_only: bool) -> list[str]:
    captured: dict[str, list[str]] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with patch.object(changed_lines.subprocess, "run", side_effect=fake_run):
        changed_lines.run_git_diff(Path("."), "origin/main", ["*.md"], name_only=name_only)
    return captured["command"]


def test_run_git_diff_diffs_against_merge_base() -> None:
    command = _capture_git_command(name_only=False)

    assert "--merge-base" in command
    assert command.index("--merge-base") < command.index("origin/main")


def test_run_git_diff_name_only_also_diffs_against_merge_base() -> None:
    command = _capture_git_command(name_only=True)

    assert "--merge-base" in command
    assert "--name-only" in command


def test_added_lines_exclude_base_drift() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        git = ["git", "-C", str(repo)]

        def run(*args: str, **kwargs: str) -> None:
            subprocess.run([*git, *args], check=True, capture_output=True, **kwargs)

        run("init", "-q")
        run("config", "user.email", "test@example.com")
        run("config", "user.name", "Test")
        run("config", "commit.gpgsign", "false")
        run("checkout", "-q", "-b", "main")

        words = repo / "words.txt"
        words.write_text("dorny\n", encoding="utf-8")
        run("add", "words.txt")
        run("commit", "-q", "-m", "main v1")

        run("checkout", "-q", "-b", "feature")
        words.write_text("dorny\nfancytoken\n", encoding="utf-8")
        run("add", "words.txt")
        run("commit", "-q", "-m", "feature change")

        feature_head = subprocess.run(
            [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()

        run("checkout", "-q", "main")
        words.write_text("dorny_renamed\n", encoding="utf-8")
        run("add", "words.txt")
        run("commit", "-q", "-m", "main v2")

        new_main = subprocess.run(
            [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()

        run("update-ref", "refs/remotes/origin/main", new_main)
        run("checkout", "-q", feature_head)

        output = repo / "added-lines.txt"
        argv = [
            "changed_lines.py",
            "--repo", str(repo),
            "--base", "origin/main",
            "--extensions", ".txt",
            "--mode", "added-lines",
            "--output", str(output),
        ]
        with patch.object(sys, "argv", argv):
            rc = changed_lines.main()
        assert rc == 0

        added = output.read_text(encoding="utf-8")
        assert "fancytoken" in added
        assert "dorny" not in added
