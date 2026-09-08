# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


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


def git(repo: Path, *args: str) -> str:
    """Run git in `repo` and return stdout."""
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


@pytest.fixture
def diverged_repo(tmp_path: Path) -> Path:
    """A branch one commit ahead of a base that has since moved on.

    The base's later commits rewrite lines the branch never touched, which is the
    shape that matters: from the base tip those lines look removed there and
    present here, so they read as added by this branch.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    git(repo, "config", "user.email", "ci@example.invalid")
    git(repo, "config", "user.name", "CI")
    tracked = repo / "notes.md"
    untouched = repo / "untouched.md"

    tracked.write_text("Shared line the branch never edits.\n", encoding="utf-8")
    untouched.write_text("A file the branch never opens.\n", encoding="utf-8")
    git(repo, "add", "notes.md", "untouched.md")
    git(repo, "commit", "--quiet", "--message", "base: initial")

    git(repo, "checkout", "--quiet", "-b", "feature")
    tracked.write_text(tracked.read_text(encoding="utf-8") + "Line this branch really adds.\n", encoding="utf-8")
    git(repo, "commit", "--quiet", "--all", "--message", "feature: add a line")

    git(repo, "checkout", "--quiet", "main")
    tracked.write_text("Shared line rewritten on the base.\n", encoding="utf-8")
    untouched.write_text("Rewritten on the base.\n", encoding="utf-8")
    git(repo, "commit", "--quiet", "--all", "--message", "base: rewrite both files")

    git(repo, "checkout", "--quiet", "feature")
    return repo


def added_lines_against(repo: Path, base: str) -> list[str]:
    """Added lines the script reports for `*.md` against `base`."""
    diff_text = changed_lines.run_git_diff(repo, base, ["*.md"], name_only=False)
    return changed_lines.extract_added_lines(diff_text).splitlines()


def test_added_lines_exclude_commits_that_landed_on_the_base(diverged_repo: Path) -> None:
    """Only what the branch added, not the base's own later commits.

    Diffing from the base tip attributed the branch's copy of every line the
    base had since rewritten to the branch. On a real branch a few dozen commits
    behind main that inflated one PR's added lines from 142 to over 160,000, so
    the spell-check job scoped to them checked the whole repository instead.
    """
    assert added_lines_against(diverged_repo, "main") == ["Line this branch really adds."]


def test_uncommitted_work_is_still_reported(diverged_repo: Path) -> None:
    """The diff stays against the working tree, not the branch tip.

    This is why the base is resolved to a merge base rather than the diff being
    switched to `main...HEAD`: that form compares two commits, and this script is
    also run locally before committing.
    """
    notes = diverged_repo / "notes.md"
    notes.write_text(notes.read_text(encoding="utf-8") + "Line not committed yet.\n", encoding="utf-8")

    assert added_lines_against(diverged_repo, "main") == [
        "Line this branch really adds.",
        "Line not committed yet.",
    ]


def test_changed_files_are_scoped_to_the_branch_too(diverged_repo: Path) -> None:
    """`--mode changed-files` shares the base resolution.

    Both modes answer "what did this branch touch", so `untouched.md` -- which
    existed before the branch was cut and has since been rewritten only on the
    base -- must not be listed. It has to pre-date the branch to test this: a
    file the base adds afterwards is simply absent from the branch, so it reads
    as a deletion, which the diff filter drops either way.
    """
    changed = changed_lines.run_git_diff(diverged_repo, "main", ["*.md"], name_only=True).split()

    assert changed == ["notes.md"]


def test_missing_merge_base_falls_back_to_the_base_tip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """An unresolvable merge base must not crash the job.

    A shallow clone can have grafts that do not reach the divergence point. The
    old behaviour -- diff from the base tip -- over-reports, which is the safe
    direction for the checks built on this: they flag too much rather than miss
    something. It is reported so the cause is visible in the log.
    """
    repo = tmp_path / "unrelated"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    git(repo, "config", "user.email", "ci@example.invalid")
    git(repo, "config", "user.name", "CI")
    (repo / "notes.md").write_text("Only history.\n", encoding="utf-8")
    git(repo, "add", "notes.md")
    git(repo, "commit", "--quiet", "--message", "only commit")

    assert changed_lines.resolve_merge_base(repo, "refs/heads/no-such-branch") == "refs/heads/no-such-branch"
    captured = capsys.readouterr()
    assert "cannot resolve merge base" in captured.err
    # And nothing on stdout: that is the result channel when `--output` is
    # omitted, so a warning there is consumed as a changed file name.
    assert captured.out == ""


def test_warning_does_not_contaminate_the_result_on_stdout(tmp_path: Path) -> None:
    """The warning must not be readable as output data.

    Asserted end to end through the CLI rather than on ``resolve_merge_base``
    alone, because that is where the two streams meet: without ``--output`` the
    result is written to stdout, so a caller doing ``for f in $(changed_lines
    ... --mode changed-files)`` would treat the words of the warning as file
    names.

    The spell-check workflow passes ``--output`` and so was never affected;
    ``--output`` is optional, and the fallback exists for exactly the shallow
    clone a CI job runs in, so the two meet in any *other* caller that reads
    stdout.
    """
    # Two unrelated root commits: the base ref resolves, so the fallback `git
    # diff` against its tip succeeds, but there is no merge base to find. A
    # ref that does not exist at all would fail the fallback diff too and never
    # reach the point this test is about.
    repo = tmp_path / "solo"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    git(repo, "config", "user.email", "ci@example.invalid")
    git(repo, "config", "user.name", "CI")
    (repo / "seed.md").write_text("Unrelated root.\n", encoding="utf-8")
    git(repo, "add", "seed.md")
    git(repo, "commit", "--quiet", "--message", "unrelated root")
    git(repo, "checkout", "--quiet", "--orphan", "work")
    git(repo, "rm", "--quiet", "-rf", ".")
    (repo / "notes.md").write_text("Only history.\n", encoding="utf-8")
    git(repo, "add", "notes.md")
    git(repo, "commit", "--quiet", "--message", "only commit")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--base",
            "refs/heads/main",
            "--extensions",
            ".md",
            "--mode",
            "changed-files",
            "--repo",
            str(repo),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
    )

    assert result.returncode == 0
    assert "cannot resolve merge base" in result.stderr
    assert "warning" not in result.stdout
    # Every stdout line is still a path the diff produced, not prose.
    for line in result.stdout.splitlines():
        assert line == "notes.md", f"stdout carried a non-path line: {line!r}"
