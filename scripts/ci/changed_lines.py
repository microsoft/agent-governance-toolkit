# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Utilities for scoping CI checks to changed files or added diff lines."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


DEFAULT_REPO = Path.cwd()


def normalize_extensions(extensions: str) -> list[str]:
    """Return normalized extension filters from a comma-separated string."""
    normalized: list[str] = []
    for extension in extensions.split(","):
        value = extension.strip()
        if not value:
            continue
        normalized.append(value if value.startswith(".") else f".{value}")
    return normalized


def pathspecs_for_extensions(extensions: Iterable[str]) -> list[str]:
    """Build git pathspecs matching files with the requested extensions."""
    return [f"*{extension}" for extension in extensions]


def extract_added_lines(diff_text: str) -> str:
    """Extract only added content lines from a unified diff."""
    added_lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added_lines.append(line[1:])
    return "\n".join(added_lines) + ("\n" if added_lines else "")


def run_git_diff(
    repo: Path,
    base: str,
    pathspecs: Sequence[str],
    *,
    name_only: bool,
) -> str:
    """Run git diff for the requested pathspecs and return stdout."""
    command = [
        "git",
        "diff",
        "--no-ext-diff",
        "--diff-filter=ACMRT",
    ]
    if name_only:
        command.append("--name-only")
    else:
        command.append("--unified=0")
    command.extend([base, "--", *pathspecs])
    result = subprocess.run(
        command,
        cwd=repo,
        check=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def write_or_print(content: str, output: Path | None) -> None:
    """Write content to the requested output file, or print it to stdout."""
    if output is None:
        print(content, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Git ref to diff against, for example origin/main.")
    parser.add_argument(
        "--extensions",
        required=True,
        help="Comma-separated file extensions to include, for example .md,.txt,.py.",
    )
    parser.add_argument(
        "--mode",
        choices=("added-lines", "changed-files"),
        default="added-lines",
        help="Whether to emit added diff lines or changed file names.",
    )
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO, help="Repository working tree path.")
    parser.add_argument("--output", type=Path, help="Optional output file path.")
    return parser.parse_args()


def main() -> int:
    """Run the changed-lines helper."""
    args = parse_args()
    extensions = normalize_extensions(args.extensions)
    pathspecs = pathspecs_for_extensions(extensions)
    if args.mode == "changed-files":
        content = run_git_diff(args.repo, args.base, pathspecs, name_only=True)
    else:
        diff_text = run_git_diff(args.repo, args.base, pathspecs, name_only=False)
        content = extract_added_lines(diff_text)
    write_or_print(content, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
