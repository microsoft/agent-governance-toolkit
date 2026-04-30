# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Extract bash inline scripts from GitHub Actions workflow files."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RUN_BLOCK_RE = re.compile(r"^(?P<indent>\s*)run:\s*[|>][-+]?\s*(?:#.*)?$")
SHELL_RE = re.compile(r"^\s*shell:\s*(?P<shell>[^#\n]+)")
RUNS_ON_RE = re.compile(r"^\s*runs-on:\s*(?P<runs_on>[^#\n]+)")
STEP_RE = re.compile(r"^(?P<indent>\s*)-\s+")


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _clean_scalar(value: str) -> str:
    return value.strip().strip('"\'')


def _block_end(lines: list[str], start: int, parent_indent: int) -> int:
    index = start + 1
    while index < len(lines):
        line = lines[index]
        if line.strip() and _indent_width(line) <= parent_indent:
            break
        index += 1
    return index


def _find_step_bounds(lines: list[str], run_index: int, run_indent: int) -> tuple[int, int]:
    step_start = run_index
    step_indent = run_indent
    for index in range(run_index, -1, -1):
        line = lines[index]
        if STEP_RE.match(line) and _indent_width(line) <= run_indent:
            step_start = index
            step_indent = _indent_width(line)
            break

    step_end = len(lines)
    for index in range(run_index + 1, len(lines)):
        line = lines[index]
        if line.strip() and _indent_width(line) <= step_indent and STEP_RE.match(line):
            step_end = index
            break
        if line.strip() and _indent_width(line) < step_indent:
            step_end = index
            break
    return step_start, step_end


def _step_shell(lines: list[str], step_start: int, step_end: int, run_start: int, run_end: int) -> str | None:
    for index in range(step_start, step_end):
        if run_start <= index < run_end:
            continue
        match = SHELL_RE.match(lines[index])
        if match:
            return _clean_scalar(match.group("shell"))
    return None


def _job_runs_on(lines: list[str], run_index: int) -> str | None:
    for index in range(run_index, -1, -1):
        line = lines[index]
        if line.strip() and _indent_width(line) <= 2 and index != run_index:
            if index < run_index and RUNS_ON_RE.match(line):
                return _clean_scalar(RUNS_ON_RE.match(line).group("runs_on"))
            if _indent_width(line) <= 2 and not line.lstrip().startswith(("runs-on:", "#")):
                break
        match = RUNS_ON_RE.match(line)
        if match:
            return _clean_scalar(match.group("runs_on"))
    return None


def _is_bash_step(shell: str | None, runs_on: str | None) -> bool:
    if shell is not None:
        return shell.split()[0] == "bash"
    return "windows" not in (runs_on or "").lower()


def _dedent_block(block_lines: list[str]) -> list[str]:
    content_indents = [_indent_width(line) for line in block_lines if line.strip()]
    if not content_indents:
        return [""] if block_lines else []
    trim = min(content_indents)
    return [line[trim:] if len(line) >= trim else "" for line in block_lines]


def extract_file(path: Path) -> list[tuple[str, int, list[str]]]:
    """Return extracted bash blocks as ``(path, run_line, lines)`` tuples."""
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[tuple[str, int, list[str]]] = []
    for index, line in enumerate(lines):
        match = RUN_BLOCK_RE.match(line)
        if not match:
            continue

        run_indent = len(match.group("indent"))
        run_end = _block_end(lines, index, run_indent)
        step_start, step_end = _find_step_bounds(lines, index, run_indent)
        shell = _step_shell(lines, step_start, step_end, index, run_end)
        runs_on = _job_runs_on(lines, index)
        if not _is_bash_step(shell, runs_on):
            continue

        block = _dedent_block(lines[index + 1 : run_end])
        blocks.append((path.as_posix(), index + 1, block))
    return blocks


def workflow_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(path for path in root.rglob("*.yml") if path.is_file())


def emit_shell(root: Path) -> str:
    sections: list[str] = []
    for path in workflow_files(root):
        for file_name, line_number, block in extract_file(path):
            sections.append(f"# === {file_name}:{line_number} ===")
            sections.extend(block)
            sections.append("")
    return "\n".join(sections).rstrip() + "\n" if sections else ""


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow_path", type=Path, help="Workflow file or directory to scan")
    args = parser.parse_args()
    sys.stdout.write(emit_shell(args.workflow_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
