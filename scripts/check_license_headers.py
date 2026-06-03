#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Check that source files contain the MIT license header.

Usage:
    python scripts/check_license_headers.py [--fix]

Checks .py, .ts, .cs, .rs, .go files for the required header.
With --fix, prepends the header to files that are missing it.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Expected header patterns per language (single-line and two-line variants)
HEADERS_SINGLE: dict[str, str] = {
    ".py": "# Copyright (c) Microsoft Corporation. Licensed under the MIT License.",
    ".ts": "// Copyright (c) Microsoft Corporation. Licensed under the MIT License.",
    ".cs": "// Copyright (c) Microsoft Corporation. Licensed under the MIT License.",
    ".rs": "// Copyright (c) Microsoft Corporation. Licensed under the MIT License.",
    ".go": "// Copyright (c) Microsoft Corporation. Licensed under the MIT License.",
}

HEADERS_MULTI: dict[str, tuple[str, str]] = {
    ".py": ("# Copyright (c) Microsoft Corporation.", "# Licensed under the MIT License."),
    ".ts": ("// Copyright (c) Microsoft Corporation.", "// Licensed under the MIT License."),
    ".cs": ("// Copyright (c) Microsoft Corporation.", "// Licensed under the MIT License."),
    ".rs": ("// Copyright (c) Microsoft Corporation.", "// Licensed under the MIT License."),
    ".go": ("// Copyright (c) Microsoft Corporation.", "// Licensed under the MIT License."),
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".eggs", ".tox", ".mypy_cache",
    "vendor", "third_party",
    # Vendored third-party subtree: the Agent Control Specification (ACS) is
    # MIT-licensed by a third party (Copyright (c) 2026 responsibleai, see
    # policy-engine/LICENSE.acs). Stamping a Microsoft copyright header onto
    # these files would misattribute the upstream copyright, so the subtree is
    # exempt from Microsoft-header enforcement.
    "policy-engine",
}

# Files to skip (generated, vendored, etc.)
SKIP_FILES = {"__init__.py"}


def should_skip(path: Path) -> bool:
    """Return True if the file should be skipped."""
    parts = path.parts
    if any(d in parts for d in SKIP_DIRS):
        return True
    if path.name in SKIP_FILES:
        return True
    # Skip empty files
    if path.stat().st_size == 0:
        return True
    return False


def check_header(path: Path) -> bool:
    """Return True if the file has the correct license header."""
    single = HEADERS_SINGLE.get(path.suffix)
    multi = HEADERS_MULTI.get(path.suffix)
    if not single:
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return True  # skip unreadable files

    # Check first 5 lines for the header (allows shebang, encoding, etc.)
    lines = content.split("\n", 5)[:5]
    # Single-line match
    if any(single in line for line in lines):
        return True
    # Two-line match
    if multi:
        text = "\n".join(lines)
        if multi[0] in text and multi[1] in text:
            return True
    return False


def fix_header(path: Path) -> None:
    """Prepend the license header to a file."""
    expected = HEADERS_SINGLE.get(path.suffix)
    if not expected:
        return
    content = path.read_text(encoding="utf-8")
    # If file starts with shebang, insert after it
    if content.startswith("#!"):
        first_newline = content.index("\n")
        path.write_text(
            content[: first_newline + 1] + expected + "\n" + content[first_newline + 1 :],
            encoding="utf-8",
        )
    else:
        path.write_text(expected + "\n" + content, encoding="utf-8")


def main() -> int:
    fix_mode = "--fix" in sys.argv
    file_args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = Path(".")
    missing: list[Path] = []

    if file_args:
        # Check only specified files
        for f in file_args:
            path = Path(f)
            if path.exists() and path.suffix in HEADERS_SINGLE and not should_skip(path):
                if not check_header(path):
                    missing.append(path)
    else:
        # Check all source files
        for ext in HEADERS_SINGLE:
            for path in root.rglob(f"*{ext}"):
                if should_skip(path):
                    continue
                if not check_header(path):
                    missing.append(path)

    if not missing:
        print(f"All source files have license headers.")
        return 0

    if fix_mode:
        for path in missing:
            fix_header(path)
            print(f"Fixed: {path}")
        print(f"\nFixed {len(missing)} file(s).")
        return 0

    print(f"Missing license header in {len(missing)} file(s):\n")
    for path in sorted(missing):
        print(f"  {path}")
    print(f"\nRun with --fix to add headers automatically.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
