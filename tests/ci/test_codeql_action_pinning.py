# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for CodeQL action references in repository content."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CODEQL_REFERENCE_RE = re.compile(
    r"github/codeql-action/[A-Za-z0-9_-]+@(?P<ref>[^\s#`'\"]+)"
    r"(?:\s+#\s*(?P<version>v[0-9]+(?:\.[0-9]+){1,2}))?"
)
SHA_RE = re.compile(r"[0-9a-f]{40}")
V4_VERSION_RE = re.compile(r"v4\.[0-9]+\.[0-9]+")


def _codeql_references() -> list[tuple[str, int, str, str | None]]:
    result = subprocess.run(
        ["git", "grep", "-n", "-F", "github/codeql-action/", "--"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode in (0, 1), result.stderr

    references: list[tuple[str, int, str, str | None]] = []
    for line in result.stdout.splitlines():
        path, line_number, content = line.split(":", 2)
        for match in CODEQL_REFERENCE_RE.finditer(content):
            references.append(
                (path, int(line_number), match.group("ref"), match.group("version"))
            )
    return references


def test_all_codeql_action_references_are_sha_pinned_to_codeql_v4() -> None:
    references = _codeql_references()
    assert references, "Expected at least one CodeQL action reference"

    for path, line_number, reference, version in references:
        location = f"{path}:{line_number}"
        assert SHA_RE.fullmatch(reference), (
            f"{location} must use a full 40-character lowercase SHA, got {reference!r}"
        )
        assert version and V4_VERSION_RE.fullmatch(version), (
            f"{location} must identify a CodeQL v4 release, got {version!r}"
        )

    assert len({reference for _, _, reference, _ in references}) == 1, (
        "All CodeQL action references must use the same release SHA"
    )
    assert len({version for _, _, _, version in references}) == 1, (
        "All CodeQL action references must use the same release annotation"
    )
