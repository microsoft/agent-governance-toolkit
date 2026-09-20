# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for synchronized CodeQL action references.

User-facing templates and tutorials intentionally mirror the canonical CodeQL
workflow pin. A future Dependabot update to that workflow must update those
references in the same change rather than leaving copy-paste examples stale.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL_CODEQL_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "codeql.yml"
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


def _canonical_codeql_pin() -> tuple[str, str]:
    match = CODEQL_REFERENCE_RE.search(
        CANONICAL_CODEQL_WORKFLOW.read_text(encoding="utf-8")
    )
    assert match, f"No CodeQL action reference found in {CANONICAL_CODEQL_WORKFLOW}"
    version = match.group("version")
    assert version is not None
    return match.group("ref"), version


def test_all_codeql_action_references_match_canonical_v4_pin() -> None:
    references = _codeql_references()
    assert references, "Expected at least one CodeQL action reference"
    canonical_reference, canonical_version = _canonical_codeql_pin()

    for path, line_number, reference, version in references:
        location = f"{path}:{line_number}"
        assert SHA_RE.fullmatch(reference), (
            f"{location} must use a full 40-character lowercase SHA, got {reference!r}"
        )
        assert version and V4_VERSION_RE.fullmatch(version), (
            f"{location} must identify a CodeQL v4 release, got {version!r}"
        )
        assert reference == canonical_reference, (
            f"{location} must match the canonical CodeQL SHA {canonical_reference}"
        )
        assert version == canonical_version, (
            f"{location} must match the canonical CodeQL release {canonical_version}"
        )
