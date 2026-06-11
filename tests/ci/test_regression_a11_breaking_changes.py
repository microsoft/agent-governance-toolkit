# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for red-team finding A11.

Making ``toolkit-version`` required in the published composite action is a
breaking change for downstream consumers who were relying on the default.
Operators need a migration entry to know they must pin to ``@v3`` (or
similar) and start supplying ``toolkit-version`` explicitly.

Fix: commit a ``BREAKING_CHANGES.md`` at repo root documenting the change.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "BREAKING_CHANGES.md"


def test_a11_breaking_changes_file_exists() -> None:
    assert DOC.exists(), (
        f"BREAKING_CHANGES.md must exist at {DOC} to document the "
        "toolkit-version requirement and other release-time breakages"
    )


def test_a11_breaking_changes_documents_toolkit_version_requirement() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "toolkit-version" in text, (
        "BREAKING_CHANGES.md must reference the toolkit-version input by name"
    )
    lower = text.lower()
    assert "required" in lower or "breaking" in lower, (
        "BREAKING_CHANGES.md must label the toolkit-version change as "
        "required/breaking"
    )
