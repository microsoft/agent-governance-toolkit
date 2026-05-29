# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for A1 and A9 of the red-team review.

A1 (High): the ``npm install`` of ``agent-threat-rules`` in
``sync-atr-community-rules.yml`` runs lifecycle scripts. SHA-512 integrity
only verifies the bytes-as-published; a compromised publisher who registers
a new integrity still gets arbitrary code execution at install time in a
job that holds ``contents:write`` + ``pull-requests:write`` + ``GITHUB_TOKEN``.
Fix: ``--ignore-scripts``.

A9 (Low): the tarball is downloaded to a fixed ``/tmp/atr.tgz`` path. Switch
to ``mktemp -t atr.XXXXXX.tgz`` as defense-in-depth on shared (e.g.
self-hosted) runners.
"""

from __future__ import annotations

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "sync-atr-community-rules.yml"
)


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_a1_atr_npm_install_disables_lifecycle_scripts() -> None:
    """The ATR ``npm install`` must include ``--ignore-scripts``."""
    text = _workflow_text()
    # There must be at least one npm install line in the file.
    assert "npm install" in text, "sync-atr workflow lost its npm install step"
    # Every npm install line in this workflow must include --ignore-scripts.
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "npm install" in stripped or "npm i " in stripped or stripped.endswith("npm i"):
            assert "--ignore-scripts" in stripped, (
                f"line {lineno}: npm install missing --ignore-scripts: {stripped!r}"
            )


def test_a9_atr_tarball_uses_mktemp_path() -> None:
    """The downloaded ATR tarball must live at an unpredictable per-run path."""
    text = _workflow_text()
    assert "/tmp/atr.tgz" not in text, (
        "Predictable tarball path /tmp/atr.tgz must be replaced with mktemp"
    )
    assert "mktemp" in text, "Expected mktemp-based tarball path"
    # The mktemp template should restrict the suffix so the file is identifiable.
    assert "atr." in text, "mktemp template should keep the atr. prefix"
