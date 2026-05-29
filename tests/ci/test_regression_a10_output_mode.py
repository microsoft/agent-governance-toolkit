# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for red-team finding A10.

The AI agent runner accepted any ``output-mode`` string. If a future caller
configured a mode whose required permissions were not granted to the
workflow (e.g. ``pr-review`` requires ``pull-requests: write``), the
runner would silently produce no output and the failure mode was opaque.

Fix: startup check inside the runner script that validates ``output-mode``
is in an allowlist and that the surrounding job declares the required
permissions before any model call is made.
"""

from __future__ import annotations

from pathlib import Path

ACTION = (
    Path(__file__).resolve().parents[2]
    / ".github" / "actions" / "ai-agent-runner" / "action.yml"
)


def test_a10_runner_has_output_mode_allowlist() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert "ALLOWED_OUTPUT_MODES" in text, (
        "ai-agent-runner action.yml must define an ALLOWED_OUTPUT_MODES "
        "allowlist so unknown output-mode values fail fast at startup"
    )


def test_a10_runner_maps_modes_to_required_perms() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert "OUTPUT_MODE_REQUIRED_PERMS" in text or "required-perms" in text, (
        "ai-agent-runner action.yml must declare which permissions each "
        "output-mode requires so the startup check can detect mismatches"
    )
