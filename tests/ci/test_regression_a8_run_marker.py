# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for red-team finding A8.

``RUN_MARKER`` originally embedded ``GITHUB_RUN_ATTEMPT`` so any maintainer
re-run produced a different marker. The aggregator step then could not find
prior agent comments, so AI summaries silently broke across re-runs.

Fix: derive ``RUN_MARKER`` from ``GITHUB_RUN_ID`` only -- one run, one marker
across all attempts.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "ai-pr-review.yml"
)


def test_a8_run_marker_is_stable_across_reruns() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    # Find every RUN_MARKER assignment line.
    matches = [
        line for line in text.splitlines()
        if re.search(r"\bRUN_MARKER\s*=", line)
    ]
    assert matches, "ai-pr-review.yml lost its RUN_MARKER assignment"
    for line in matches:
        assert "GITHUB_RUN_ATTEMPT" not in line, (
            f"RUN_MARKER must not embed GITHUB_RUN_ATTEMPT (breaks aggregator "
            f"on re-run): {line.strip()!r}"
        )
        assert "GITHUB_RUN_ID" in line, (
            f"RUN_MARKER must still scope by GITHUB_RUN_ID: {line.strip()!r}"
        )
