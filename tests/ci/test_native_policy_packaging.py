# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CI coverage for native policy wheel composition."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_native_policy_wheels() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/ci/check_native_policy_wheels.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert completed.returncode == 0, (
        completed.stdout[-2000:] + completed.stderr[-2000:]
    )
    assert "native policy wheels OK" in completed.stdout
