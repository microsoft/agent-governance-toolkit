# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared helpers for OPA-backed migration scenarios."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


def eval_verdict(tmp_path: Path, rego_source: str, snapshot: dict) -> str:
    """Write a bundle, evaluate data.agt.legacy.verdict, and return its decision."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(exist_ok=True)
    (bundle / "agt_legacy.rego").write_text(rego_source, encoding="utf-8")
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "raw",
            "--stdin-input",
            "--data",
            str(bundle),
            "data.agt.legacy.verdict.decision",
        ],
        input=json.dumps({"snapshot": snapshot}),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, f"opa stderr: {proc.stderr}"
    return proc.stdout.strip().strip('"')
