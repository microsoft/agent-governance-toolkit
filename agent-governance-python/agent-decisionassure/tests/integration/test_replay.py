# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
import subprocess
from pathlib import Path


def test_cli_impact():
    cwd = Path(__file__).parent.parent.parent.parent  # repo root
    traces = cwd / "examples/decisionassure/sample_traces.jsonl"
    if not traces.exists():
        pytest.skip("Sample traces not found; run generate_sample.py")
    
    policy4 = cwd / "examples/decisionassure/policy_v4.yaml"
    policy5 = cwd / "examples/decisionassure/policy_v5.yaml"
    if not policy4.exists() or not policy5.exists():
        pytest.skip("Policy YAMLs not found")
    
    result = subprocess.run(
        ["decisionassure", "impact", "--traces", str(traces), "--policy-current", str(policy4), "--policy-proposed", str(policy5)],
        capture_output=True,
        text=True,
        cwd=str(cwd)
    )
    assert result.returncode in (0, 1)
    assert "DECISIONASSURE IMPACT REPORT" in result.stdout
