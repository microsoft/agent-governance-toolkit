# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
import subprocess
import json
import os
from pathlib import Path
from src.agent_decisionassure.engine import ImpactEngine
from src.agent_decisionassure.cli import load_traces
import yaml


@pytest.fixture
def sample_traces(tmp_path):
    """Generate a small set of traces using the sample generator."""
    # We assume the generator script is at examples/decisionassure/generate_sample.py
    gen_path = Path("examples/decisionassure/generate_sample.py")
    if not gen_path.exists():
        pytest.skip("Sample generator not found; run from repo root")
    
    # Run the generator to create a temporary traces file
    traces_file = tmp_path / "traces.jsonl"
    # We could run the script, but it writes to a fixed path. Instead, we'll load the
    # existing sample_traces.jsonl if it exists.
    sample_file = Path("examples/decisionassure/sample_traces.jsonl")
    if sample_file.exists():
        # copy to tmp
        import shutil
        shutil.copy(sample_file, traces_file)
    else:
        pytest.skip("No sample traces file found")
    return traces_file


def test_end_to_end_replay(sample_traces):
    """Run the impact analysis on sample traces and verify we get a non-zero diff."""
    policy_v4 = Path("examples/decisionassure/policy_v4.yaml")
    policy_v5 = Path("examples/decisionassure/policy_v5.yaml")
    if not policy_v4.exists() or not policy_v5.exists():
        pytest.skip("Policy YAMLs not found")

    with open(policy_v4) as f:
        curr_policy = yaml.safe_load(f)
    with open(policy_v5) as f:
        prop_policy = yaml.safe_load(f)

    traces = load_traces(str(sample_traces))
    engine = ImpactEngine(traces)
    
    authority = {
        "delegations": [
            {
                "id": "delegation_123",
                "grantor": "admin",
                "grantee": "agent",
                "permissions": ["refund", "payment", "credit_decision", "aml_check"],
                "valid_from": "2026-01-01T00:00:00",
                "valid_until": "2027-01-01T00:00:00",
            }
        ],
        "global_tool_capabilities": {"payment-api": ["read", "write"]},
    }

    report = engine.analyze_impact(curr_policy, authority, prop_policy, authority)
    
    # At least some decisions should be affected if traces contain refund amounts > 40k.
    affected = report.transitions.admissible_to_inadmissible + report.transitions.inadmissible_to_admissible
    assert affected > 0, "Expected some decisions to be affected by the policy change"
    assert report.recommendation in ("BLOCK", "REVIEW")