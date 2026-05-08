# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for tutorial example demos.

These tests run each example demo as a subprocess and verify that:
1. The script exits with code 0 (no crashes)
2. Key expected output strings appear (correct behavior)

These complement unit tests by validating the public-facing examples work.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


def _run_demo(script: Path, timeout: int = 30) -> str:
    """Run a demo script and return its combined stdout+stderr."""
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(REPO_ROOT),
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"Demo {script.name} failed:\n{output}"
    return result.stdout


# ---------------------------------------------------------------------------
# Intent-Based Authorization Demo
# ---------------------------------------------------------------------------


class TestIntentAuthDemo:
    SCRIPT = EXAMPLES / "intent-auth" / "intent_auth_demo.py"

    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        if not self.SCRIPT.exists():
            pytest.skip(f"{self.SCRIPT} not found")

    def test_exits_cleanly(self):
        output = _run_demo(self.SCRIPT)
        assert "Demo complete!" in output

    def test_intent_lifecycle(self):
        output = _run_demo(self.SCRIPT)
        assert "declared" in output.lower()
        assert "approved" in output.lower()

    def test_drift_detection(self):
        output = _run_demo(self.SCRIPT)
        assert "DRIFT" in output
        assert "trust" in output.lower()

    def test_hard_block(self):
        output = _run_demo(self.SCRIPT)
        assert "BLOCKED" in output

    def test_child_scope(self):
        output = _run_demo(self.SCRIPT)
        assert "valid subset" in output.lower() or "Child scope" in output
        assert "cannot expand" in output.lower() or "Scope violation" in output


# ---------------------------------------------------------------------------
# Multi-Agent Collective Policy Demo
# ---------------------------------------------------------------------------


class TestMultiAgentPolicyDemo:
    SCRIPT = EXAMPLES / "multi-agent-governance" / "multi_agent_policy_demo.py"

    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        if not self.SCRIPT.exists():
            pytest.skip(f"{self.SCRIPT} not found")

    def test_exits_cleanly(self):
        output = _run_demo(self.SCRIPT)
        assert "Demo complete!" in output

    def test_rate_limit_enforcement(self):
        output = _run_demo(self.SCRIPT)
        assert "ALLOWED" in output
        assert "DENIED" in output

    def test_config_loading(self):
        output = _run_demo(self.SCRIPT)
        assert "Loaded 2 policies" in output

    def test_window_stats(self):
        output = _run_demo(self.SCRIPT)
        assert "Actions in last" in output
        assert "Unique agents" in output


# ---------------------------------------------------------------------------
# Decision BOM Demo
# ---------------------------------------------------------------------------


class TestDecisionBOMDemo:
    SCRIPT = EXAMPLES / "decision-bom" / "decision_bom_demo.py"

    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        if not self.SCRIPT.exists():
            pytest.skip(f"{self.SCRIPT} not found")

    def test_exits_cleanly(self):
        output = _run_demo(self.SCRIPT)
        assert "Demo complete!" in output

    def test_partial_bom_lower_completeness(self):
        output = _run_demo(self.SCRIPT)
        assert "Partial BOM" in output
        assert "60%" in output

    def test_full_bom_higher_completeness(self):
        output = _run_demo(self.SCRIPT)
        assert "Full BOM" in output
        assert "100%" in output

    def test_batch_reconstruction(self):
        output = _run_demo(self.SCRIPT)
        assert "Reconstructed 2 decisions" in output

    def test_json_export(self):
        output = _run_demo(self.SCRIPT)
        assert "JSON Export" in output
        assert "fields" in output.lower()


# ---------------------------------------------------------------------------
# Cost Governance Demo
# ---------------------------------------------------------------------------


class TestCostGovernanceDemo:
    SCRIPT = EXAMPLES / "cost-governance" / "cost_governance_demo.py"

    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        if not self.SCRIPT.exists():
            pytest.skip(f"{self.SCRIPT} not found")

    def test_exits_cleanly(self):
        output = _run_demo(self.SCRIPT)
        assert "Demo complete!" in output

    def test_pre_check_enforcement(self):
        output = _run_demo(self.SCRIPT)
        assert "allowed=True" in output
        assert "allowed=False" in output

    def test_alert_escalation(self):
        output = _run_demo(self.SCRIPT)
        assert "WARNING" in output
        assert "CRITICAL" in output

    def test_kill_switch(self):
        output = _run_demo(self.SCRIPT)
        assert "KILLED" in output or "killed=True" in output

    def test_org_budget(self):
        output = _run_demo(self.SCRIPT)
        assert "Organization Budget" in output or "Org budget" in output
        assert "BLOCKED" in output

    def test_anomaly_detection(self):
        output = _run_demo(self.SCRIPT)
        assert "Anomaly detected" in output
