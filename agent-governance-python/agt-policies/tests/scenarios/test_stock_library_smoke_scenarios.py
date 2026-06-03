# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Stock library import scenarios.

Asserts that the AGT stock Rego library (M4.S1) is reachable from a
custom host-authored policy and that the helper packages compute the
expected verdicts when invoked. These are smoke tests rather than
behavior tests; they protect against accidental library breakage.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agt._harness.opa_runner import _find_stock_rego_root
from agt._harness.snapshot import pre_tool_call_snapshot


pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _run_custom_policy(
    tmp_path: Path,
    custom_rego_source: str,
    query: str,
    policy_input: dict,
) -> dict:
    """Render a tiny bundle with stock library + the custom policy and
    evaluate one query. Returns the verdict body."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    stock_root = _find_stock_rego_root()
    for rego in stock_root.glob("*.rego"):
        if rego.name.endswith("_test.rego"):
            continue
        (bundle / rego.name).write_text(rego.read_text(encoding="utf-8"))
    (bundle / "custom.rego").write_text(custom_rego_source, encoding="utf-8")

    proc = subprocess.run(  # noqa: S603 — trusted test harness
        ["opa", "eval", "--format", "json", "--stdin-input",
         "--data", str(bundle), query],
        input=json.dumps(policy_input),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, f"opa: {proc.stderr}"
    body = json.loads(proc.stdout)
    return body["result"][0]["expressions"][0]["value"]


def test_stock_budgets_library_loads(tmp_path: Path) -> None:
    """Smoke test: ensure the agt.budgets package is importable from a
    host policy and evaluates without error."""
    custom = """\
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.host
import rego.v1
import data.agt.budgets

over_limit := budgets.max_tool_calls_exceeded(10)
"""
    snap = pre_tool_call_snapshot(
        agent_id="x", tool_name="t", args={}, tool_call_count=15,
    )
    pi = {
        "intervention_point": "pre_tool_call",
        "policy_target": {"kind": "tool_args", "path": "$policy_target", "value": {}},
        "snapshot": snap,
        "annotations": {},
        "tool": {"name": "t"},
    }
    result = _run_custom_policy(tmp_path, custom, "data.agt.host.over_limit", pi)
    assert result is True


def test_stock_patterns_library_loads(tmp_path: Path) -> None:
    """Smoke test: ensure the agt.patterns package loads and the
    pii_patterns data set is non-empty."""
    custom = """\
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.host
import rego.v1
import data.agt.patterns

count_of_pii := count(patterns.pii_patterns)
"""
    pi = {
        "intervention_point": "input",
        "policy_target": {"kind": "input_body", "path": "$policy_target", "value": ""},
        "snapshot": {},
        "annotations": {},
        "tool": None,
    }
    result = _run_custom_policy(tmp_path, custom, "data.agt.host.count_of_pii", pi)
    # PII patterns: SSN, email, credit card, secrets, US phone (per
    # m4-stock-rego deliverable). count MUST be >= 4.
    assert isinstance(result, int) and result >= 4


def test_stock_egress_library_loads(tmp_path: Path) -> None:
    """Smoke test for the agt.egress package."""
    custom = """\
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.host
import rego.v1
import data.agt.egress

# Trivial reachability: package must compile and export at least one rule.
egress_module_loaded := true
"""
    pi = {
        "intervention_point": "input",
        "policy_target": {"kind": "input_body", "path": "$policy_target", "value": ""},
        "snapshot": {},
        "annotations": {},
        "tool": None,
    }
    assert _run_custom_policy(tmp_path, custom, "data.agt.host.egress_module_loaded", pi) is True


def test_stock_drift_confidence_approval_redact_load(tmp_path: Path) -> None:
    """Smoke test that the rest of the stock library (drift, confidence,
    approval, redact) imports cleanly together."""
    custom = """\
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.host
import rego.v1
import data.agt.drift
import data.agt.confidence
import data.agt.approval
import data.agt.redact

stock_libraries_load := true
"""
    pi = {
        "intervention_point": "input",
        "policy_target": {"kind": "input_body", "path": "$policy_target", "value": ""},
        "snapshot": {},
        "annotations": {},
        "tool": None,
    }
    assert _run_custom_policy(tmp_path, custom, "data.agt.host.stock_libraries_load", pi) is True


def test_stock_agt_ifc_library_uses_correct_paths(tmp_path: Path) -> None:
    """The agt.ifc library reads input.input.ifc.source_labels (AGT-
    correct path), not input.snapshot.ifc.source_labels. Verify it
    sees a label the test supplies at the AGT path."""
    custom = """\
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.host
import rego.v1
import data.agt.ifc

labels := ifc.source_labels
"""
    snap = {
        "envelope": {"agent": {"id": "x"}, "session": {"id": "s"}, "intervention_point": "input", "timestamp": "t"},
        "input": {"body": "...", "source": "user", "headers": {}, "ifc": {"source_labels": ["confidential", "internal"]}},
    }
    pi = {
        "intervention_point": "input",
        "policy_target": {"kind": "input_body", "path": "$policy_target", "value": "..."},
        "snapshot": snap,
        "annotations": {},
        "tool": None,
    }
    result = _run_custom_policy(tmp_path, custom, "data.agt.host.labels", pi)
    assert result == ["confidential", "internal"]
