# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Records / IFC and data classification scenarios.

Demonstrates information-flow control (IFC) and data classification
gating via the AGT-correct snapshot paths (input.ifc.source_labels,
not snapshot.ifc.*). Covers the no-write-down property: data marked
confidential cannot flow to a public sink.

These scenarios use rule conditions over IFC-shaped snapshot fields
to keep the test surface small; M5.S2 will add a parallel set that
imports the agt.ifc stock library directly.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agt._harness.opa_runner import run_scenario
from agt._harness.snapshot import input_snapshot, pre_tool_call_snapshot


pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _records_governance() -> dict:
    return {
        "rules": [
            {
                "name": "deny_external_egress_with_confidential_data",
                "condition": {
                    "field": "tool_call.args.classification",
                    "operator": "eq",
                    "value": "confidential",
                },
                "action": "deny",
                "priority": 200,
                "message": "Confidential records cannot be sent externally",
            },
            {
                "name": "deny_top_secret_at_input",
                "condition": {
                    "field": "input.body",
                    "operator": "contains",
                    "value": "TOP_SECRET",
                },
                "action": "deny",
                "priority": 200,
                "message": "TOP_SECRET classification refused at input",
            },
        ],
        "tools": {
            "send_external": {
                "clearance": "public",
                "security_labels": ["external"],
            },
            "store_internal": {
                "clearance": "confidential",
            },
        },
        "intervention_points": {
            "input": {
                "policy_target": "$.input.body",
                "policy_target_kind": "input_body",
                "policy": {"id": "agt_legacy_rules"},
            },
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            },
        },
    }


def test_confidential_record_to_external_sink_denied(tmp_path: Path) -> None:
    """The classic IFC no-write-down case: a confidential record
    cannot flow to a tool with public clearance."""
    snap = pre_tool_call_snapshot(
        agent_id="records",
        tool_name="send_external",
        args={"classification": "confidential", "patient_id": "P-001"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _records_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_external_egress_with_confidential_data"


def test_internal_record_to_internal_sink_allowed(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="records",
        tool_name="store_internal",
        args={"classification": "internal", "patient_id": "P-001"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _records_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow


def test_top_secret_refused_at_input(tmp_path: Path) -> None:
    """Input intervention point catches sensitive payloads before the
    agent loop begins."""
    snap = input_snapshot(
        agent_id="records",
        body="Process record TOP_SECRET project ABC",
        source="user",
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _records_governance()},
        intervention_point="input",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_top_secret_at_input"


def test_clean_input_passes(tmp_path: Path) -> None:
    snap = input_snapshot(
        agent_id="records",
        body="Please summarize patient encounter notes for review",
        source="user",
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _records_governance()},
        intervention_point="input",
        snapshot=snap,
    )
    assert result.is_allow
