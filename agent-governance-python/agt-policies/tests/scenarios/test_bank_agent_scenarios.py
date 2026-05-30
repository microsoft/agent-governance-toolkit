# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Bank agent scenarios.

Proposes a policy, sets up an agent, runs evaluation, asserts the
expected verdicts. Demonstrates AGT 5.0 end-to-end through the
resolution layer and the OPA dispatcher.

Each test reads as: (1) describe what behaviour we want to enforce,
(2) declare the policy in YAML (the same YAML a user would write),
(3) run a scenario through the engine, (4) assert.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agt._harness.opa_runner import run_scenario
from agt._harness.snapshot import (
    pre_tool_call_snapshot,
)


pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


# ── Wire-transfer dollar-limit gate ─────────────────────────────────


def _bank_governance() -> dict:
    """Policy: wire_transfer over $100k is denied; high tool-call count
    triggers an escalation."""
    return {
        "rules": [
            {
                "name": "block_large_wire_transfer",
                "condition": {
                    "field": "tool_call.args.amount_usd",
                    "operator": "gt",
                    "value": 100000,
                },
                "action": "deny",
                "priority": 100,
                "message": "Wire transfers over USD 100000 are not permitted",
            },
            {
                "name": "escalate_after_many_calls",
                "condition": {
                    "field": "envelope.budgets.tool_call_count",
                    "operator": "gte",
                    "value": 20,
                },
                "action": "escalate",
                "priority": 50,
                "message": "Many tool calls without checkpoint",
            },
        ],
        "tools": {
            "wire_transfer": {
                "clearance": "confidential",
                "security_labels": ["financial", "external"],
            }
        },
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }


def test_wire_transfer_under_limit_is_allowed(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="bank-agent",
        tool_name="wire_transfer",
        args={"amount_usd": 5000, "to": "acct-42"},
        tool_call_count=3,
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _bank_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow, f"expected allow, got {result.raw}"


def test_wire_transfer_at_limit_boundary_is_allowed(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="bank-agent",
        tool_name="wire_transfer",
        args={"amount_usd": 100000, "to": "acct-42"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _bank_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    # rule is gt (not gte) so 100000 is allowed
    assert result.is_allow


def test_wire_transfer_over_limit_is_denied(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="bank-agent",
        tool_name="wire_transfer",
        args={"amount_usd": 250000, "to": "acct-42"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _bank_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "block_large_wire_transfer"
    assert result.message == "Wire transfers over USD 100000 are not permitted"


def test_budget_exhaustion_escalates(tmp_path: Path) -> None:
    """At 20+ tool calls without checkpoint, the engine escalates per the
    secondary rule. This validates the AGT-side stateful counter feeding
    into the snapshot (Q5/Q3 sub-decision)."""
    snap = pre_tool_call_snapshot(
        agent_id="bank-agent",
        tool_name="wire_transfer",
        args={"amount_usd": 100, "to": "acct-42"},
        tool_call_count=25,
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _bank_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_escalate
    assert result.reason == "escalate_after_many_calls"


def test_priority_higher_rule_wins_when_both_match(tmp_path: Path) -> None:
    """Big transfer AND many tool calls should match both rules. The
    higher-priority deny (100) wins over the lower-priority escalate (50).
    """
    snap = pre_tool_call_snapshot(
        agent_id="bank-agent",
        tool_name="wire_transfer",
        args={"amount_usd": 250000, "to": "acct-42"},
        tool_call_count=25,
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _bank_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "block_large_wire_transfer"


# ── Deny-immutability invariant in the AGT resolution layer ──────────


def test_child_override_cannot_defeat_parent_deny(tmp_path: Path) -> None:
    """AGT-RESOLUTION §2.4: a child rule with override:true and the same
    name as a parent deny MUST be dropped during merge. The parent deny
    survives evaluation."""
    parent = {
        "rules": [
            {
                "name": "block_large_wire_transfer",
                "condition": {
                    "field": "tool_call.args.amount_usd",
                    "operator": "gt",
                    "value": 100000,
                },
                "action": "deny",
                "priority": 100,
                "message": "Org-level deny",
            }
        ],
        "tools": {"wire_transfer": {"clearance": "confidential"}},
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    # Child tries to allow what parent denies, via override:true at higher priority
    child = {
        "rules": [
            {
                "name": "block_large_wire_transfer",
                "condition": {
                    "field": "tool_call.args.amount_usd",
                    "operator": "gt",
                    "value": 100000,
                },
                "action": "allow",
                "priority": 200,
                "override": True,
                "message": "Child tries to override; should be dropped",
            }
        ],
    }

    snap = pre_tool_call_snapshot(
        agent_id="bank-agent",
        tool_name="wire_transfer",
        args={"amount_usd": 999999, "to": "acct-42"},
    )

    # Place child governance file in a subdirectory; the resolution
    # layer should keep the parent deny and drop the child override.
    (tmp_path / "subdir").mkdir()
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={
            "governance.yaml": parent,
            "subdir/governance.yaml": child,
        },
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny, f"parent deny MUST survive child override; got {result.raw}"
    assert result.reason == "block_large_wire_transfer"
