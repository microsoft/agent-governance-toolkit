# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Negative-operator fail-closed scenarios (#3297).

The render-level assertions in ``tests/test_manifest_resolution.py`` prove
the emitted Rego *shape*. These scenarios push the emitted policy through
OPA so the end-to-end verdict is locked, not just the rendered string.

Two fail-open paths are covered:
  - A ``deny`` rule on ``ne``/``not_in`` did not fire when the field was
    absent, so a caller bypassed the deny simply by omitting the field.
  - A missing *intermediate* path segment left the accessor undefined
    rather than ``null``, silently failing the match for every operator.

Polarity is asserted too: the ``_v != null`` guard is dropped only for
``deny``. An ``allow`` on a negative operator must still not fire on a
missing field, or it would preempt a later deny in the first-match chain.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agt._harness.opa_runner import run_scenario
from agt._harness.snapshot import pre_tool_call_snapshot


pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _intervention_points() -> dict:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


# ── deny + ne ───────────────────────────────────────────────────────


def _deny_ne_governance(field: str = "tool_call.args.env") -> dict:
    """Deny anything whose env is not exactly "sandbox"."""
    return {
        "rules": [
            {
                "name": "deny_non_sandbox_env",
                "condition": {"field": field, "operator": "ne", "value": "sandbox"},
                "action": "deny",
                "priority": 100,
                "message": "only the sandbox env is permitted",
            }
        ],
        "tools": {"deploy": {"security_labels": ["external"]}},
        "intervention_points": _intervention_points(),
    }


def test_deny_ne_fires_when_field_is_missing(tmp_path: Path) -> None:
    """The bypass: omitting the field must not dodge the deny."""
    snap = pre_tool_call_snapshot(agent_id="ci", tool_name="deploy", args={})
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _deny_ne_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_non_sandbox_env"


def test_deny_ne_fires_when_field_differs(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="ci", tool_name="deploy", args={"env": "production"}
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _deny_ne_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_non_sandbox_env"


def test_deny_ne_does_not_fire_when_field_matches(tmp_path: Path) -> None:
    """Fail-closed must not become fire-always."""
    snap = pre_tool_call_snapshot(
        agent_id="ci", tool_name="deploy", args={"env": "sandbox"}
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _deny_ne_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert not result.is_deny


def test_deny_ne_fires_when_intermediate_segment_is_missing(tmp_path: Path) -> None:
    """The array-path accessor fix: a missing parent object resolves to
    null, not undefined, so the deny still fires."""
    snap = pre_tool_call_snapshot(agent_id="ci", tool_name="deploy", args={})
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={
            "governance.yaml": _deny_ne_governance(field="tool_call.args.meta.env")
        },
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_non_sandbox_env"


# ── deny + not_in ───────────────────────────────────────────────────


def _deny_not_in_governance() -> dict:
    """Deny any region outside the approved allowlist."""
    return {
        "rules": [
            {
                "name": "deny_region_outside_allowlist",
                "condition": {
                    "field": "tool_call.args.region",
                    "operator": "not_in",
                    "value": ["eu-west-1", "eu-central-1"],
                },
                "action": "deny",
                "priority": 100,
                "message": "region is not on the approved allowlist",
            }
        ],
        "tools": {"provision": {"security_labels": ["external"]}},
        "intervention_points": _intervention_points(),
    }


def test_deny_not_in_fires_when_field_is_missing(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(agent_id="ci", tool_name="provision", args={})
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _deny_not_in_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_region_outside_allowlist"


def test_deny_not_in_fires_when_value_is_outside_allowlist(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="ci", tool_name="provision", args={"region": "us-east-1"}
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _deny_not_in_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny


def test_deny_not_in_does_not_fire_for_allowlisted_value(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="ci", tool_name="provision", args={"region": "eu-west-1"}
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _deny_not_in_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert not result.is_deny


# ── polarity: allow keeps the null guard ────────────────────────────


def _allow_ne_preemption_governance() -> dict:
    """A higher-priority allow on a negative operator sits in front of a
    deny. If the allow fired on a missing field it would preempt the deny
    in the first-match chain, which is the fail-open this guards against.
    """
    return {
        "rules": [
            {
                "name": "allow_non_blocked_service",
                "condition": {
                    "field": "tool_call.args.service",
                    "operator": "ne",
                    "value": "blocked",
                },
                "action": "allow",
                "priority": 100,
                "message": "service is not on the blocklist",
            },
            {
                "name": "deny_all_deploys",
                "condition": {
                    "field": "tool_call.name",
                    "operator": "eq",
                    "value": "deploy",
                },
                "action": "deny",
                "priority": 50,
                "message": "deploys are denied unless explicitly allowed",
            },
        ],
        "tools": {"deploy": {"security_labels": ["external"]}},
        "intervention_points": _intervention_points(),
    }


def test_allow_ne_does_not_preempt_deny_when_field_is_missing(tmp_path: Path) -> None:
    """Missing field must not satisfy the allow, so the deny still wins."""
    snap = pre_tool_call_snapshot(agent_id="ci", tool_name="deploy", args={})
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _allow_ne_preemption_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_all_deploys"


def test_allow_ne_preempts_deny_when_field_is_present(tmp_path: Path) -> None:
    """With the field present the allow legitimately wins on priority."""
    snap = pre_tool_call_snapshot(
        agent_id="ci", tool_name="deploy", args={"service": "billing"}
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _allow_ne_preemption_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow
    assert result.reason == "allow_non_blocked_service"
