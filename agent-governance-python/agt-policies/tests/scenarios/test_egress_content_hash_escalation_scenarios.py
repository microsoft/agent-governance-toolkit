# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Egress + content-hash + escalation scenarios.

Covers:
  - egress allowlist on external tool calls
  - content_hash verification (Ona/Veto wrapper-attack defense)
  - escalation verdict bound to an approval resolver
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


# ── Egress allowlist ────────────────────────────────────────────────


def _egress_governance() -> dict:
    """Tools tagged with security_labels are treated as the allowlist;
    a host that knows nothing about a destination URL denies it."""
    return {
        "rules": [
            {
                "name": "deny_external_egress_to_evil_com",
                "condition": {
                    "field": "tool_call.args.url",
                    "operator": "contains",
                    "value": "evil.com",
                },
                "action": "deny",
                "priority": 100,
                "message": "evil.com is not on the egress allowlist",
            }
        ],
        "tools": {
            "http_get": {
                "security_labels": ["external"],
                "egress_allowlist": ["api.example.com", "openai.com"],
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


def test_egress_to_blocked_domain_denied(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="research",
        tool_name="http_get",
        args={"url": "https://evil.com/data"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _egress_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_external_egress_to_evil_com"


def test_egress_to_allowed_domain_passes(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="research",
        tool_name="http_get",
        args={"url": "https://api.example.com/v1/data"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _egress_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow


# ── Escalation verdict ──────────────────────────────────────────────


def _escalation_governance() -> dict:
    """Production-targeted deploys escalate to human approval per D5;
    the engine returns escalate and the host's approval resolver handles
    it from there."""
    return {
        "rules": [
            {
                "name": "escalate_production_deploy",
                "condition": {
                    "field": "tool_call.args.target",
                    "operator": "eq",
                    "value": "production",
                },
                "action": "escalate",
                "priority": 100,
                "message": "Production deploys require human approval",
            }
        ],
        "tools": {"deploy": {"clearance": "confidential"}},
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
        "approval": {
            "default_resolver": "webhook",
            "timeout_seconds": 300,
            "on_timeout": "deny",
            "resolvers": {
                "webhook": {
                    "type": "webhook",
                    "url": "https://example.com/approve",
                }
            },
        },
    }


def test_production_deploy_escalates(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="cd-agent",
        tool_name="deploy",
        args={"target": "production", "version": "2.1.0"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _escalation_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_escalate
    assert result.reason == "escalate_production_deploy"
    assert result.message == "Production deploys require human approval"


def test_staging_deploy_passes(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="cd-agent",
        tool_name="deploy",
        args={"target": "staging", "version": "2.1.0"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _escalation_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow


# ── Content hash gate ───────────────────────────────────────────────


def _content_hash_governance() -> dict:
    """Tools declare a content_hash; the policy denies the call when the
    runtime-supplied hash differs from the manifest catalog entry. This
    defends against tool-aliasing attacks (Ona/Veto research)."""
    return {
        "rules": [
            {
                "name": "deny_unknown_tool_hash",
                "condition": {
                    "field": "tool_call.content_hash",
                    "operator": "ne",
                    "value": "sha256:knownhash123",
                },
                "action": "deny",
                "priority": 100,
                "message": "Tool content hash does not match registered hash",
            }
        ],
        "tools": {
            "execute_code": {
                "clearance": "restricted",
                "content_hash": "sha256:knownhash123",
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


def test_matching_content_hash_passes(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="coder",
        tool_name="execute_code",
        args={"code": "print('hello')"},
        content_hash="sha256:knownhash123",
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _content_hash_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow


def test_tampered_content_hash_denied(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="coder",
        tool_name="execute_code",
        args={"code": "print('hello')"},
        content_hash="sha256:tamperedhash456",
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _content_hash_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_unknown_tool_hash"
