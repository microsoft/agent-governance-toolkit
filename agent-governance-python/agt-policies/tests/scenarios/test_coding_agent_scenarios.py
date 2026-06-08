# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Coding agent scenarios.

Covers diff-scope enforcement, restricted-path egress, and budget
exhaustion at the post_tool_call intervention point. Demonstrates the
non-tool intervention point binding via `output` for the assembled
review.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agt._harness.opa_runner import run_scenario
from agt._harness.snapshot import (
    post_tool_call_snapshot,
    pre_tool_call_snapshot,
)


pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _coding_governance() -> dict:
    """A coding agent that:
    - allows file_read on any file
    - denies file_write to env-y paths (secrets, .env)
    - escalates rm -rf-style commands
    - denies high-token model calls
    """
    return {
        "rules": [
            {
                "name": "deny_write_to_env_files",
                "condition": {
                    "field": "tool_call.args.path",
                    "operator": "matches",
                    "value": r"\.env|secrets/",
                },
                "action": "deny",
                "priority": 200,
                "message": "Writes to .env or secrets/ are blocked",
            },
            {
                "name": "escalate_destructive_shell",
                "condition": {
                    "field": "tool_call.args.command",
                    "operator": "matches",
                    "value": r"rm\s+-rf",
                },
                "action": "escalate",
                "priority": 150,
                "message": "Destructive shell command requires approval",
            },
            {
                "name": "deny_post_call_oversized_output",
                "condition": {
                    "field": "tool_result.duration_ms",
                    "operator": "gt",
                    "value": 30000,
                },
                "action": "deny",
                "priority": 100,
                "message": "Tool call exceeded duration budget",
            },
        ],
        "tools": {
            "file_write": {"clearance": "internal"},
            "shell": {"clearance": "confidential"},
            "tests_run": {"clearance": "internal"},
        },
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            },
            "post_tool_call": {
                "policy_target": "$.tool_result",
                "policy_target_kind": "tool_result",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            },
        },
    }


def test_file_write_to_env_file_is_denied(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="coder",
        tool_name="file_write",
        args={"path": ".env", "content": "API_KEY=xxx"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _coding_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_write_to_env_files"


def test_file_write_to_secrets_dir_is_denied(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="coder",
        tool_name="file_write",
        args={"path": "secrets/db.yaml", "content": "..."},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _coding_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_write_to_env_files"


def test_file_write_to_regular_path_is_allowed(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="coder",
        tool_name="file_write",
        args={"path": "src/lib/app.py", "content": "print('hi')"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _coding_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_allow


def test_rm_rf_escalates(tmp_path: Path) -> None:
    snap = pre_tool_call_snapshot(
        agent_id="coder",
        tool_name="shell",
        args={"command": "rm -rf /tmp/build"},
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _coding_governance()},
        intervention_point="pre_tool_call",
        snapshot=snap,
    )
    assert result.is_escalate
    assert result.reason == "escalate_destructive_shell"


def test_post_tool_call_too_long_is_denied(tmp_path: Path) -> None:
    """post_tool_call intervention point: deny when test run took over the budget."""
    snap = post_tool_call_snapshot(
        agent_id="coder",
        tool_name="tests_run",
        args={"suite": "all"},
        result={"passed": 100, "failed": 0},
        duration_ms=45000,
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _coding_governance()},
        intervention_point="post_tool_call",
        snapshot=snap,
    )
    assert result.is_deny
    assert result.reason == "deny_post_call_oversized_output"


def test_post_tool_call_fast_passes(tmp_path: Path) -> None:
    snap = post_tool_call_snapshot(
        agent_id="coder",
        tool_name="tests_run",
        args={"suite": "unit"},
        result={"passed": 50, "failed": 0},
        duration_ms=1500,
    )
    result = run_scenario(
        workspace_root=tmp_path,
        governance_yaml={"governance.yaml": _coding_governance()},
        intervention_point="post_tool_call",
        snapshot=snap,
    )
    assert result.is_allow
