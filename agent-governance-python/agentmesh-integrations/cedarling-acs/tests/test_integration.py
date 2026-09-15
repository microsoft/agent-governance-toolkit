# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Live integration tests against the real cedarling-python engine.

Skipped unless ``cedarling-python`` is installed. Exercises the dispatcher
against the unsigned policy store shipped with the cedarling-governed example,
so it also guards that store from drift.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cedarling_python")

from cedarling_acs import CedarlingConfig, CedarlingPolicyDispatcher  # noqa: E402

# tests/ -> cedarling-acs -> agentmesh-integrations -> agent-governance-python -> repo root
_STORE = (
    Path(__file__).resolve().parents[4]
    / "examples"
    / "cedarling-governed"
    / "policy-stores"
    / "unsigned"
)


@pytest.fixture(scope="module")
def dispatcher() -> CedarlingPolicyDispatcher:
    if not _STORE.is_dir():
        pytest.skip(f"policy store not found at {_STORE}")
    return CedarlingPolicyDispatcher.from_bootstrap(
        {"CEDARLING_POLICY_STORE_LOCAL_FN": str(_STORE), "CEDARLING_LOG_TYPE": "off"},
        config=CedarlingConfig(namespace="AGT", auth_type="unsigned"),
    )


def _pi(agent_id: str, role: str, tool: str) -> dict:
    return {
        "input": {
            "intervention_point": "pre_tool_call",
            "policy_target": {"kind": "tool_args", "path": "$.tool_call.args", "value": {}},
            "snapshot": {"envelope": {"agent": {"id": agent_id, "attributes": {"role": role}}}},
            "annotations": {},
            "tool": {"name": tool, "clearance": "public"},
        }
    }


def test_admin_permitted(dispatcher):
    verdict = dispatcher.evaluate(_pi("agent-analyst", "admin", "read_data"))
    assert verdict["decision"] == "allow"


def test_guest_default_denied(dispatcher):
    verdict = dispatcher.evaluate(_pi("agent-guest", "guest", "read_data"))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "cedarling_deny"


def test_auditor_explicit_forbid_carries_policy_id(dispatcher):
    verdict = dispatcher.evaluate(_pi("agent-auditor", "auditor", "delete_file"))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "forbid-auditor-delete"
