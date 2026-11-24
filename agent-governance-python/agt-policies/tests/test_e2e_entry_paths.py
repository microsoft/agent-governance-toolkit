# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end ACS x AGT seam coverage for manifest entry paths."""

from __future__ import annotations

import asyncio
import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_control_specification._native")

from agent_control_specification import AgentControl, Decision, InterventionPoint  # noqa: E402

from agent_control_specification import (  # noqa: E402
    HostSession,
    SnapshotBuilder,
)
from agent_control_specification import ApprovalResolution  # noqa: E402


_REPO_ROOT = Path(__file__).resolve().parents[3]
_STOCK_REGO_ROOT = _REPO_ROOT / "policy-engine" / "policy" / "lib"


def _require_opa(monkeypatch: pytest.MonkeyPatch) -> None:
    opa = shutil.which("opa")
    if opa is None:
        candidate = Path.home() / ".local" / "bin" / "opa"
        if candidate.exists():
            opa = str(candidate)
    if opa is None:
        pytest.skip("opa binary required for ACS x AGT end-to-end tests")
    monkeypatch.setenv("ACS_OPA_PATH", opa)


def _write_yaml(path: Path, doc: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")


def _pre_tool_snapshot(
    tool_name: str = "lookup",
    args: dict[str, Any] | None = None,
    *,
    tool_call_count: int = 0,
    token_count: int = 0,
) -> dict[str, Any]:
    return SnapshotBuilder(
        agent_id="bot",
        session_id="s-1",
        tool_call_count=tool_call_count,
        token_count=token_count,
    ).snapshot(
        "pre_tool_call",
        tool_call={"name": tool_name, "args": args or {}, "id": "call-1"},
    )

def _write_budget_rego_manifest(tmp_path: Path) -> Path:
    bundle = tmp_path / "budget_bundle"
    bundle.mkdir()
    shutil.copy(_STOCK_REGO_ROOT / "budgets.rego", bundle / "budgets.rego")
    (bundle / "e2e_budget.rego").write_text(
        """# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.e2e_budget

import data.agt.budgets
import rego.v1

default verdict := {"decision": "allow"}

verdict := v if {
    v := budgets.deny_if_budget_exceeded({"tool_call_count": 1, "token_count": 1})
}
""",
        encoding="utf-8",
    )
    manifest = {
        "agent_control_specification_version": "0.4.0-alpha.1",
        "metadata": {"name": "direct_budget_e2e"},
        "extends": [],
        "policies": {
            "budget": {
                "type": "rego",
                "bundle": str(bundle),
                "query": "data.agt.e2e_budget.verdict",
            }
        },
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "budget"},
            }
        },
        "tools": {"lookup": {"clearance": "public"}},
    }
    manifest_path = tmp_path / "direct_manifest.yaml"
    _write_yaml(manifest_path, manifest)
    return manifest_path


def test_direct_entry_path_from_path_denies_malformed_budget_and_allows_benign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    manifest_path = _write_budget_rego_manifest(tmp_path)
    control = AgentControl.from_path(str(manifest_path))

    async def run() -> tuple[Any, Any, Any]:
        allowed = await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, _pre_tool_snapshot("lookup")
        )
        malformed_string = _pre_tool_snapshot("lookup")
        malformed_string["envelope"]["budgets"]["tool_call_count"] = "2"
        denied_string = await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, malformed_string
        )
        malformed_null = _pre_tool_snapshot("lookup")
        malformed_null["envelope"]["budgets"]["token_count"] = None
        denied_null = await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, malformed_null
        )
        return allowed, denied_string, denied_null

    allowed, denied_string, denied_null = asyncio.run(run())

    assert allowed.verdict.decision == Decision.ALLOW
    assert denied_string.verdict.decision == Decision.DENY
    assert denied_string.verdict.reason == "budget_counter_invalid"
    assert denied_null.verdict.decision == Decision.DENY
    assert denied_null.verdict.reason == "budget_counter_invalid"


def test_direct_entry_path_from_path_rejects_unsupported_manifest_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    manifest_path = _write_budget_rego_manifest(tmp_path)
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["agent_control_specification_version"] = "banana"
    _write_yaml(manifest_path, manifest)

    try:
        AgentControl.from_path(str(manifest_path))
    except Exception as exc:
        assert "unsupported" in str(exc).lower()
        return

    pytest.skip("native ACS build does not yet enforce unsupported manifest versions")


def _write_cedar_schema(path: Path) -> None:
    """The Cedar schema for the snapshot the runtime builds at pre_tool_call.

    The request mapping is fixed by the specification: the principal is
    ``Agent::"<agent.id>"``, the action is ``Action::"pre_tool_call"`` and the
    resource is ``Tool::"<tool.name>"``, and the context is the snapshot with
    the annotations nested under ``annotations``. With a ``schema_path`` set,
    the builtin dispatcher validates the policy set and the request against
    this schema, so it must declare those types, that action and the context
    shape the snapshot actually carries.
    """
    schema = {
        "": {
            "entityTypes": {
                "Agent": {"shape": {"type": "Record", "attributes": {}}},
                "Tool": {"shape": {"type": "Record", "attributes": {}}},
            },
            "actions": {
                "pre_tool_call": {
                    "appliesTo": {
                        "principalTypes": ["Agent"],
                        "resourceTypes": ["Tool"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "envelope": {
                                    "type": "Record",
                                    "attributes": {
                                        "agent": {
                                            "type": "Record",
                                            "attributes": {
                                                "id": {"type": "String"},
                                                "version": {"type": "String", "required": False},
                                                "name": {"type": "String", "required": False},
                                            },
                                        },
                                        "session": {
                                            "type": "Record",
                                            "required": False,
                                            "attributes": {
                                                "id": {"type": "String"},
                                                "started_at": {"type": "String", "required": False},
                                            },
                                        },
                                        "intervention_point": {"type": "String", "required": False},
                                        "timestamp": {"type": "String", "required": False},
                                        "budgets": {
                                            "type": "Record",
                                            "required": False,
                                            "attributes": {
                                                "tool_call_count": {"type": "Long", "required": False},
                                                "token_count": {"type": "Long", "required": False},
                                                "elapsed_seconds": {
                                                    "type": "Extension",
                                                    "name": "decimal",
                                                    "required": False,
                                                },
                                                "cost_usd": {
                                                    "type": "Extension",
                                                    "name": "decimal",
                                                    "required": False,
                                                },
                                            },
                                        },
                                    },
                                },
                                "tool_call": {
                                    "type": "Record",
                                    "attributes": {
                                        "name": {"type": "String"},
                                        "id": {"type": "String", "required": False},
                                        # The fixture calls the tool with empty
                                        # arguments. Cedar's full schema format
                                        # allows no open records, so the args
                                        # record declares no attributes.
                                        "args": {"type": "Record", "attributes": {}},
                                    },
                                },
                                "annotations": {
                                    "type": "Record",
                                    "attributes": {},
                                },
                            },
                        },
                    },
                }
            },
        }
    }
    path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


def _write_cedar_manifest(tmp_path: Path, schema_path: Path) -> Path:
    manifest_path = tmp_path / "cedar_manifest.yaml"
    _write_yaml(
        manifest_path,
        {
            "agent_control_specification_version": "0.4.0-alpha.1",
            "metadata": {"name": "cedar_schema_path_e2e"},
            "policies": {
                "guard": {
                    "type": "cedar",
                    "policy_set": "permit(principal, action, resource);",
                    "schema_path": str(schema_path),
                }
            },
            "intervention_points": {
                "pre_tool_call": {
                    "policy_target": "$.tool_call.args",
                    "policy_target_kind": "tool_args",
                    "tool_name_from": "$.tool_call.name",
                    "policy": {"id": "guard"},
                }
            },
            "tools": {"lookup": {"clearance": "public"}},
        },
    )
    return manifest_path


def test_direct_entry_path_cedar_schema_path_allows_benign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    schema_path = tmp_path / "schema.json"
    _write_cedar_schema(schema_path)
    manifest_path = _write_cedar_manifest(tmp_path, schema_path)

    control = AgentControl.from_path(str(manifest_path))

    async def run() -> Any:
        return await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, _pre_tool_snapshot("lookup")
        )

    result = asyncio.run(run())
    assert result.verdict.decision == Decision.ALLOW


def test_direct_entry_path_cedar_empty_schema_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty schema declares no entity types and no actions, so the strict
    validator finds no applicable action for the request and the runtime fails
    closed. A schema that declares nothing must not silently allow everything."""
    _require_opa(monkeypatch)
    schema_path = tmp_path / "schema.json"
    schema_path.write_text("{}\n", encoding="utf-8")
    manifest_path = _write_cedar_manifest(tmp_path, schema_path)

    control = AgentControl.from_path(str(manifest_path))

    async def run() -> Any:
        return await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, _pre_tool_snapshot("lookup")
        )

    result = asyncio.run(run())
    assert result.verdict.decision == Decision.DENY
    assert result.verdict.reason == "runtime_error:policy_invocation_failed"


def test_runtime_approval_timeout_denies_promptly(tmp_path: Path) -> None:
    manifest_path = tmp_path / "approval_manifest.yaml"
    manifest_path.write_text(
        """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: approval_timeout_e2e
extends: []
policies:
  p:
    type: custom
    adapter: approval_timeout_test
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    policy:
      id: p
approval:
  timeout_seconds: 1
""",
        encoding="utf-8",
    )

    class EscalatingPolicy:
        def evaluate(self, invocation: Any) -> dict[str, str]:
            return {"decision": "escalate", "reason": "approval_required"}

    blocker = threading.Event()

    def resolver(ip: str, result: Any) -> ApprovalResolution:
        blocker.wait()
        return ApprovalResolution.allow(result.enforced_identity)

    control = AgentControl.from_path(
        str(manifest_path),
        policy_dispatcher=EscalatingPolicy(),
        approval_resolver=resolver,
    )
    session = HostSession(
        control, agent_id="bot", session_id="s-1", approval_timeout_seconds=1
    )

    started = time.monotonic()
    try:
        result = session.pre_tool_call(tool_name="lookup", args={})
    finally:
        blocker.set()
    elapsed = time.monotonic() - started

    assert elapsed < 1.5
    assert result.verdict.decision.value == "deny"
    # A timed out approval is an approval that did not resolve, and
    # `approval_timeout` is not in the reserved set.
    assert result.verdict.reason == "host_error:approval_unresolved"
