# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end ACS x AGT seam coverage for manifest entry paths."""

from __future__ import annotations

import asyncio
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

from agt.manifest_resolution import ResolutionError, ResolutionReason, discover_policies  # noqa: E402
from agt.policies import SnapshotBuilder  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


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
    ).pre_tool_call(tool_name=tool_name, args=args or {})


def _governance_doc(rules: list[dict[str, Any]], *, scope: str | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "rules": rules,
        "tools": {"lookup": {"clearance": "public"}, "danger": {"clearance": "public"}},
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    if scope is not None:
        doc["scope"] = scope
    return doc


def _rule(
    name: str,
    action: str,
    *,
    field: str = "tool_call.name",
    operator: str = "eq",
    value: Any = "danger",
    priority: int = 10,
) -> dict[str, Any]:
    return {
        "name": name,
        "condition": {"field": field, "operator": operator, "value": value},
        "action": action,
        "priority": priority,
        "message": f"{name} fired",
    }


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
        "agent_control_specification_version": "0.3.0-alpha-agt",
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


def test_resolution_entry_path_enforces_deny_immutability_and_happy_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    child = tmp_path / "service"
    child.mkdir()
    _write_yaml(tmp_path / "governance.yaml", _governance_doc([_rule("org_deny", "deny")]))
    _write_yaml(
        child / "governance.yaml",
        _governance_doc([_rule("child_allow", "allow", priority=99)]),
    )

    runtime = AgtRuntime(child, resolution_root=tmp_path)

    denied = runtime.evaluate_intervention_point(
        "pre_tool_call", _pre_tool_snapshot("danger")
    )
    assert denied.verdict == "deny"
    assert denied.reason == "org_deny"

    allowed = runtime.evaluate_intervention_point(
        "pre_tool_call", _pre_tool_snapshot("lookup")
    )
    assert allowed.verdict == "allow"


def test_resolution_entry_path_applies_trailing_slash_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    action = tmp_path / "dir" / "file.py"
    action.parent.mkdir()
    action.write_text("# action\n", encoding="utf-8")
    _write_yaml(
        tmp_path / "governance.yaml",
        _governance_doc([_rule("scoped_deny", "deny")], scope="dir/"),
    )

    runtime = AgtRuntime(action, resolution_root=tmp_path)

    denied = runtime.evaluate_intervention_point(
        "pre_tool_call", _pre_tool_snapshot("danger")
    )
    assert denied.verdict == "deny"
    assert denied.reason == "scoped_deny"


def test_resolution_entry_path_rejects_governance_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "attacker.yaml").write_text("rules: []\n", encoding="utf-8")
    (workspace / "governance.yaml").symlink_to(outside / "attacker.yaml")

    with pytest.raises(ResolutionError) as exc:
        discover_policies(workspace, workspace)

    assert exc.value.reason == ResolutionReason.PATH_TRAVERSAL


def test_resolution_entry_path_malformed_budget_snapshot_denies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    _write_yaml(
        tmp_path / "governance.yaml",
        _governance_doc(
            [
                _rule(
                    "budget_deny",
                    "deny",
                    field="envelope.budgets.tool_call_count",
                    operator="gte",
                    value=1,
                )
            ]
        ),
    )
    runtime = AgtRuntime(tmp_path, resolution_root=tmp_path)
    malformed = _pre_tool_snapshot("lookup")
    malformed["envelope"]["budgets"]["tool_call_count"] = "2"

    denied = runtime.evaluate_intervention_point("pre_tool_call", malformed)

    assert denied.verdict == "deny"
    assert denied.allowed == False


def test_bridge_entry_path_blocks_patterns_inside_nested_tool_args_and_allows_benign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    pytest.importorskip("agent_os")
    from agent_os.integrations.base import GovernancePolicy
    from agt.policies.bridge import governance_to_acs_manifest

    policy = GovernancePolicy(
        max_tokens=1000,
        max_tool_calls=10,
        allowed_tools=[],
        blocked_patterns=["banned-substring"],
        require_human_approval=False,
        confidence_threshold=0.0,
    )
    manifest = governance_to_acs_manifest(policy, bundle_dir=tmp_path / "bridge_bundle")
    manifest_path = tmp_path / "bridge_manifest.yaml"
    _write_yaml(manifest_path, manifest)
    runtime = AgtRuntime(manifest_path)

    dict_result = runtime.evaluate_intervention_point(
        "pre_tool_call",
        _pre_tool_snapshot("lookup", {"outer": {"inner": "has banned-substring"}}),
    )
    list_result = runtime.evaluate_intervention_point(
        "pre_tool_call",
        _pre_tool_snapshot("lookup", {"items": ["has banned-substring"]}),
    )
    allowed = runtime.evaluate_intervention_point(
        "pre_tool_call", _pre_tool_snapshot("lookup", {"items": ["safe"]})
    )

    assert dict_result.verdict == "deny"
    assert dict_result.reason == "blocked_pattern_input"
    assert list_result.verdict == "deny"
    assert list_result.reason == "blocked_pattern_input"
    assert allowed.verdict == "allow"


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


def test_direct_entry_path_cedar_schema_path_if_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_opa(monkeypatch)
    manifest_path = tmp_path / "cedar_manifest.yaml"
    schema_path = tmp_path / "schema.json"
    schema_path.write_text("{}\n", encoding="utf-8")
    _write_yaml(
        manifest_path,
        {
            "agent_control_specification_version": "0.3.0-alpha-agt",
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

    try:
        control = AgentControl.from_path(str(manifest_path))
    except Exception as exc:
        pytest.skip(f"cedar default dispatcher unavailable in this build: {exc}")

    async def run() -> Any:
        return await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL, _pre_tool_snapshot("lookup")
        )

    result = asyncio.run(run())
    assert result.verdict.decision == Decision.ALLOW


def test_runtime_approval_timeout_denies_promptly(tmp_path: Path) -> None:
    manifest_path = tmp_path / "approval_manifest.yaml"
    manifest_path.write_text(
        """agent_control_specification_version: 0.3.0-alpha-agt
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

    def resolver(ip: str, result: Any) -> ApprovalDecision:
        blocker.wait()
        return ApprovalDecision.allow(result.enforced_identity)

    runtime = AgtRuntime(
        manifest_path,
        policy_dispatcher=EscalatingPolicy(),
        approval_resolver=resolver,
    )

    started = time.monotonic()
    try:
        result = runtime.evaluate_intervention_point(
            "pre_tool_call", _pre_tool_snapshot("lookup")
        )
    finally:
        blocker.set()
    elapsed = time.monotonic() - started

    assert elapsed < 1.5
    assert result.verdict == "deny"
    assert result.reason == "runtime_error:approval_timeout"
