# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT-DELTA D5 regression tests for the v5 runtime bridge.

After commit a19a7e09 the manifest bridge emits a v5-valid
``approval`` section (an empty object) whenever
``require_human_approval=True``. The bridge's
``_build_runtime`` MUST forward that section to the runtime so the
Rego's ``approval.escalate_if_approver_required`` rule can fire the
escalate verdict that the host's ``approval_resolver`` resolves
through ``AgtRuntime``. A previous defense
``manifest.pop("approval", None)`` stripped the section before the
runtime saw it, which silently suppressed approval routing for every
adapter using the bridge.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytest.importorskip("agent_control_specification")
pytest.importorskip("agt.policies.runtime")

from agent_os.integrations._v5_runtime_bridge import (  # noqa: E402
    _build_runtime,
    get_runtime_bridge,
)
from agent_os.integrations.base import GovernancePolicy  # noqa: E402


def _resolver_accept_all(_ip: str, result: Any) -> Any:
    from agt.policies.runtime import ApprovalDecision

    return ApprovalDecision.allow(result.enforced_identity)


def _approval_required_policy() -> GovernancePolicy:
    return GovernancePolicy(
        max_tool_calls=10,
        allowed_tools=["search"],
        require_human_approval=True,
    )


def _read_manifest_for(runtime: Any) -> dict[str, Any]:
    manifest_path = Path(runtime._manifest_path)
    return yaml.safe_load(manifest_path.read_text(encoding="utf-8"))


def test_build_runtime_writes_approval_section_when_required():
    """The runtime's manifest MUST carry ``approval: {}`` so the rego
    bridge's ``escalate_if_approver_required`` rule reaches the host
    approval path. Previously ``manifest.pop("approval", None)``
    stripped it.
    """
    runtime = _build_runtime(_approval_required_policy(), _resolver_accept_all)

    manifest = _read_manifest_for(runtime)
    assert "approval" in manifest, (
        "approval section was stripped before reaching AgtRuntime; "
        "regression of the dead `manifest.pop(\"approval\", None)` defense"
    )
    assert manifest["approval"] == {}


def test_build_runtime_omits_approval_section_when_not_required():
    """Without ``require_human_approval`` the bridge MUST NOT add an
    approval section (the manifest bridge only emits one when needed).
    """
    policy = GovernancePolicy(
        max_tool_calls=10,
        allowed_tools=["search"],
        require_human_approval=False,
    )
    runtime = _build_runtime(policy, None)
    manifest = _read_manifest_for(runtime)
    assert "approval" not in manifest


def test_build_runtime_escalate_routes_through_resolver(tmp_path: Path):
    """End-to-end smoke: an AgtRuntime built by ``_build_runtime`` with
    ``require_human_approval=True`` and a resolver MUST surface
    ``allow`` after the resolver approves an escalate verdict that the
    rego bridge's ``approval.escalate_if_approver_required`` rule fires.
    """
    captured: dict[str, Any] = {}

    def resolver(ip: str, result: Any) -> Any:
        from agt.policies.runtime import ApprovalDecision

        captured["ip"] = ip
        captured["enforced_identity"] = result.enforced_identity
        captured.setdefault("calls", 0)
        captured["calls"] += 1
        return ApprovalDecision.allow(result.enforced_identity)

    runtime = _build_runtime(_approval_required_policy(), resolver)

    snapshot = {
        "envelope": {"intervention_point": "pre_tool_call"},
        "tool_call": {"name": "search", "args": {"q": "AI"}, "id": "c1"},
    }
    evaluation = runtime.evaluate_intervention_point("pre_tool_call", snapshot)

    assert evaluation.verdict == "allow", (
        f"escalate -> resolver -> allow path broken; got {evaluation.verdict}: {evaluation.reason}"
    )
    assert captured.get("calls") == 1
    assert captured.get("ip") == "pre_tool_call"
    assert captured.get("enforced_identity"), (
        "AGT D1.4 enforced_identity must be handed to the resolver"
    )


def test_runtime_factory_bypasses_process_cache_for_equal_policies():
    """Test seams MUST NOT reuse a stale cached runtime from an equal policy."""
    policy = GovernancePolicy(max_tool_calls=3)
    calls: list[str] = []

    def first_factory(_policy: GovernancePolicy) -> str:
        calls.append("first")
        return "first-runtime"

    def second_factory(_policy: GovernancePolicy) -> str:
        calls.append("second")
        return "second-runtime"

    first = get_runtime_bridge(policy, runtime_factory=first_factory)
    second = get_runtime_bridge(
        GovernancePolicy(max_tool_calls=3),
        runtime_factory=second_factory,
    )

    assert first.runtime == "first-runtime"
    assert first.runtime == "first-runtime"
    assert second.runtime == "second-runtime"
    assert second.runtime == "second-runtime"
    assert calls == ["first", "second"]
