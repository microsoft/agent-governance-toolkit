# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A2A adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`A2AGovernanceAdapter` surface
routed through :class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the task is permitted.
- ``deny`` -> ``evaluate_task`` returns ``allowed=False`` with the AGT
  reason.
- ``transform`` -> ``evaluate_task`` returns ``allowed=True`` with the
  AGT D1.1 ``{path, value}`` payload exposed on
  :attr:`A2AEvaluation.transform_value` so the host can rewrite the
  outbound task content.
- ``escalate`` (resolver approves) -> the task is permitted after the
  resolver returns an allow.
- ``escalate`` (no resolver) -> the task is denied with the AGT
  ``human_approval_required`` reason.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: a2a_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: a2a_adapter_scenarios_adapter
intervention_points:
  input:
    policy_target: $.input.body
    policy_target_kind: user_input
    policy:
      id: scenario_policy
"""


class _ScriptedPolicy:
    """Tiny ACS PolicyDispatcher that returns a scripted verdict per call."""

    def __init__(self, verdicts: list[dict[str, Any]]):
        self._verdicts = list(verdicts)
        self.invocations: list[dict[str, Any]] = []

    def evaluate(self, invocation):  # type: ignore[no-untyped-def]
        self.invocations.append(dict(invocation))
        if not self._verdicts:
            raise AssertionError(
                "ScriptedPolicy ran out of verdicts; test wired too few."
            )
        return self._verdicts.pop(0)


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(_MANIFEST, encoding="utf-8")
    return path


def _build_runtime(
    tmp_path: Path,
    verdicts: list[dict[str, Any]],
    *,
    approval_resolver=None,
) -> tuple[AgtRuntime, _ScriptedPolicy]:
    policy = _ScriptedPolicy(verdicts)
    runtime = AgtRuntime(
        _write_manifest(tmp_path),
        policy_dispatcher=policy,
        approval_resolver=approval_resolver,
    )
    return runtime, policy


def _make_task(text: str = "Find weather") -> dict[str, Any]:
    return {
        "id": "task-001",
        "skill_id": "search",
        "status": {"state": "submitted"},
        "x-agentmesh-trust": {
            "source_did": "did:mesh:agent-a",
            "source_trust_score": 500,
        },
        "messages": [
            {"role": "user", "parts": [{"text": text}]},
        ],
    }


# ── verdict scenarios ────────────────────────────────────────────────


def test_evaluate_task_allow_path_passes(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the A2A task through."""
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    adapter = A2AGovernanceAdapter(_runtime=runtime)

    result = adapter.evaluate_task(_make_task("hello"))

    assert result.allowed is True
    assert result.transform_value is None
    assert len(policy.invocations) == 1


def test_evaluate_task_deny_path_blocks(tmp_path: Path) -> None:
    """A ``deny`` verdict blocks the A2A task."""
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "blocked_a2a_payload",
                "message": "payload contains forbidden content",
            }
        ],
    )
    adapter = A2AGovernanceAdapter(_runtime=runtime)

    result = adapter.evaluate_task(_make_task("share the password"))

    assert result.allowed is False
    assert "blocked_a2a_payload" in result.reason
    assert result.bridge_result is not None
    assert result.bridge_result.verdict == "deny"


def test_evaluate_task_transform_path_captures_redaction(tmp_path: Path) -> None:
    """A ``transform`` verdict surfaces a redacted payload to the host."""
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "pii_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "Customer SSN is [REDACTED]",
                },
            }
        ],
    )
    adapter = A2AGovernanceAdapter(_runtime=runtime)

    result = adapter.evaluate_task(_make_task("Customer SSN is 123-45-6789"))

    assert result.allowed is True
    assert result.transform_value == "Customer SSN is [REDACTED]"


def test_evaluate_task_escalate_with_approving_resolver_passes(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves lets the task through."""
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    captured: dict[str, Any] = {}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        captured["ip"] = ip
        captured["enforced_identity"] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=resolver,
    )
    adapter = A2AGovernanceAdapter(_runtime=runtime, approval_resolver=resolver)

    result = adapter.evaluate_task(_make_task("approve this please"))

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    assert result.allowed is True


def test_evaluate_task_escalate_with_no_resolver_blocks(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    adapter = A2AGovernanceAdapter(_runtime=runtime)

    result = adapter.evaluate_task(_make_task("needs approval"))

    assert result.allowed is False
    assert result.bridge_result is not None
    assert result.bridge_result.verdict == "deny"
