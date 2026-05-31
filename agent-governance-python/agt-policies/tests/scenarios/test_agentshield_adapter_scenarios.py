# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Shield adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`AgentShieldKernel` surface
routed through :class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The Agent Shield SDK itself is mocked (so the suite does not depend on
``agent-shield`` being installed), and the AGT runtime is wired with a
scripted policy dispatcher so the suite does not depend on OPA on
``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back onto the ShieldVerdict / ToolCallVerdict surface:

- ``allow`` -> the verdict from the Agent Shield SDK is returned
  unchanged.
- ``deny`` -> the merged ShieldVerdict carries ``allowed=False``, the
  AGT reason, and ``metadata['source'] == 'agt_bridge'``.
- ``transform`` -> the merged ShieldVerdict carries the AGT D1.1
  ``{path, value}`` payload on ``modified_value``.
- ``escalate`` (resolver approves) -> the verdict is allowed after the
  resolver returns an allow.
- ``escalate`` (no resolver) -> the merged ShieldVerdict is denied.
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
  name: agentshield_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: agentshield_adapter_scenarios_adapter
intervention_points:
  input:
    policy_target: $.input.body
    policy_target_kind: user_input
    policy:
      id: scenario_policy
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: scenario_policy
  output:
    policy_target: $.response.content
    policy_target_kind: assistant_output
    policy:
      id: scenario_policy
tools:
  send_email:
    clearance: public
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


# ── verdict scenarios on validate_input ──────────────────────────────


def test_validate_input_allow_path_passes(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the Agent Shield input pass."""
    from agent_os.integrations.agentshield_adapter import (
        AgentShieldKernel,
        ShieldAction,
    )

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_input("Hello, world")

    assert verdict.allowed is True
    assert verdict.action == ShieldAction.ALLOW
    assert len(policy.invocations) == 1


def test_validate_input_deny_path_blocks(tmp_path: Path) -> None:
    """A ``deny`` verdict overrides the Agent Shield allow."""
    from agent_os.integrations.agentshield_adapter import (
        AgentShieldKernel,
        ShieldAction,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "blocked_user_input",
                "message": "input contains forbidden text",
            }
        ],
    )
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_input("share the password")

    assert verdict.allowed is False
    assert verdict.action == ShieldAction.BLOCK
    assert verdict.reason == "blocked_user_input"
    assert verdict.metadata.get("source") == "agt_bridge"
    assert verdict.metadata.get("agt_verdict") == "deny"


def test_validate_input_transform_path_sets_modified_value(tmp_path: Path) -> None:
    """A ``transform`` verdict surfaces the redacted text on the verdict."""
    from agent_os.integrations.agentshield_adapter import AgentShieldKernel

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
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_input("Customer SSN is 123-45-6789")

    assert verdict.allowed is True
    assert verdict.modified_value == "Customer SSN is [REDACTED]"


def test_validate_input_escalate_with_approving_resolver_passes(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves lets the input pass."""
    from agent_os.integrations.agentshield_adapter import AgentShieldKernel

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
    kernel = AgentShieldKernel.mock(_runtime=runtime, approval_resolver=resolver)

    verdict = kernel.validate_input("approve this please")

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    assert verdict.allowed is True


def test_validate_input_escalate_with_no_resolver_blocks(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to a block."""
    from agent_os.integrations.agentshield_adapter import (
        AgentShieldKernel,
        ShieldAction,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_input("needs approval")

    assert verdict.allowed is False
    assert verdict.action == ShieldAction.BLOCK
    assert verdict.metadata.get("source") == "agt_bridge"


# ── verdict scenarios on validate_tool_call ──────────────────────────


def test_validate_tool_call_transform_rewrites_parameters(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the tool parameters."""
    from agent_os.integrations.agentshield_adapter import AgentShieldKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"to": "[REDACTED]"},
                },
            }
        ],
    )
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_tool_call(
        "send_email", {"to": "user@example.com"}
    )

    assert verdict.allowed is True
    assert verdict.parameters == {"to": "[REDACTED]"}


def test_validate_tool_call_deny_blocks_tool_call(tmp_path: Path) -> None:
    """A ``deny`` verdict from AGT blocks the merged ToolCallVerdict."""
    from agent_os.integrations.agentshield_adapter import AgentShieldKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "tool_args_forbidden",
                "message": "args contain unsafe payload",
            }
        ],
    )
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_tool_call(
        "send_email", {"to": "user@example.com"}
    )

    assert verdict.allowed is False
    assert verdict.execution_verdict.allowed is False
    assert verdict.execution_verdict.metadata.get("source") == "agt_bridge"


# ── verdict scenarios on validate_output ─────────────────────────────


def test_validate_output_transform_redacts_response(tmp_path: Path) -> None:
    """A ``transform`` verdict on output sets ``modified_value``."""
    from agent_os.integrations.agentshield_adapter import AgentShieldKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "pii_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "Order processed for [REDACTED]",
                },
            }
        ],
    )
    kernel = AgentShieldKernel.mock(_runtime=runtime)

    verdict = kernel.validate_output("Order processed for SSN 123-45-6789")

    assert verdict.allowed is True
    assert verdict.modified_value == "Order processed for [REDACTED]"
