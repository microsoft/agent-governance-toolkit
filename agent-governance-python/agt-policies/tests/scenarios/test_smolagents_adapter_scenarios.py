# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smolagents adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`SmolagentsKernel` and
:class:`GovernanceStepCallback` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> ``before_tool_call`` returns ``None`` and the step
  callback lets the smolagents step run.
- ``deny`` -> ``before_tool_call`` returns a block dict and the step
  callback raises :class:`PolicyViolationError`.
- ``transform`` -> ``before_tool_call`` rewrites the tool args in
  place with the AGT D1.1 ``{path, value}`` payload before forwarding.
- ``escalate`` (resolver approves) -> ``before_tool_call`` returns
  ``None``.
- ``escalate`` (no resolver) -> ``before_tool_call`` returns a block
  dict.
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
  name: smolagents_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: smolagents_adapter_scenarios_adapter
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
  search:
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


class _Step:
    """Stub smolagents MemoryStep with tool_calls and observation."""

    def __init__(self, tool_calls: list[Any] | None = None, observation: Any = None):
        self.tool_calls = tool_calls or []
        self.observation = observation


class _ToolCall:
    """Stub smolagents tool call with mutable ``tool_arguments``."""

    def __init__(self, tool_name: str = "search", tool_arguments: Any = None):
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments if tool_arguments is not None else {"q": "x"}


class _Agent:
    name = "scenario-agent"


# ── verdict scenarios on before_tool_call ────────────────────────────


def test_before_tool_call_allow_path_allows(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the smolagents tool call through."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = SmolagentsKernel(_runtime=runtime)

    result = kernel.before_tool_call(tool_name="search", tool_args={"q": "weather"})

    assert result is None
    assert len(policy.invocations) == 1


def test_before_tool_call_deny_path_blocks(tmp_path: Path) -> None:
    """A ``deny`` verdict blocks the smolagents tool call."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

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
    kernel = SmolagentsKernel(_runtime=runtime)

    result = kernel.before_tool_call(tool_name="search", tool_args={"q": "x"})

    assert result is not None
    assert result["policy"] == "agt_pre_tool_call"
    assert result["verdict"] == "deny"


def test_before_tool_call_transform_path_rewrites_args(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the smolagents tool args in place."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"q": "[SANITIZED]"},
                },
            }
        ],
    )
    kernel = SmolagentsKernel(_runtime=runtime)
    args: dict[str, Any] = {"q": "drop table users"}

    result = kernel.before_tool_call(tool_name="search", tool_args=args)

    assert result is None
    assert args == {"q": "[SANITIZED]"}


def test_before_tool_call_escalate_with_approving_resolver_allows(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves passes the call."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

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
    kernel = SmolagentsKernel(_runtime=runtime, approval_resolver=resolver)

    result = kernel.before_tool_call(tool_name="search", tool_args={"q": "x"})

    assert captured["ip"] == "pre_tool_call"
    assert captured["enforced_identity"] is not None
    assert result is None


def test_before_tool_call_escalate_with_no_resolver_blocks(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to a block."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = SmolagentsKernel(_runtime=runtime)

    result = kernel.before_tool_call(tool_name="search", tool_args={"q": "x"})

    assert result is not None
    assert result["policy"] == "agt_pre_tool_call"


# ── verdict scenarios on GovernanceStepCallback ──────────────────────


def test_step_callback_allow_path_allows(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the step callback succeed."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = SmolagentsKernel(_runtime=runtime)
    callback = kernel.as_step_callback()

    callback(_Step(tool_calls=[_ToolCall()]), _Agent())

    assert len(policy.invocations) == 1


def test_step_callback_deny_path_raises(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.smolagents_adapter import (
        PolicyViolationError,
        SmolagentsKernel,
    )

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
    kernel = SmolagentsKernel(_runtime=runtime)
    callback = kernel.as_step_callback()

    with pytest.raises(PolicyViolationError):
        callback(_Step(tool_calls=[_ToolCall()]), _Agent())


def test_step_callback_transform_path_rewrites_args(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the smolagents tool args in place."""
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"q": "[SANITIZED]"},
                },
            }
        ],
    )
    kernel = SmolagentsKernel(_runtime=runtime)
    callback = kernel.as_step_callback()
    tc = _ToolCall(tool_arguments={"q": "drop table users"})

    callback(_Step(tool_calls=[tc]), _Agent())

    assert tc.tool_arguments == {"q": "[SANITIZED]"}
