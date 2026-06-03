# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CrewAI adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`CrewAIKernel` and the native
:class:`GovernanceHooks` (``before_tool_call`` / ``after_tool_call`` /
``before_llm_call`` / ``after_llm_call``) surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> ``before_tool_call`` returns ``None`` so CrewAI proceeds.
- ``deny`` -> ``before_tool_call`` returns ``False`` so CrewAI skips
  the tool.
- ``transform`` -> ``before_tool_call`` rewrites the tool input with
  the AGT D1.1 ``{path, value}`` payload before forwarding.
- ``escalate`` (resolver approves) -> ``before_tool_call`` returns
  ``None``.
- ``escalate`` (no resolver) -> ``before_tool_call`` returns ``False``.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")


# ── Stub crewai.hooks if not installed ──────────────────────────────
# Mirrors the stub in agent-os/tests/test_crewai_hooks.py so the
# scenario suite runs without CrewAI installed.

if "crewai" not in sys.modules:
    _registered: dict[str, list] = {
        "before_tool_call": [],
        "after_tool_call": [],
        "before_llm_call": [],
        "after_llm_call": [],
    }

    def _make_decorator(hook_name: str):
        def decorator(*dargs, **dkwargs):
            def wrap_fn(fn):
                _registered[hook_name].append(fn)
                return fn
            if len(dargs) == 1 and callable(dargs[0]) and not dkwargs:
                return wrap_fn(dargs[0])
            return wrap_fn
        return decorator

    crewai_mod = types.ModuleType("crewai")
    crewai_hooks_mod = types.ModuleType("crewai.hooks")
    crewai_hooks_mod.before_tool_call = _make_decorator("before_tool_call")
    crewai_hooks_mod.after_tool_call = _make_decorator("after_tool_call")
    crewai_hooks_mod.before_llm_call = _make_decorator("before_llm_call")
    crewai_hooks_mod.after_llm_call = _make_decorator("after_llm_call")
    crewai_mod.hooks = crewai_hooks_mod
    sys.modules["crewai"] = crewai_mod
    sys.modules["crewai.hooks"] = crewai_hooks_mod


from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: crewai_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: crewai_adapter_scenarios_adapter
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


class _ToolContext:
    """Stub CrewAI ToolCallHookContext."""

    def __init__(
        self,
        tool_name: str = "search",
        tool_input: Any = None,
    ):
        self.tool_name = tool_name
        self.tool_input = tool_input if tool_input is not None else {"q": "x"}
        self.tool_call_id = "call-1"
        self.agent = None
        self.task = None
        self.crew = None


# ── verdict scenarios ────────────────────────────────────────────────


def test_before_tool_call_allow_path_allows(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the CrewAI tool call through."""
    from agent_os.integrations.crewai_adapter import CrewAIKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = CrewAIKernel(_runtime=runtime)
    hooks = kernel.as_hooks(name=f"scenario-allow-{tmp_path.name}")
    hook_fn = hooks._make_before_tool_call()

    ctx = _ToolContext()
    result = hook_fn(ctx)

    assert result is None  # CrewAI proceeds with the tool call
    assert len(policy.invocations) == 1


def test_before_tool_call_deny_path_blocks(tmp_path: Path) -> None:
    """A ``deny`` verdict blocks the CrewAI tool call."""
    from agent_os.integrations.crewai_adapter import CrewAIKernel

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
    kernel = CrewAIKernel(_runtime=runtime)
    hooks = kernel.as_hooks(name=f"scenario-deny-{tmp_path.name}")
    hook_fn = hooks._make_before_tool_call()

    ctx = _ToolContext()
    result = hook_fn(ctx)

    assert result is False


def test_before_tool_call_transform_path_rewrites_input(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the CrewAI tool input."""
    from agent_os.integrations.crewai_adapter import CrewAIKernel

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
    kernel = CrewAIKernel(_runtime=runtime)
    hooks = kernel.as_hooks(name=f"scenario-transform-{tmp_path.name}")
    hook_fn = hooks._make_before_tool_call()

    ctx = _ToolContext(tool_input={"q": "drop table users"})
    result = hook_fn(ctx)

    assert result is None
    assert ctx.tool_input == {"q": "[SANITIZED]"}


def test_before_tool_call_escalate_with_approving_resolver_allows(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves passes the call."""
    from agent_os.integrations.crewai_adapter import CrewAIKernel

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
    kernel = CrewAIKernel(_runtime=runtime, approval_resolver=resolver)
    hooks = kernel.as_hooks(name=f"scenario-escalate-{tmp_path.name}")
    hook_fn = hooks._make_before_tool_call()

    ctx = _ToolContext()
    result = hook_fn(ctx)

    assert captured["ip"] == "pre_tool_call"
    assert captured["enforced_identity"] is not None
    assert result is None


def test_before_tool_call_escalate_with_no_resolver_blocks(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to block."""
    from agent_os.integrations.crewai_adapter import CrewAIKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = CrewAIKernel(_runtime=runtime)
    hooks = kernel.as_hooks(name=f"scenario-noresolver-{tmp_path.name}")
    hook_fn = hooks._make_before_tool_call()

    ctx = _ToolContext()
    result = hook_fn(ctx)

    assert result is False
