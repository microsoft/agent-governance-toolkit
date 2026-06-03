# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AutoGen adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`AutoGenKernel` and
:class:`GovernanceInterventionHandler` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the FunctionCall is forwarded unchanged.
- ``deny`` -> the handler returns ``DropMessage``.
- ``transform`` -> the handler rewrites the FunctionCall ``arguments``
  with the AGT D1.1 ``{path, value}`` payload before forwarding.
- ``escalate`` (resolver approves) -> the handler forwards the message.
- ``escalate`` (no resolver) -> the handler returns ``DropMessage``.
"""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")


# ── Stub the autogen_core module if not installed ────────────────────
# Mirrors the stub in
# agent-os/tests/test_autogen_hooks.py so the scenario suite runs
# without AutoGen installed.

if "autogen_core" not in sys.modules:

    class _DropMessage:  # noqa: D401 — stub sentinel
        """Sentinel returned by intervention handlers to drop a message."""

        pass

    class _FunctionCall:  # noqa: D401 — stub matching AutoGen v0.4+ shape
        def __init__(self, id: str = "call-1", name: str = "", arguments: str = ""):
            self.id = id
            self.name = name
            self.arguments = arguments

    _autogen_core_mod = types.ModuleType("autogen_core")
    _autogen_core_mod.DropMessage = _DropMessage
    _autogen_core_mod.FunctionCall = _FunctionCall

    _intervention_mod = types.ModuleType("autogen_core.intervention")

    class _DefaultInterventionHandler:  # noqa: D401 — stub base class
        async def on_send(self, message, **kwargs):  # type: ignore[no-untyped-def]
            return message

    _intervention_mod.DefaultInterventionHandler = _DefaultInterventionHandler
    _autogen_core_mod.intervention = _intervention_mod

    sys.modules["autogen_core"] = _autogen_core_mod
    sys.modules["autogen_core.intervention"] = _intervention_mod


from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: autogen_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: autogen_adapter_scenarios_adapter
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


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_function_call(name: str = "search", arguments: str = '{"q":"x"}') -> Any:
    from autogen_core import FunctionCall

    return FunctionCall(id="call-1", name=name, arguments=arguments)


# ── verdict scenarios ────────────────────────────────────────────────


def test_on_send_allow_path_forwards_function_call(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the FunctionCall through unchanged."""
    from agent_os.integrations.autogen_adapter import AutoGenKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = AutoGenKernel(_runtime=runtime)
    handler = kernel.as_handler()

    fc = _make_function_call()
    result = _run(handler.on_send(fc))

    assert result is fc
    assert len(policy.invocations) == 1


def test_on_send_deny_path_drops_message(tmp_path: Path) -> None:
    """A ``deny`` verdict drops the FunctionCall."""
    from autogen_core import DropMessage

    from agent_os.integrations.autogen_adapter import AutoGenKernel

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
    kernel = AutoGenKernel(_runtime=runtime)
    handler = kernel.as_handler()

    fc = _make_function_call()
    result = _run(handler.on_send(fc))

    assert result is DropMessage


def test_on_send_transform_path_rewrites_function_call_arguments(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the FunctionCall arguments."""
    from agent_os.integrations.autogen_adapter import AutoGenKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"arguments": '{"q":"[SANITIZED]"}'},
                },
            }
        ],
    )
    kernel = AutoGenKernel(_runtime=runtime)
    handler = kernel.as_handler()

    fc = _make_function_call(arguments='{"q":"drop table users"}')
    result = _run(handler.on_send(fc))

    assert result is fc
    assert fc.arguments == '{"q":"[SANITIZED]"}'


def test_on_send_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the message."""
    from agent_os.integrations.autogen_adapter import AutoGenKernel

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
    kernel = AutoGenKernel(_runtime=runtime, approval_resolver=resolver)
    handler = kernel.as_handler()

    fc = _make_function_call()
    result = _run(handler.on_send(fc))

    assert captured["ip"] == "pre_tool_call"
    assert captured["enforced_identity"] is not None
    assert result is fc


def test_on_send_escalate_with_no_resolver_drops(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to drop."""
    from autogen_core import DropMessage

    from agent_os.integrations.autogen_adapter import AutoGenKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = AutoGenKernel(_runtime=runtime)
    handler = kernel.as_handler()

    fc = _make_function_call()
    result = _run(handler.on_send(fc))

    assert result is DropMessage
