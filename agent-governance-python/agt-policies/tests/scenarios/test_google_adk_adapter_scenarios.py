# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Google ADK adapter end-to-end scenarios on the AGT 5.0 ACS runtime.

These scenarios exercise the v4 :class:`GoogleADKKernel` callback
surface routed through :class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH`` or on ``google-adk`` being
installed (the kernel ships its own ``PolicyConfig`` shim).

Each test covers one of the AGT verdicts that the adapter must
translate back to its v4 callback surface:

- ``allow`` -> ``before_tool_callback`` returns ``None``.
- ``deny`` -> the callback returns a v4-shaped ``{"error": "..."}`` dict
  carrying the AGT reason.
- ``transform`` -> the callback mutates ``tool_context.tool_args``
  in-place (pre_tool_call) or rewrites the ``tool_result`` (output)
  with the AGT D1.1 ``{path, value}`` payload.
- ``escalate`` (resolver approves) -> the callback returns ``None``.
- ``escalate`` (no resolver) -> the callback returns an error dict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402,F401
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: google_adk_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: google_adk_adapter_scenarios_adapter
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
  delete_file:
    clearance: confidential
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


class _FakeToolContext:
    """Minimal fake of ADK's ``ToolContext`` for kernel callback tests."""

    def __init__(self, tool_name="search", tool_args=None, agent_name="agent"):
        self.tool_name = tool_name
        self.tool_args = tool_args if tool_args is not None else {}
        self.agent_name = agent_name


class _FakeCallbackContext:
    """Minimal fake of ADK's ``CallbackContext``."""

    def __init__(self, agent_name="root-agent", invocation_id="inv-001"):
        self.agent_name = agent_name
        self.invocation_id = invocation_id


def _kernel(runtime, *, approval_resolver=None):
    from agent_os.integrations.google_adk_adapter import GoogleADKKernel

    return GoogleADKKernel(
        _runtime=runtime,
        approval_resolver=approval_resolver,
    )


# ── verdict scenarios — pre_tool_call ────────────────────────────────


def test_before_tool_callback_allow_path(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the ADK tool execute."""
    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = _kernel(runtime)
    ctx = _FakeToolContext(tool_name="search", tool_args={"q": "AI"})

    result = kernel.before_tool_callback(ctx)

    assert result is None
    assert len(policy.invocations) == 1
    assert (
        policy.invocations[0]["input"]["intervention_point"] == "pre_tool_call"
    )


def test_before_tool_callback_deny_path(tmp_path: Path) -> None:
    """A ``deny`` verdict surfaces as a v4 ``{"error": ...}`` dict."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "tool_args_forbidden",
                "message": "query is off limits",
            }
        ],
    )
    kernel = _kernel(runtime)
    ctx = _FakeToolContext(tool_name="search", tool_args={"q": "secrets"})

    result = kernel.before_tool_callback(ctx)

    assert result is not None
    assert "error" in result
    assert "agt_pre_tool_call_deny" in result["error"]


def test_before_tool_callback_transform_rewrites_args(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites ``tool_context.tool_args``."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"q": "[REDACTED]"},
                },
            }
        ],
    )
    kernel = _kernel(runtime)
    ctx = _FakeToolContext(tool_name="search", tool_args={"q": "raw input"})

    result = kernel.before_tool_callback(ctx)

    assert result is None
    assert ctx.tool_args == {"q": "[REDACTED]"}


def test_before_tool_callback_escalate_with_resolver_passes(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves passes."""
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
    kernel = _kernel(runtime, approval_resolver=resolver)
    ctx = _FakeToolContext(tool_name="search", tool_args={"q": "AI"})

    result = kernel.before_tool_callback(ctx)

    assert captured["ip"] == "pre_tool_call"
    assert result is None


def test_before_tool_callback_escalate_with_no_resolver_denies(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = _kernel(runtime)
    ctx = _FakeToolContext(tool_name="search", tool_args={"q": "AI"})

    result = kernel.before_tool_callback(ctx)

    assert result is not None
    assert "error" in result


# ── verdict scenarios — output / agent ───────────────────────────────


def test_after_tool_callback_transform_rewrites_result(tmp_path: Path) -> None:
    """A ``transform`` verdict on the output rewrites ``tool_result``."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "output_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "[REDACTED OUTPUT]",
                },
            }
        ],
    )
    kernel = _kernel(runtime)
    ctx = _FakeToolContext(tool_name="search")

    result = kernel.after_tool_callback(ctx, tool_result="leaked secret")

    assert result == "[REDACTED OUTPUT]"


def test_after_tool_callback_deny_path(tmp_path: Path) -> None:
    """A ``deny`` verdict on the output returns a v4 error dict."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "deny", "reason": "output_blocked"}],
    )
    kernel = _kernel(runtime)
    ctx = _FakeToolContext(tool_name="search")

    result = kernel.after_tool_callback(ctx, tool_result="secret payload")

    assert isinstance(result, dict)
    assert "error" in result
    assert "agt_output_deny" in result["error"]


def test_before_agent_callback_deny_blocks_agent(tmp_path: Path) -> None:
    """A ``deny`` verdict on agent invocation blocks the agent."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "deny", "reason": "agent_blocked"}],
    )
    kernel = _kernel(runtime)
    ctx = _FakeCallbackContext(agent_name="suspicious-agent")

    result = kernel.before_agent_callback(callback_context=ctx)

    assert isinstance(result, dict)
    assert "error" in result
    assert "agt_input_deny" in result["error"]


def test_after_agent_callback_transform_rewrites_content(tmp_path: Path) -> None:
    """A ``transform`` verdict on agent output rewrites content."""
    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "output_redaction",
                "transform": {
                    "path": "$policy_target",
                    "value": "[SANITISED AGENT OUTPUT]",
                },
            }
        ],
    )
    kernel = _kernel(runtime)
    ctx = _FakeCallbackContext()

    result = kernel.after_agent_callback(
        callback_context=ctx, content="leaked secret"
    )

    assert result == "[SANITISED AGENT OUTPUT]"
