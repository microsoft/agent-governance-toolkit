# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Semantic Kernel adapter scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`SemanticKernelWrapper` /
:class:`GovernanceFunctionFilter` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the SK ``next(context)`` continuation is invoked
  verbatim.
- ``deny`` -> the filter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the filter rewrites ``context.arguments`` with the
  AGT D1.1 ``{path, value}`` payload before invoking the next filter.
- ``escalate`` (resolver approves) -> the filter forwards the call.
- ``escalate`` (no resolver) -> the filter raises a deny.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: semantic_kernel_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: semantic_kernel_adapter_scenarios_adapter
intervention_points:
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
  MyPlugin.safe_func:
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


def _make_sk_context(
    func_name: str = "safe_func",
    plugin_name: str = "MyPlugin",
    args: dict[str, Any] | None = None,
) -> Any:
    """Create a mock SK FunctionInvocationContext."""
    func = SimpleNamespace(name=func_name, plugin_name=plugin_name)
    ctx = SimpleNamespace(
        function=func,
        arguments=args if args is not None else {"query": "hello"},
        result=None,
    )
    return ctx


# ── verdict scenarios ────────────────────────────────────────────────


def test_filter_allow_path_invokes_next(tmp_path: Path) -> None:
    """An ``allow`` verdict lets SK invoke the wrapped function."""
    from agent_os.integrations.semantic_kernel_adapter import SemanticKernelWrapper

    runtime, policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # pre_tool_call
            {"decision": "allow"},  # output
        ],
    )
    wrapper = SemanticKernelWrapper(_runtime=runtime)
    sk_filter = wrapper.as_filter()
    ctx = _make_sk_context()

    async def _next(c: Any) -> None:
        c.result = "ok"

    asyncio.run(sk_filter(ctx, _next))

    assert ctx.result == "ok"
    assert len(policy.invocations) == 2


def test_filter_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict at pre_tool_call raises :class:`PolicyViolationError`."""
    from agent_os.integrations.semantic_kernel_adapter import (
        PolicyViolationError,
        SemanticKernelWrapper,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "tool_args_forbidden",
                "message": "function args are off limits",
            }
        ],
    )
    wrapper = SemanticKernelWrapper(_runtime=runtime)
    sk_filter = wrapper.as_filter()
    ctx = _make_sk_context()
    next_fn = AsyncMock()

    with pytest.raises(PolicyViolationError) as excinfo:
        asyncio.run(sk_filter(ctx, next_fn))

    assert excinfo.value.check_result.reason == "tool_args_forbidden"
    next_fn.assert_not_awaited()


def test_filter_transform_path_rewrites_arguments(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites ``context.arguments`` per AGT D1.1."""
    from agent_os.integrations.semantic_kernel_adapter import SemanticKernelWrapper

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "transform",
                "reason": "query_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"query": "[SANITIZED]"},
                },
            },
            {"decision": "allow"},  # output
        ],
    )
    wrapper = SemanticKernelWrapper(_runtime=runtime)
    sk_filter = wrapper.as_filter()
    ctx = _make_sk_context(args={"query": "DROP TABLE users;"})

    captured: dict[str, Any] = {}

    async def _next(c: Any) -> None:
        captured["args"] = c.arguments
        c.result = "done"

    asyncio.run(sk_filter(ctx, _next))

    # The filter MUST forward the AGT-redacted arguments to the SK
    # function rather than the original payload.
    assert captured["args"] == {"query": "[SANITIZED]"}


def test_filter_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.semantic_kernel_adapter import SemanticKernelWrapper

    captured: dict[str, Any] = {}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        captured["ip"] = ip
        captured["enforced_identity"] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {"decision": "escalate", "reason": "human_approval_required"},
            {"decision": "allow"},  # output
        ],
        approval_resolver=resolver,
    )
    wrapper = SemanticKernelWrapper(_runtime=runtime, approval_resolver=resolver)
    sk_filter = wrapper.as_filter()
    ctx = _make_sk_context()
    next_fn = AsyncMock()

    asyncio.run(sk_filter(ctx, next_fn))

    assert captured["ip"] == "pre_tool_call"
    assert captured["enforced_identity"] is not None
    next_fn.assert_awaited_once_with(ctx)


def test_filter_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.semantic_kernel_adapter import (
        PolicyViolationError,
        SemanticKernelWrapper,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    wrapper = SemanticKernelWrapper(_runtime=runtime)
    sk_filter = wrapper.as_filter()
    ctx = _make_sk_context()
    next_fn = AsyncMock()

    with pytest.raises(PolicyViolationError):
        asyncio.run(sk_filter(ctx, next_fn))

    next_fn.assert_not_awaited()


def test_governed_invoke_output_transform_rewrites_result(tmp_path: Path) -> None:
    """AGT-DELTA D1.1 regression: GovernedSemanticKernel.invoke MUST
    consume a Transform verdict at the output intervention point.
    Previously the post hook only consulted ``post_result.allowed`` and
    silently returned the original ``result``, so an output transform
    never reached the caller.
    """
    from agent_os.integrations.semantic_kernel_adapter import (
        SemanticKernelWrapper,
    )

    # Only the ``output`` intervention point reaches the scripted
    # dispatcher; ``pre_tool_call`` for the bare ``safe_func`` name
    # fails closed as ``runtime_error:tool_unknown`` and the bridge
    # rewrites it to allow because ``allowed_tools`` is empty (see
    # _v5_runtime_bridge._evaluate rewrite_as_allow branch).
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
            },
        ],
    )
    wrapper = SemanticKernelWrapper(_runtime=runtime)

    fake_function = SimpleNamespace(name="safe_func", plugin_name="MyPlugin")
    fake_result = "leaked secret"

    class _FakeKernel:
        async def invoke(self, function, **kwargs):  # noqa: ARG002
            return fake_result

    governed = wrapper.wrap(_FakeKernel())
    out = asyncio.run(governed.invoke(function=fake_function, input="hi"))

    assert out == "[REDACTED OUTPUT]", (
        f"AGT D1.1 output transform was dropped; got {out!r}"
    )

