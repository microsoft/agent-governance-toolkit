# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MAF adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`MAFKernel` +
:class:`GovernancePolicyMiddleware` + :class:`CapabilityGuardMiddleware`
surface routed through :class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the MAF ``call_next`` continuation is awaited.
- ``deny`` -> the middleware raises
  :class:`MiddlewareTermination` carrying the canonical AGT reason.
- ``transform`` -> the middleware rewrites the most recent user message
  body / tool arguments with the AGT D1.1 ``{path, value}`` payload
  before forwarding the call.
- ``escalate`` (resolver approves) -> the middleware forwards the call.
- ``escalate`` (no resolver) -> the middleware raises a deny.
"""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

# The MAF adapter optionally imports agent_framework; provide a stub so
# the scenario suite can construct middleware classes without the SDK,
# mirroring the adapter's own except-ImportError fallback.
sys.modules.setdefault("agent_framework", types.ModuleType("agent_framework"))

from agt.policies import EvaluationResult  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: maf_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: maf_adapter_scenarios_adapter
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
  web_search:
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


def _make_agent_ctx(
    *,
    text: str = "Hello",
    agent_name: str = "test-agent",
) -> Any:
    msg = SimpleNamespace(role="user", text=text, contents=[text])
    return SimpleNamespace(
        agent=SimpleNamespace(name=agent_name),
        messages=[msg],
        stream=False,
        metadata={},
        result=None,
    )


def _make_function_ctx(
    *,
    func_name: str = "web_search",
    arguments: dict[str, Any] | None = None,
) -> Any:
    return SimpleNamespace(
        function=SimpleNamespace(name=func_name),
        arguments=arguments if arguments is not None else {"query": "weather"},
        result=None,
    )


# ── verdict scenarios: GovernancePolicyMiddleware (input intervention) ──


def test_policy_middleware_allow_path_invokes_next(tmp_path: Path) -> None:
    """An ``allow`` verdict lets MAF invoke the wrapped agent."""
    from agent_os.integrations.maf_adapter import (
        GovernancePolicyMiddleware,
        MAFKernel,
    )

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = MAFKernel(_runtime=runtime)
    mw = GovernancePolicyMiddleware(kernel=kernel)
    ctx = _make_agent_ctx(text="what is the weather today?")
    call_next = AsyncMock()

    asyncio.run(mw.process(ctx, call_next))

    call_next.assert_awaited_once()
    assert len(policy.invocations) == 1
    assert ctx.metadata["governance_decision"].allowed is True


def test_policy_middleware_deny_path_raises_termination(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`MiddlewareTermination`."""
    from agent_os.integrations.maf_adapter import (
        GovernancePolicyMiddleware,
        MAFKernel,
        MiddlewareTermination,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "user_blocked_topic",
                "message": "topic is off limits",
            }
        ],
    )
    kernel = MAFKernel(_runtime=runtime)
    mw = GovernancePolicyMiddleware(kernel=kernel)
    ctx = _make_agent_ctx(text="tell me about secrets")
    call_next = AsyncMock()

    with pytest.raises(MiddlewareTermination, match="user_blocked_topic"):
        asyncio.run(mw.process(ctx, call_next))

    call_next.assert_not_awaited()
    bridge_result = ctx.metadata["governance_decision"]
    assert bridge_result.allowed is False
    assert bridge_result.check_result.reason == "user_blocked_topic"


def test_policy_middleware_transform_path_rewrites_message(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the most recent user message body."""
    from agent_os.integrations.maf_adapter import (
        GovernancePolicyMiddleware,
        MAFKernel,
    )

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
    kernel = MAFKernel(_runtime=runtime)
    mw = GovernancePolicyMiddleware(kernel=kernel)
    ctx = _make_agent_ctx(text="Customer SSN is 123-45-6789")
    call_next = AsyncMock()

    asyncio.run(mw.process(ctx, call_next))

    call_next.assert_awaited_once()
    # The MAF Message body MUST carry the AGT-redacted text by the time
    # the next middleware (or the agent itself) sees it.
    last_msg = ctx.messages[-1]
    assert last_msg.text == "Customer SSN is [REDACTED]"
    assert last_msg.contents == ["Customer SSN is [REDACTED]"]


def test_policy_middleware_escalate_with_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.maf_adapter import (
        GovernancePolicyMiddleware,
        MAFKernel,
    )

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
    kernel = MAFKernel(_runtime=runtime, approval_resolver=resolver)
    mw = GovernancePolicyMiddleware(kernel=kernel)
    ctx = _make_agent_ctx(text="approve this please")
    call_next = AsyncMock()

    asyncio.run(mw.process(ctx, call_next))

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    call_next.assert_awaited_once()


def test_policy_middleware_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.maf_adapter import (
        GovernancePolicyMiddleware,
        MAFKernel,
        MiddlewareTermination,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = MAFKernel(_runtime=runtime)
    mw = GovernancePolicyMiddleware(kernel=kernel)
    ctx = _make_agent_ctx(text="needs approval")
    call_next = AsyncMock()

    with pytest.raises(MiddlewareTermination):
        asyncio.run(mw.process(ctx, call_next))

    call_next.assert_not_awaited()


# ── verdict scenarios: CapabilityGuardMiddleware (pre_tool_call) ───────


def test_capability_guard_transform_path_rewrites_arguments(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites ``context.arguments`` per AGT D1.1."""
    from agent_os.integrations.maf_adapter import (
        CapabilityGuardMiddleware,
        MAFKernel,
    )

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
            }
        ],
    )
    kernel = MAFKernel(_runtime=runtime)
    mw = CapabilityGuardMiddleware(kernel=kernel)
    ctx = _make_function_ctx(arguments={"query": "DROP TABLE users;"})

    captured: dict[str, Any] = {}

    async def _next() -> None:
        captured["args"] = ctx.arguments
        ctx.result = "ok"

    asyncio.run(mw.process(ctx, _next))

    # The wrapped tool MUST receive the AGT-redacted arguments.
    assert captured["args"] == {"query": "[SANITIZED]"}
