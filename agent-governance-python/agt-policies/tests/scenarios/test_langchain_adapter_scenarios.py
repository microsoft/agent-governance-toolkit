# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LangChain adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`LangChainKernel` and
:class:`GovernanceMiddleware` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the LangChain handler is forwarded the original tool call.
- ``deny`` -> the middleware raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the middleware rewrites the tool arguments with the
  AGT D1.1 ``{path, value}`` payload before invoking the handler.
- ``escalate`` (resolver approves) -> the middleware forwards the call.
- ``escalate`` (no resolver) -> the middleware raises a deny.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: langchain_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: langchain_adapter_scenarios_adapter
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


def _make_tool_request(name: str = "search", args: dict[str, Any] | None = None) -> Any:
    request = MagicMock()
    request.tool_call = {
        "name": name,
        "args": args or {"query": "AI safety"},
        "id": "call_1",
    }
    return request


def _make_tool_result(content: str = "ok") -> Any:
    result = MagicMock()
    result.content = content
    return result


# ── verdict scenarios ────────────────────────────────────────────────


def test_wrap_tool_call_allow_path_forwards_to_handler(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the LangChain handler see the original call."""
    from agent_os.integrations.langchain_adapter import LangChainKernel

    runtime, policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # pre_tool_call
            {"decision": "allow"},  # output (post-execute)
        ],
    )
    kernel = LangChainKernel(_runtime=runtime)
    mw = kernel.as_middleware()
    handler = MagicMock(return_value=_make_tool_result("AI safety research"))

    result = mw.wrap_tool_call(_make_tool_request(), handler)

    handler.assert_called_once()
    assert result.content == "AI safety research"
    assert len(policy.invocations) == 2


def test_wrap_tool_call_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.langchain_adapter import (
        LangChainKernel,
        PolicyViolationError,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "tool_args_forbidden",
                "message": "search query is off limits",
            }
        ],
    )
    kernel = LangChainKernel(_runtime=runtime)
    mw = kernel.as_middleware()
    handler = MagicMock(return_value=_make_tool_result())

    with pytest.raises(PolicyViolationError) as excinfo:
        mw.wrap_tool_call(_make_tool_request(), handler)

    assert excinfo.value.check_result.reason == "tool_args_forbidden"
    handler.assert_not_called()


def test_wrap_tool_call_transform_path_rewrites_arguments(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the tool arguments."""
    from agent_os.integrations.langchain_adapter import LangChainKernel

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
    kernel = LangChainKernel(_runtime=runtime)
    mw = kernel.as_middleware()
    handler = MagicMock(return_value=_make_tool_result())

    request = _make_tool_request("search", {"query": "drop table users;"})
    mw.wrap_tool_call(request, handler)

    handler.assert_called_once()
    # The middleware rewrote ``request.tool_call["args"]`` before
    # forwarding it to the handler per AGT-DELTA D1.1.
    assert request.tool_call["args"] == {"query": "[SANITIZED]"}


def test_wrap_tool_call_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.langchain_adapter import LangChainKernel

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
    kernel = LangChainKernel(_runtime=runtime, approval_resolver=resolver)
    mw = kernel.as_middleware()
    handler = MagicMock(return_value=_make_tool_result())

    mw.wrap_tool_call(_make_tool_request(), handler)

    assert captured["ip"] == "pre_tool_call"
    assert captured["enforced_identity"] is not None
    handler.assert_called_once()


def test_wrap_tool_call_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.langchain_adapter import (
        LangChainKernel,
        PolicyViolationError,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = LangChainKernel(_runtime=runtime)
    mw = kernel.as_middleware()
    handler = MagicMock(return_value=_make_tool_result())

    with pytest.raises(PolicyViolationError):
        mw.wrap_tool_call(_make_tool_request(), handler)

    handler.assert_not_called()
