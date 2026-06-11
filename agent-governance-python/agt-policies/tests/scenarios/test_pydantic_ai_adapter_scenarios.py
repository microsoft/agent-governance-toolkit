# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""PydanticAI adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`PydanticAIKernel` and
:class:`GovernanceCapability` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the PydanticAI tool / prompt is forwarded verbatim.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the adapter rewrites the outbound tool arguments or
  prompt with the AGT D1.1 ``{path, value}`` payload before invoking
  the wrapped agent.
- ``escalate`` (resolver approves) -> the adapter forwards the call.
- ``escalate`` (no resolver) -> the adapter raises a deny.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: pydantic_ai_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: pydantic_ai_adapter_scenarios_adapter
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


# ── verdict scenarios ────────────────────────────────────────────────


def test_before_run_allow_path_forwards_prompt(tmp_path: Path) -> None:
    """An ``allow`` verdict on input returns the original prompt unchanged."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = PydanticAIKernel(_runtime=runtime)
    capability = kernel.as_capability()

    result = capability.before_run("what is the weather today?")

    assert result == "what is the weather today?"
    assert len(policy.invocations) == 1


def test_before_run_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.pydantic_ai_adapter import (
        PolicyViolationError,
        PydanticAIKernel,
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
    kernel = PydanticAIKernel(_runtime=runtime)
    capability = kernel.as_capability()

    with pytest.raises(PolicyViolationError) as excinfo:
        capability.before_run("tell me about secrets")

    assert excinfo.value.check_result.reason == "user_blocked_topic"


def test_before_run_transform_path_rewrites_prompt(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the outbound prompt."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

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
    kernel = PydanticAIKernel(_runtime=runtime)
    capability = kernel.as_capability()

    rewritten = capability.before_run("Customer SSN is 123-45-6789")

    # PydanticAI's before_run hook returns the prompt PydanticAI will
    # actually send to the model; the transform replaces it per AGT D1.1.
    assert rewritten == "Customer SSN is [REDACTED]"


def test_before_run_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the prompt."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

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
    kernel = PydanticAIKernel(_runtime=runtime, approval_resolver=resolver)
    capability = kernel.as_capability()

    result = capability.before_run("approve this please")

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    assert result == "approve this please"


def test_before_run_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.pydantic_ai_adapter import (
        PolicyViolationError,
        PydanticAIKernel,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = PydanticAIKernel(_runtime=runtime)
    capability = kernel.as_capability()

    with pytest.raises(PolicyViolationError):
        capability.before_run("needs approval")


def test_before_tool_execute_transform_rewrites_arguments(tmp_path: Path) -> None:
    """A ``transform`` verdict at pre_tool_call rewrites tool arguments."""
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

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
    kernel = PydanticAIKernel(_runtime=runtime)
    capability = kernel.as_capability()

    rewritten = capability.before_tool_execute(
        "search", {"query": "drop table users;"}
    )

    # The capability returns the AGT-rewritten arguments dict so
    # PydanticAI invokes the tool with the redacted payload.
    assert rewritten == {"query": "[SANITIZED]"}


def test_before_tool_execute_escalate_routes_through_resolver(
    tmp_path: Path,
) -> None:
    """AGT-DELTA D5 regression: when ``require_human_approval=True`` and
    an ``approval_resolver`` is wired, the AGT escalate path MUST drive
    the resolver at ``pre_tool_call``. Previously the adapter swapped to
    a no-approval ``_approved_bridge`` after the legacy
    ``approval_callback`` ran, so the AGT resolver never saw the call
    and the bisected enforced_identity (AGT-DELTA D1.4) never propagated.
    """
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

    captured: dict[str, Any] = {}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        captured.setdefault("calls", 0)
        captured["calls"] += 1
        captured["ip"] = ip
        captured["enforced_identity"] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=resolver,
    )
    policy = GovernancePolicy(require_human_approval=True)
    kernel = PydanticAIKernel(
        policy=policy,
        _runtime=runtime,
        approval_resolver=resolver,
        approval_callback=None,
    )
    capability = kernel.as_capability()

    forwarded = capability.before_tool_execute("search", {"q": "weather"})

    # The bridge returned escalate, the resolver approved, and the
    # capability forwards the arguments unchanged because the bridge
    # never swapped to a sibling no-approval bridge.
    assert forwarded == {"q": "weather"}
    assert captured.get("calls") == 1, (
        "AGT resolver must be invoked exactly once for the escalate verdict"
    )
    assert captured.get("ip") == "pre_tool_call"
    assert captured.get("enforced_identity"), (
        "AGT D1.4 enforced_identity must be handed to the resolver"
    )


def test_before_tool_execute_no_resolver_falls_back_to_legacy_callback(
    tmp_path: Path,
) -> None:
    """When ``approval_resolver`` is absent, the v4 ``approval_callback``
    path remains in effect. This preserves backwards compatibility for
    kernels that only configured the legacy callback.
    """
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

    callback_calls: dict[str, Any] = {}

    def callback(tool_name: str, args: dict[str, Any]) -> bool:
        callback_calls["tool"] = tool_name
        callback_calls["args"] = args
        return True

    runtime, _policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    policy = GovernancePolicy(require_human_approval=True)
    kernel = PydanticAIKernel(
        policy=policy,
        _runtime=runtime,
        approval_callback=callback,
        approval_resolver=None,
    )
    capability = kernel.as_capability()

    forwarded = capability.before_tool_execute("search", {"q": "weather"})

    assert forwarded is None or forwarded == {"q": "weather"}
    assert callback_calls.get("tool") == "search"
