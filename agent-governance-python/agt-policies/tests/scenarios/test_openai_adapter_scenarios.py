# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenAI adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`OpenAIKernel` /
:class:`GovernedAssistant` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the OpenAI message is forwarded verbatim.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the adapter rewrites the outbound message with the
  AGT D1.1 ``{path, value}`` payload before calling the OpenAI client.
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

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: openai_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: openai_adapter_scenarios_adapter
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
  get_weather:
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


def _make_openai_client() -> MagicMock:
    client = MagicMock()
    msg = MagicMock()
    msg.id = "msg_xyz"
    client.beta.threads.messages.create.return_value = msg
    return client


def _make_assistant() -> MagicMock:
    assistant = MagicMock()
    assistant.id = "asst_test"
    return assistant


# ── verdict scenarios ────────────────────────────────────────────────


def test_add_message_allow_path_forwards_to_openai(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the OpenAI client see the original content."""
    from agent_os.integrations.openai_adapter import OpenAIKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = OpenAIKernel(_runtime=runtime)
    client = _make_openai_client()
    governed = kernel.wrap(_make_assistant(), client)

    governed.add_message("thread_1", "what is the weather today?")

    assert len(policy.invocations) == 1
    client.beta.threads.messages.create.assert_called_once()
    sent = client.beta.threads.messages.create.call_args.kwargs
    assert sent["content"] == "what is the weather today?"


def test_add_message_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.openai_adapter import OpenAIKernel, PolicyViolationError

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
    kernel = OpenAIKernel(_runtime=runtime)
    client = _make_openai_client()
    governed = kernel.wrap(_make_assistant(), client)

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.add_message("thread_1", "tell me about secrets")

    assert excinfo.value.check_result.reason == "user_blocked_topic"
    client.beta.threads.messages.create.assert_not_called()


def test_add_message_transform_path_redacts_outbound_content(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the outbound message body."""
    from agent_os.integrations.openai_adapter import OpenAIKernel

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
    kernel = OpenAIKernel(_runtime=runtime)
    client = _make_openai_client()
    governed = kernel.wrap(_make_assistant(), client)

    governed.add_message("thread_1", "Customer SSN is 123-45-6789")

    client.beta.threads.messages.create.assert_called_once()
    sent = client.beta.threads.messages.create.call_args.kwargs
    # The OpenAI SDK MUST see the redacted text, not the original.
    assert sent["content"] == "Customer SSN is [REDACTED]"


def test_add_message_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.openai_adapter import OpenAIKernel

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
    kernel = OpenAIKernel(_runtime=runtime, approval_resolver=resolver)
    client = _make_openai_client()
    governed = kernel.wrap(_make_assistant(), client)

    governed.add_message("thread_1", "approve this please")

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    client.beta.threads.messages.create.assert_called_once()


def test_add_message_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.openai_adapter import OpenAIKernel, PolicyViolationError

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = OpenAIKernel(_runtime=runtime)
    client = _make_openai_client()
    governed = kernel.wrap(_make_assistant(), client)

    with pytest.raises(PolicyViolationError):
        governed.add_message("thread_1", "needs approval")

    client.beta.threads.messages.create.assert_not_called()
