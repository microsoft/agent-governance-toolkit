# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Mistral adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`MistralKernel` /
:class:`GovernedMistralClient` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH``.

Each test covers one of the five AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the Mistral client sees the original chat() payload.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the adapter rewrites the outbound message content
  with the AGT D1.1 ``{path, value}`` payload before calling chat().
- ``escalate`` (resolver approves) -> the adapter forwards the call.
- ``escalate`` (no resolver) -> the adapter raises a deny.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

# The Mistral adapter has a hard import-time guard on ``mistralai`` for
# ``kernel.wrap(client)``. Stub the module so the scenarios run without
# the real SDK, mirroring the agent-os tests/test_provider_adapters.py
# pattern.
sys.modules.setdefault("mistralai", types.ModuleType("mistralai"))

import agent_os.integrations.mistral_adapter as _mistral_adapter_mod  # noqa: E402

_mistral_adapter_mod._HAS_MISTRAL = True

from agt.policies import EvaluationResult  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: mistral_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: mistral_adapter_scenarios_adapter
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


def _make_client() -> MagicMock:
    client = MagicMock()
    resp = MagicMock()
    resp.id = "chatcmpl-xyz"
    resp.usage.prompt_tokens = 10
    resp.usage.completion_tokens = 20
    resp.choices = []
    client.chat.return_value = resp
    return client


# ── verdict scenarios ────────────────────────────────────────────────


def test_chat_allow_path_forwards_to_mistral(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the Mistral client see the original message."""
    from agent_os.integrations.mistral_adapter import MistralKernel

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = MistralKernel(_runtime=runtime)
    client = _make_client()
    governed = kernel.wrap(client)

    governed.chat(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": "what is the weather today?"}],
    )

    assert len(policy.invocations) == 1
    client.chat.assert_called_once()
    sent = client.chat.call_args.kwargs
    assert sent["messages"][0]["content"] == "what is the weather today?"


def test_chat_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.mistral_adapter import (
        MistralKernel,
        PolicyViolationError,
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
    kernel = MistralKernel(_runtime=runtime)
    client = _make_client()
    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.chat(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "tell me about secrets"}],
        )

    assert excinfo.value.check_result.reason == "user_blocked_topic"
    client.chat.assert_not_called()


def test_chat_transform_path_redacts_outbound_content(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the outbound message content."""
    from agent_os.integrations.mistral_adapter import MistralKernel

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
    kernel = MistralKernel(_runtime=runtime)
    client = _make_client()
    governed = kernel.wrap(client)

    governed.chat(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": "Customer SSN is 123-45-6789"}],
    )

    client.chat.assert_called_once()
    sent = client.chat.call_args.kwargs
    # The Mistral client MUST see the redacted text, not the original.
    assert sent["messages"][0]["content"] == "Customer SSN is [REDACTED]"


def test_chat_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.mistral_adapter import MistralKernel

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
    kernel = MistralKernel(_runtime=runtime, approval_resolver=resolver)
    client = _make_client()
    governed = kernel.wrap(client)

    governed.chat(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": "approve this please"}],
    )

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    client.chat.assert_called_once()


def test_chat_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.mistral_adapter import (
        MistralKernel,
        PolicyViolationError,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = MistralKernel(_runtime=runtime)
    client = _make_client()
    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError):
        governed.chat(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "needs approval"}],
        )

    client.chat.assert_not_called()
