# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Gemini adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`GeminiKernel` and
:class:`GovernedGeminiModel` surface routed through
:class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH`` or on the ``google-generativeai``
SDK being installed.

Each test covers one of the AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> Gemini sees the original prompt.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the adapter rewrites the outbound prompt or tool
  arguments with the AGT D1.1 ``{path, value}`` payload before calling
  the Gemini client.
- ``escalate`` (resolver approves) -> the adapter forwards the call.
- ``escalate`` (no resolver) -> the adapter raises a deny.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("agent_control_specification")
pytest.importorskip("agent_os")

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402,F401
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: gemini_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: gemini_adapter_scenarios_adapter
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


def _make_gemini_model(response: Any | None = None) -> MagicMock:
    """Return a mock ``GenerativeModel`` that responds with ``response``."""
    model = MagicMock()
    model.model_name = "gemini-pro"
    model.generate_content.return_value = response or SimpleNamespace(
        candidates=[],
        usage_metadata=SimpleNamespace(
            prompt_token_count=10,
            candidates_token_count=20,
        ),
    )
    return model


def _make_function_call_response(name: str, args: dict[str, Any]) -> SimpleNamespace:
    """Build a Gemini response containing a single function call."""
    fn_call = SimpleNamespace(name=name, args=args)
    part = SimpleNamespace(function_call=fn_call)
    content = SimpleNamespace(parts=[part])
    candidate = SimpleNamespace(content=content)
    return SimpleNamespace(
        candidates=[candidate],
        usage_metadata=SimpleNamespace(
            prompt_token_count=10,
            candidates_token_count=20,
        ),
    )


# ── verdict scenarios — prompt path ──────────────────────────────────


def test_generate_content_allow_path_forwards_to_gemini(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the Gemini client see the original prompt."""
    # Bypass the google.generativeai import check for the wrap() call so
    # the test runs without the SDK installed.
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel

    gemini_mod._HAS_GENAI = True

    runtime, policy = _build_runtime(tmp_path, [{"decision": "allow"}])
    kernel = GeminiKernel(_runtime=runtime)
    model = _make_gemini_model()
    governed = kernel.wrap(model)

    governed.generate_content("what is the weather today?")

    assert len(policy.invocations) == 1
    model.generate_content.assert_called_once()
    sent = model.generate_content.call_args.args
    assert sent[0] == "what is the weather today?"


def test_generate_content_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel, PolicyViolationError

    gemini_mod._HAS_GENAI = True

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
    kernel = GeminiKernel(_runtime=runtime)
    model = _make_gemini_model()
    governed = kernel.wrap(model)

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.generate_content("tell me about secrets")

    assert excinfo.value.check_result.reason == "user_blocked_topic"
    model.generate_content.assert_not_called()


def test_generate_content_transform_path_redacts_outbound_prompt(tmp_path: Path) -> None:
    """A ``transform`` verdict rewrites the outbound prompt."""
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel

    gemini_mod._HAS_GENAI = True

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
    kernel = GeminiKernel(_runtime=runtime)
    model = _make_gemini_model()
    governed = kernel.wrap(model)

    governed.generate_content("Customer SSN is 123-45-6789")

    model.generate_content.assert_called_once()
    sent = model.generate_content.call_args.args
    # The Gemini SDK MUST see the redacted text, not the original.
    assert sent[0] == "Customer SSN is [REDACTED]"


def test_generate_content_escalate_with_approving_resolver_forwards(
    tmp_path: Path,
) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel

    gemini_mod._HAS_GENAI = True

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
    kernel = GeminiKernel(_runtime=runtime, approval_resolver=resolver)
    model = _make_gemini_model()
    governed = kernel.wrap(model)

    governed.generate_content("approve this please")

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    model.generate_content.assert_called_once()


def test_generate_content_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel, PolicyViolationError

    gemini_mod._HAS_GENAI = True

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = GeminiKernel(_runtime=runtime)
    model = _make_gemini_model()
    governed = kernel.wrap(model)

    with pytest.raises(PolicyViolationError):
        governed.generate_content("needs approval")

    model.generate_content.assert_not_called()


# ── verdict scenarios — function_call path ───────────────────────────


def test_function_call_transform_rewrites_args(tmp_path: Path) -> None:
    """A ``transform`` verdict on a returned function_call rewrites its args."""
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel

    gemini_mod._HAS_GENAI = True

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # input
            {
                "decision": "transform",
                "reason": "args_sanitized",
                "transform": {
                    "path": "$policy_target",
                    "value": {"city": "[REDACTED]"},
                },
            },
        ],
    )
    kernel = GeminiKernel(_runtime=runtime)
    response = _make_function_call_response("get_weather", {"city": "Seattle"})
    model = _make_gemini_model(response=response)
    governed = kernel.wrap(model)

    governed.generate_content("weather please")

    # The function_call in the returned candidate has args rewritten by
    # the AGT D1.1 transform.
    fn_call = response.candidates[0].content.parts[0].function_call
    assert fn_call.args == {"city": "[REDACTED]"}


def test_function_call_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict on a returned function_call raises PolicyViolationError."""
    from agent_os.integrations import gemini_adapter as gemini_mod
    from agent_os.integrations.gemini_adapter import GeminiKernel, PolicyViolationError

    gemini_mod._HAS_GENAI = True

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # input
            {
                "decision": "deny",
                "reason": "tool_args_forbidden",
                "message": "weather lookup is off limits",
            },
        ],
    )
    kernel = GeminiKernel(_runtime=runtime)
    response = _make_function_call_response("get_weather", {"city": "Seattle"})
    model = _make_gemini_model(response=response)
    governed = kernel.wrap(model)

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.generate_content("weather please")

    assert excinfo.value.check_result.reason == "tool_args_forbidden"
