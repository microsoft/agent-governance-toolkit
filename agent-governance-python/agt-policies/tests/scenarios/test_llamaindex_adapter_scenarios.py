# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LlamaIndex adapter end-to-end scenarios on the AGT 5.0 ACS-backed runtime.

These scenarios exercise the v4 :class:`LlamaIndexKernel` surface routed
through :class:`agt.policies.runtime.AgtRuntime` via the
:class:`agent_os.integrations._v5_runtime_bridge.AdapterRuntimeBridge`.
The scripted policy dispatcher is injected directly so the suite does
not depend on OPA being on ``PATH`` or on the ``llama_index`` SDK
being installed.

Each test covers one of the AGT verdicts that the adapter must
translate back to its v4 surface:

- ``allow`` -> the LlamaIndex engine sees the original query / message.
- ``deny`` -> the adapter raises
  :class:`PolicyViolationError.from_check_result(...)`.
- ``transform`` -> the adapter rewrites the outbound query / message
  (or the engine's response) with the AGT D1.1 ``{path, value}``
  payload.
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
  name: llamaindex_adapter_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: llamaindex_adapter_scenarios_adapter
intervention_points:
  input:
    policy_target: $.input.body
    policy_target_kind: user_input
    policy:
      id: scenario_policy
  output:
    policy_target: $.response.content
    policy_target_kind: assistant_output
    policy:
      id: scenario_policy
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


def _make_engine(query_response: str = "answer") -> MagicMock:
    """Return a mock LlamaIndex engine (no SDK required)."""
    engine = MagicMock()
    # MagicMock auto-generates a ``name`` attribute that breaks the
    # adapter's agent_id validation; drop it.
    del engine.name
    engine.query.return_value = SimpleNamespace(response=query_response)
    engine.chat.return_value = SimpleNamespace(response=query_response)
    return engine


# ── verdict scenarios ────────────────────────────────────────────────


def test_query_allow_path_forwards_to_engine(tmp_path: Path) -> None:
    """An ``allow`` verdict lets the LlamaIndex engine see the original query."""
    from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel

    runtime, policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # input
            {"decision": "allow"},  # output
        ],
    )
    kernel = LlamaIndexKernel(_runtime=runtime)
    engine = _make_engine()
    governed = kernel.wrap(engine)

    result = governed.query("what is the meaning of life?")

    assert result.response == "answer"
    engine.query.assert_called_once()
    assert engine.query.call_args.args[0] == "what is the meaning of life?"
    assert len(policy.invocations) == 2


def test_query_deny_path_raises_policy_violation(tmp_path: Path) -> None:
    """A ``deny`` verdict raises :class:`PolicyViolationError`."""
    from agent_os.integrations.llamaindex_adapter import (
        LlamaIndexKernel,
        PolicyViolationError,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {
                "decision": "deny",
                "reason": "blocked_query",
                "message": "query is off limits",
            }
        ],
    )
    kernel = LlamaIndexKernel(_runtime=runtime)
    engine = _make_engine()
    governed = kernel.wrap(engine)

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.query("tell me secrets")

    assert excinfo.value.check_result.reason == "blocked_query"
    engine.query.assert_not_called()


def test_chat_transform_path_redacts_outbound_message(tmp_path: Path) -> None:
    """A ``transform`` verdict on the input rewrites the chat message."""
    from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel

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
            },
            {"decision": "allow"},  # output
        ],
    )
    kernel = LlamaIndexKernel(_runtime=runtime)
    engine = _make_engine()
    governed = kernel.wrap(engine)

    governed.chat("Customer SSN is 123-45-6789")

    engine.chat.assert_called_once()
    assert engine.chat.call_args.args[0] == "Customer SSN is [REDACTED]"


def test_output_transform_path_redacts_response(tmp_path: Path) -> None:
    """A ``transform`` verdict on the output rewrites the engine's response."""
    from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel

    runtime, _policy = _build_runtime(
        tmp_path,
        [
            {"decision": "allow"},  # input
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
    kernel = LlamaIndexKernel(_runtime=runtime)
    engine = _make_engine(query_response="leaked secret payload")
    governed = kernel.wrap(engine)

    result = governed.query("safe question")

    assert result.response == "[REDACTED OUTPUT]"


def test_query_escalate_with_approving_resolver_forwards(tmp_path: Path) -> None:
    """An ``escalate`` verdict that the resolver approves forwards the call."""
    from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel

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
    kernel = LlamaIndexKernel(_runtime=runtime, approval_resolver=resolver)
    engine = _make_engine()
    governed = kernel.wrap(engine)

    governed.query("approve this please")

    assert captured["ip"] == "input"
    assert captured["enforced_identity"] is not None
    engine.query.assert_called_once()


def test_query_escalate_with_no_resolver_denies(tmp_path: Path) -> None:
    """An ``escalate`` verdict without a resolver fails closed to deny."""
    from agent_os.integrations.llamaindex_adapter import (
        LlamaIndexKernel,
        PolicyViolationError,
    )

    runtime, _policy = _build_runtime(
        tmp_path,
        [{"decision": "escalate", "reason": "human_approval_required"}],
        approval_resolver=None,
    )
    kernel = LlamaIndexKernel(_runtime=runtime)
    engine = _make_engine()
    governed = kernel.wrap(engine)

    with pytest.raises(PolicyViolationError):
        governed.query("needs approval")

    engine.query.assert_not_called()
