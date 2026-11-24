# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native framework-adapter runtime seam."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from agent_control_specification import (
    AgentControlBlocked,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    Transform,
    Verdict,
)

from agent_os.exceptions import PolicyViolationError
from agent_os.integrations._native_adapter_runtime import (
    NativeAdapterRuntime,
)


@dataclass
class _Context:
    agent_id: str = "agent"
    session_id: str = "session"
    call_count: int = 0
    total_tokens: int = 0


class _Runtime:
    manifest = None

    def __init__(
        self,
        evaluation: InterventionPointResult,
        *,
        approval_resolver: Any | None = None,
    ) -> None:
        self.evaluation = evaluation
        self._approval_resolver = approval_resolver
        self.snapshots: list[dict[str, Any]] = []

    async def evaluate_intervention_point(
        self, intervention_point, snapshot, mode=None
    ):
        self.snapshots.append(snapshot)
        return self.evaluation

    async def enforce(self, intervention_point, result, mode=None):
        # A liftable deny with no resolver configured: the host names the
        # reserved reason and keeps the approval block on the verdict.
        raise AgentControlBlocked(
            InterventionPoint(intervention_point),
            replace(
                result,
                verdict=replace(result.verdict, reason="host_error:approval_unresolved"),
            ),
        )

    def close(self) -> None:
        pass


def test_native_result_raises_native_policy_violation() -> None:
    runtime = NativeAdapterRuntime(
        _Runtime(
            InterventionPointResult(verdict=Verdict(decision=Decision.DENY, reason="blocked", message="restricted detail"))
        )
    )

    result = runtime.evaluate_input(_Context(), body="hello")
    error = result.to_policy_violation(PolicyViolationError)

    assert str(error) == "Request blocked by policy."
    assert error.evaluation_result is result.evaluation
    assert error.details["message"] == "restricted detail"


def test_native_result_routes_liftable_deny_to_the_approval_message() -> None:
    # The engine emits no ``escalate`` decision any more; an escalation is a
    # ``deny`` carrying an ``approval`` block. The adapter must read that block
    # rather than the retired decision name, or every approval-gated action is
    # reported as a plain block.
    runtime = NativeAdapterRuntime(
        _Runtime(
            InterventionPointResult(
                verdict=Verdict(
                    decision=Decision.DENY,
                    reason="needs_sign_off",
                    approval={"required": True, "resolver": "human"},
                )
            )
        )
    )

    result = runtime.evaluate_pre_tool_call(_Context(), tool_name="wire", args={})
    error = result.to_policy_violation(PolicyViolationError)

    assert result.allowed is False
    assert result.approval_required is True
    assert str(error) == "Request requires policy approval."
    assert error.details["verdict"] == "deny"
    assert error.details["approval_required"] is True
    assert error.details["reason_code"] == "host_error:approval_unresolved"


def test_native_result_plain_deny_is_not_approval_required() -> None:
    runtime = NativeAdapterRuntime(
        _Runtime(InterventionPointResult(verdict=Verdict(decision=Decision.DENY, reason="blocked")))
    )

    result = runtime.evaluate_input(_Context(), body="hello")

    assert result.approval_required is False
    assert result.audit_record()["approval_required"] is False
    assert result.public_message == "Request blocked by policy."


def test_native_result_exposes_transform_without_legacy_conversion() -> None:
    runtime = NativeAdapterRuntime(
        _Runtime(
            InterventionPointResult(
                verdict=Verdict(
                    decision=Decision.TRANSFORM,
                    transform=Transform(path="$target", value="safe"),
                )
            )
        )
    )

    result = runtime.evaluate_output(_Context(), content="secret")

    assert result.allowed is True
    assert result.transform is not None
    assert result.transform.value == "safe"


def test_native_result_exposes_materialized_nested_transform() -> None:
    runtime = NativeAdapterRuntime(
        _Runtime(
            InterventionPointResult(
                verdict=Verdict(
                    decision=Decision.TRANSFORM,
                    transform=Transform(path="$target.secret", value="[REDACTED]"),
                ),
                transformed_policy_target={"secret": "[REDACTED]", "safe": "visible"},
                transformed_policy_target_applied=True,
            )
        )
    )

    result = runtime.evaluate_pre_tool_call(
        _Context(),
        tool_name="send",
        args={"secret": "123", "safe": "visible"},
    )

    assert result.transformed_value == {
        "secret": "[REDACTED]",
        "safe": "visible",
    }


def test_native_path_charges_attempts_and_records_tokens_once() -> None:
    source = _Runtime(InterventionPointResult(verdict=Verdict(decision=Decision.ALLOW)))
    runtime = NativeAdapterRuntime(source)
    context = _Context()

    runtime.evaluate_pre_tool_call(context, tool_name="lookup", args={})
    runtime.record_post_execute(context, tokens=7, tool_calls=1)
    runtime.evaluate_pre_tool_call(context, tool_name="lookup", args={})

    first = source.snapshots[0]["envelope"]["budgets"]
    second = source.snapshots[1]["envelope"]["budgets"]
    assert first["tool_call_count"] == 0
    assert second["tool_call_count"] == 1
    assert second["token_count"] == 7


def test_model_and_output_envelopes_use_the_snapshot_contract_keys() -> None:
    """The runtime and ``HostSession``'s own methods must agree on the keys.

    A manifest binds one path per point. If the two seams spell the point
    body differently, a manifest tested behind one fails closed with
    ``runtime_error:path_missing`` behind the other.
    """
    source = _Runtime(InterventionPointResult(verdict=Verdict(decision=Decision.ALLOW)))
    runtime = NativeAdapterRuntime(source)
    context = _Context()
    messages = [{"role": "user", "content": "hi"}]

    runtime.evaluate_pre_model_call(
        context, model_name="m", messages=messages, tools=[{"name": "t"}]
    )
    runtime.evaluate_post_model_call(context, model_name="m", response={"content": "hello"})
    runtime.evaluate_output(context, content="hello")

    pre, post, output = source.snapshots
    assert pre["model_request"] == {
        "model": {"name": "m", "vendor": "test", "params": {}},
        "messages": messages,
        "tools": [{"name": "t"}],
    }
    assert post["model_response"] == {"content": "hello"}
    assert output["output"] == "hello"
    assert output["ifc"] == {"result_labels": []}
    for snapshot in (pre, post, output):
        assert "response" not in snapshot
    assert "messages" not in pre and "tools" not in pre and "model" not in pre
