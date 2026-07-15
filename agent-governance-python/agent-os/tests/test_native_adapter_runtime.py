# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native framework-adapter runtime seam."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agt.policies import PolicyEvaluation, TransformResult

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
        evaluation: PolicyEvaluation,
        *,
        approval_resolver: Any | None = None,
    ) -> None:
        self.evaluation = evaluation
        self._approval_resolver = approval_resolver
        self.snapshots: list[dict[str, Any]] = []

    def evaluate(
        self, intervention_point: str, snapshot: dict[str, Any]
    ) -> PolicyEvaluation:
        self.snapshots.append(snapshot)
        return self.evaluation.model_copy(
            update={"intervention_point": intervention_point}
        )

    def close(self) -> None:
        pass


def test_native_result_raises_native_policy_violation() -> None:
    runtime = NativeAdapterRuntime(
        _Runtime(
            PolicyEvaluation(
                verdict="deny",
                reason_code="blocked",
                message="restricted detail",
            )
        )
    )

    result = runtime.evaluate_input(_Context(), body="hello")
    error = result.to_policy_violation(PolicyViolationError)

    assert str(error) == "Request blocked by policy."
    assert error.evaluation_result is result.evaluation
    assert error.check_result is None
    assert error.details["message"] == "restricted detail"


def test_native_result_exposes_transform_without_legacy_conversion() -> None:
    runtime = NativeAdapterRuntime(
        _Runtime(
            PolicyEvaluation(
                verdict="transform",
                transform=TransformResult(path="$policy_target", value="safe"),
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
            PolicyEvaluation(
                verdict="transform",
                transform=TransformResult(
                    path="$policy_target.secret",
                    value="[REDACTED]",
                    applied_value={"secret": "[REDACTED]", "safe": "visible"},
                ),
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
    source = _Runtime(PolicyEvaluation(verdict="allow"))
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
