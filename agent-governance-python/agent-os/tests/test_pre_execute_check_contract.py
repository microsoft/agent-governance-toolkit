# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for structured integration policy-check wrapper contracts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
)
from agent_os.policies.decision import PolicyCheckResult, ViolationCategory
from agent_os.policies.decision_factory import (
    deny_blocked_pattern_input,
    deny_human_approval,
    deny_max_tool_calls,
    deny_not_allowed_tool,
    deny_timeout,
)


class _TestKernel(BaseIntegration):
    """Minimal concrete integration for policy contract tests."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


@dataclass
class _LowConfidenceInput:
    """Input object carrying confidence metadata."""

    value: str
    confidence: float


@dataclass(frozen=True)
class _PreCase:
    """Fixture data for a pre-execution denial."""

    name: str
    policy_factory: Callable[[], GovernancePolicy]
    context_mutator: Callable[[ExecutionContext], None]
    input_factory: Callable[[], Any]
    expected_category: ViolationCategory


PRE_DENIAL_CASES = [
    _PreCase(
        name="max_tool_calls",
        policy_factory=lambda: GovernancePolicy(max_tool_calls=5),
        context_mutator=lambda ctx: setattr(ctx, "call_count", 5),
        input_factory=lambda: "safe input",
        expected_category=ViolationCategory.MAX_TOOL_CALLS,
    ),
    _PreCase(
        name="timeout",
        policy_factory=lambda: GovernancePolicy(timeout_seconds=1),
        context_mutator=lambda ctx: setattr(ctx, "start_time", datetime.now() - timedelta(seconds=2)),
        input_factory=lambda: "safe input",
        expected_category=ViolationCategory.TIMEOUT,
    ),
    _PreCase(
        name="blocked_pattern",
        policy_factory=lambda: GovernancePolicy(blocked_patterns=["bar"]),
        context_mutator=lambda ctx: None,
        input_factory=lambda: "foo bar baz",
        expected_category=ViolationCategory.BLOCKED_PATTERN_INPUT,
    ),
    _PreCase(
        name="human_approval",
        policy_factory=lambda: GovernancePolicy(require_human_approval=True),
        context_mutator=lambda ctx: None,
        input_factory=lambda: "safe input",
        expected_category=ViolationCategory.HUMAN_APPROVAL,
    ),
    _PreCase(
        name="confidence_threshold",
        policy_factory=lambda: GovernancePolicy(confidence_threshold=0.9),
        context_mutator=lambda ctx: None,
        input_factory=lambda: _LowConfidenceInput("risky action", 0.2),
        expected_category=ViolationCategory.CONFIDENCE_THRESHOLD,
    ),
]

LEGACY_REASON_CASES = [
    ("max_tool_calls", lambda: deny_max_tool_calls(5).reason, "Max tool calls exceeded (5)"),
    ("timeout", lambda: deny_timeout(0.1).reason, "Timeout exceeded (0.1s)"),
    (
        "blocked_pattern_input",
        lambda: deny_blocked_pattern_input("bar", "foo bar baz").reason,
        "Blocked pattern detected: bar",
    ),
    (
        "human_approval",
        lambda: deny_human_approval().reason,
        "Execution requires human approval per governance policy",
    ),
    (
        "not_allowed_tool",
        lambda: deny_not_allowed_tool("c", ["a", "b"]).reason,
        "Tool 'c' not in allowed list: ['a', 'b']",
    ),
]


def _kernel_and_context(case: _PreCase) -> tuple[_TestKernel, ExecutionContext, Any]:
    kernel = _TestKernel(policy=case.policy_factory())
    ctx = kernel.create_context(f"agent-{case.name}")
    case.context_mutator(ctx)
    return kernel, ctx, case.input_factory()


class TestPreExecuteCheckContract:
    """Verify structured pre-checks match legacy pre-execute wrappers."""

    @pytest.mark.parametrize("case", PRE_DENIAL_CASES, ids=[case.name for case in PRE_DENIAL_CASES])
    def test_pre_execute_check_returns_structured_denial(self, case: _PreCase) -> None:
        kernel, ctx, input_data = _kernel_and_context(case)

        result = kernel.pre_execute_check(ctx, input_data)

        assert isinstance(result, PolicyCheckResult)
        assert result.allowed is False
        assert result.category is case.expected_category
        assert result.to_legacy_tuple() == kernel.pre_execute(ctx, input_data)

    @pytest.mark.parametrize("case", PRE_DENIAL_CASES, ids=[case.name for case in PRE_DENIAL_CASES])
    async def test_async_pre_execute_check_returns_structured_denial(self, case: _PreCase) -> None:
        kernel, ctx, input_data = _kernel_and_context(case)

        result = await kernel.async_pre_execute_check(ctx, input_data)

        assert isinstance(result, PolicyCheckResult)
        assert result.allowed is False
        assert result.category is case.expected_category
        assert result.to_legacy_tuple() == await kernel.async_pre_execute(ctx, input_data)


class TestPostExecuteCheckContract:
    """Verify structured post-checks match legacy post-execute wrappers."""

    @pytest.mark.parametrize("case", PRE_DENIAL_CASES, ids=[case.name for case in PRE_DENIAL_CASES])
    def test_post_execute_check_matches_legacy_tuple_for_same_policies(
        self,
        case: _PreCase,
    ) -> None:
        check_kernel, check_ctx, _ = _kernel_and_context(case)
        legacy_kernel, legacy_ctx, _ = _kernel_and_context(case)

        result = check_kernel.post_execute_check(check_ctx, "safe output")
        legacy_tuple = legacy_kernel.post_execute(legacy_ctx, "safe output")

        assert isinstance(result, PolicyCheckResult)
        assert result.to_legacy_tuple() == legacy_tuple
        assert check_ctx.call_count == legacy_ctx.call_count

    @pytest.mark.parametrize("case", PRE_DENIAL_CASES, ids=[case.name for case in PRE_DENIAL_CASES])
    async def test_async_post_execute_check_matches_legacy_tuple_for_same_policies(
        self,
        case: _PreCase,
    ) -> None:
        check_kernel, check_ctx, _ = _kernel_and_context(case)
        legacy_kernel, legacy_ctx, _ = _kernel_and_context(case)

        result = await check_kernel.async_post_execute_check(check_ctx, "safe output")
        legacy_tuple = await legacy_kernel.async_post_execute(legacy_ctx, "safe output")

        assert isinstance(result, PolicyCheckResult)
        assert result.to_legacy_tuple() == legacy_tuple
        assert check_ctx.call_count == legacy_ctx.call_count


class TestLegacyReasonSnapshots:
    """Pin byte-identical legacy denial reason strings."""

    @pytest.mark.parametrize(
        ("case_name", "reason_factory", "expected_reason"),
        LEGACY_REASON_CASES,
        ids=[case[0] for case in LEGACY_REASON_CASES],
    )
    def test_factory_reason_matches_legacy_snapshot(
        self,
        case_name: str,
        reason_factory: Callable[[], str],
        expected_reason: str,
    ) -> None:
        assert case_name
        assert reason_factory() == expected_reason
