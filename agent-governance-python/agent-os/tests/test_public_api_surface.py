# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests that pin public API signatures touched by policy decisions."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

import pytest

from agent_os import exceptions
from agent_os.integrations.base import BaseIntegration
from agent_os.policies import decision, decision_factory

SIGNATURE_CASES: list[tuple[str, Callable[..., Any], str]] = [
    (
        "PolicyViolationError.__init__",
        exceptions.PolicyViolationError.__init__,
        "(self, message, error_code=None, details=None)",
    ),
    (
        "PolicyError.__init__",
        exceptions.PolicyError.__init__,
        "(self, message, error_code=None, details=None)",
    ),
    (
        "AgentOSError.__init__",
        exceptions.AgentOSError.__init__,
        "(self, message, error_code=None, details=None)",
    ),
    (
        "BaseIntegration.pre_execute",
        BaseIntegration.pre_execute,
        "(self, ctx: 'ExecutionContext', input_data: 'Any') -> 'tuple[bool, str | None]'",
    ),
    (
        "BaseIntegration.post_execute",
        BaseIntegration.post_execute,
        "(self, ctx: 'ExecutionContext', output_data: 'Any') -> 'tuple[bool, str | None]'",
    ),
    (
        "BaseIntegration.async_pre_execute",
        BaseIntegration.async_pre_execute,
        "(self, ctx: 'ExecutionContext', input_data: 'Any') -> 'tuple[bool, str | None]'",
    ),
    (
        "BaseIntegration.async_post_execute",
        BaseIntegration.async_post_execute,
        "(self, ctx: 'ExecutionContext', output_data: 'Any') -> 'tuple[bool, str | None]'",
    ),
]

ASYNC_METHODS = [
    BaseIntegration.async_pre_execute,
    BaseIntegration.async_post_execute,
]

NEW_FACTORY_NAMES = [
    "deny_blocked_pattern_input",
    "deny_blocked_pattern_tool",
    "deny_blocked_pattern_output",
    "deny_blocked_pattern_memory",
    "deny_blocked_tool",
    "deny_not_allowed_tool",
    "deny_max_tool_calls",
    "deny_timeout",
    "deny_human_approval",
    "deny_confidence_threshold",
    "deny_policy_error",
    "deny_drift",
]


class TestPublicApiSurface:
    """Pin legacy signatures and additive policy-decision symbols."""

    @pytest.mark.parametrize(
        ("symbol_name", "symbol", "expected_signature"),
        SIGNATURE_CASES,
        ids=[case[0] for case in SIGNATURE_CASES],
    )
    def test_public_signatures_are_pinned(
        self,
        symbol_name: str,
        symbol: Callable[..., Any],
        expected_signature: str,
    ) -> None:
        assert symbol_name
        assert str(inspect.signature(symbol)) == expected_signature

    @pytest.mark.parametrize("symbol", ASYNC_METHODS)
    def test_async_wrappers_remain_coroutines(self, symbol: Callable[..., Any]) -> None:
        assert inspect.iscoroutinefunction(symbol)

    @pytest.mark.parametrize("name", NEW_FACTORY_NAMES)
    def test_new_decision_factories_exist(self, name: str) -> None:
        assert callable(getattr(decision_factory, name))

    def test_new_decision_symbols_exist(self) -> None:
        assert inspect.isclass(decision.ViolationCategory)
        assert inspect.isclass(decision.PolicyCheckResult)
        assert callable(exceptions.PolicyViolationError.from_check_result)
