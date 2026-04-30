# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for safe policy-violation exception messages."""

from __future__ import annotations

import pickle
from collections.abc import Callable

import pytest

from agent_os.exceptions import PolicyViolationError
from agent_os.integrations.base import PatternType
from agent_os.policies.decision import PolicyCheckResult
from agent_os.policies.decision_factory import (
    deny_blocked_pattern_input,
    deny_blocked_pattern_memory,
    deny_blocked_pattern_output,
    deny_blocked_pattern_tool,
    deny_blocked_tool,
    deny_confidence_threshold,
    deny_drift,
    deny_human_approval,
    deny_max_tool_calls,
    deny_not_allowed_tool,
    deny_policy_error,
    deny_timeout,
)

FactoryBuilder = Callable[[], PolicyCheckResult]

FACTORY_CASES: list[tuple[str, FactoryBuilder, str]] = [
    (
        "blocked_pattern_input",
        lambda: deny_blocked_pattern_input("secret-input-pattern", "secret input text"),
        "secret-input-pattern",
    ),
    (
        "blocked_pattern_tool",
        lambda: deny_blocked_pattern_tool("secret-tool-pattern", tool_name="danger_tool"),
        "secret-tool-pattern",
    ),
    (
        "blocked_pattern_output",
        lambda: deny_blocked_pattern_output("secret-output-pattern"),
        "secret-output-pattern",
    ),
    (
        "blocked_pattern_memory",
        lambda: deny_blocked_pattern_memory("secret-memory-pattern"),
        "secret-memory-pattern",
    ),
    ("blocked_tool", lambda: deny_blocked_tool("danger_tool"), "danger_tool"),
    (
        "not_allowed_tool",
        lambda: deny_not_allowed_tool("danger_tool", ["read_file", "write_file"]),
        "read_file",
    ),
    ("max_tool_calls", lambda: deny_max_tool_calls(5, current=6), "5"),
    ("timeout", lambda: deny_timeout(30, elapsed_s=31), "30"),
    ("human_approval", lambda: deny_human_approval("approval_tool"), "approval_tool"),
    ("confidence_threshold", lambda: deny_confidence_threshold(0.9, observed=0.42), "0.90"),
    (
        "policy_error",
        lambda: deny_policy_error("policy detail includes policy-secret"),
        "policy-secret",
    ),
    ("drift", lambda: deny_drift(0.91, 0.7), "0.91"),
]

PROPERTY_CASES: list[tuple[str, FactoryBuilder, tuple[str, ...]]] = [
    (
        "allowed_tools",
        lambda: deny_not_allowed_tool("delete_file", ["read_file", "write_file"]),
        ("delete_file", "read_file", "write_file"),
    ),
    (
        "blocked_patterns",
        lambda: deny_blocked_pattern_input(r"\b\d{3}-\d{2}-\d{4}\b"),
        (r"\b\d{3}-\d{2}-\d{4}\b", PatternType.REGEX.value),
    ),
    ("blocked_tool", lambda: deny_blocked_tool("shell_exec"), ("shell_exec",)),
    ("max_tool_calls", lambda: deny_max_tool_calls(5), ("5",)),
    ("timeout_seconds", lambda: deny_timeout(30), ("30",)),
]


class TestPolicyViolationErrorSafety:
    """Verify exceptions expose sanitized messages and retain audit details."""

    @pytest.mark.parametrize(
        ("case_name", "builder", "detail_value"),
        FACTORY_CASES,
        ids=[case[0] for case in FACTORY_CASES],
    )
    def test_from_check_result_public_message_is_safe(
        self,
        case_name: str,
        builder: FactoryBuilder,
        detail_value: str,
    ) -> None:
        result = builder()

        with pytest.raises(PolicyViolationError) as exc_info:
            raise PolicyViolationError.from_check_result(result)

        error = exc_info.value
        assert case_name
        assert str(error) == result.public_message
        assert detail_value not in str(error)
        assert detail_value not in repr(error)
        assert detail_value in error.details["detail"]
        assert error.check_result is result

    @pytest.mark.parametrize(
        ("case_name", "builder", "detail_value"),
        FACTORY_CASES,
        ids=[case[0] for case in FACTORY_CASES],
    )
    def test_pickle_round_trip_preserves_public_message_safety(
        self,
        case_name: str,
        builder: FactoryBuilder,
        detail_value: str,
    ) -> None:
        error = PolicyViolationError.from_check_result(builder())
        roundtripped = pickle.loads(pickle.dumps(error))

        # The attached check_result is diagnostic state; public-message safety is the contract.
        assert case_name
        assert str(roundtripped) == str(error)
        assert detail_value not in str(roundtripped)
        assert detail_value not in repr(roundtripped)

    @pytest.mark.parametrize(
        ("case_name", "builder", "forbidden_values"),
        PROPERTY_CASES,
        ids=[case[0] for case in PROPERTY_CASES],
    )
    def test_synthetic_policy_values_do_not_leak_to_exception_message(
        self,
        case_name: str,
        builder: FactoryBuilder,
        forbidden_values: tuple[str, ...],
    ) -> None:
        error = PolicyViolationError.from_check_result(builder())

        assert case_name
        for forbidden in forbidden_values:
            assert forbidden not in str(error)
            assert forbidden not in repr(error)
