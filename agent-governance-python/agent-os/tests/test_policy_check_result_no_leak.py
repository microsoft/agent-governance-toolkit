# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for sanitized policy-check decisions."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from agent_os.policies.decision import PolicyCheckResult, ViolationCategory
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

PUBLIC_KEYS = {"allowed", "action", "category", "matched_rule", "public_message"}

FACTORY_CASES: list[tuple[str, FactoryBuilder, str, ViolationCategory, tuple[str, ...]]] = [
    (
        "blocked_pattern_input",
        lambda: deny_blocked_pattern_input("secret-input-pattern", "secret input text"),
        "Content blocked by governance policy.",
        ViolationCategory.BLOCKED_PATTERN_INPUT,
        ("secret-input-pattern",),
    ),
    (
        "blocked_pattern_tool",
        lambda: deny_blocked_pattern_tool(
            "secret-tool-pattern", tool_name="danger_tool", matched_text="secret tool text"
        ),
        "Content blocked by governance policy.",
        ViolationCategory.BLOCKED_PATTERN_TOOL,
        ("secret-tool-pattern", "danger_tool"),
    ),
    (
        "blocked_pattern_output",
        lambda: deny_blocked_pattern_output("secret-output-pattern", matched_text="secret output"),
        "Content blocked by governance policy.",
        ViolationCategory.BLOCKED_PATTERN_OUTPUT,
        ("secret-output-pattern",),
    ),
    (
        "blocked_pattern_memory",
        lambda: deny_blocked_pattern_memory("secret-memory-pattern", matched_text="secret memory"),
        "Content blocked by governance policy.",
        ViolationCategory.BLOCKED_PATTERN_MEMORY,
        ("secret-memory-pattern",),
    ),
    (
        "blocked_tool",
        lambda: deny_blocked_tool("danger_tool"),
        "Tool blocked by governance policy.",
        ViolationCategory.BLOCKED_TOOL,
        ("danger_tool",),
    ),
    (
        "not_allowed_tool",
        lambda: deny_not_allowed_tool("danger_tool", ["read_file", "write_file"]),
        "Tool not permitted by governance policy.",
        ViolationCategory.NOT_ALLOWED_TOOL,
        ("danger_tool", "read_file", "write_file"),
    ),
    (
        "max_tool_calls",
        lambda: deny_max_tool_calls(5, current=6),
        "Tool-call limit exceeded.",
        ViolationCategory.MAX_TOOL_CALLS,
        ("5", "6"),
    ),
    (
        "timeout",
        lambda: deny_timeout(30, elapsed_s=31),
        "Execution timeout exceeded.",
        ViolationCategory.TIMEOUT,
        ("30", "31"),
    ),
    (
        "human_approval",
        lambda: deny_human_approval("approval_tool"),
        "Human approval required.",
        ViolationCategory.HUMAN_APPROVAL,
        ("approval_tool",),
    ),
    (
        "confidence_threshold",
        lambda: deny_confidence_threshold(0.9, observed=0.42),
        "Confidence below required threshold.",
        ViolationCategory.CONFIDENCE_THRESHOLD,
        ("0.9", "0.42"),
    ),
    (
        "policy_error",
        lambda: deny_policy_error("policy detail includes policy-secret", matched_rule="rule-17"),
        "Policy evaluation error.",
        ViolationCategory.POLICY_ERROR,
        ("policy-secret", "17"),
    ),
    (
        "drift",
        lambda: deny_drift(
            0.91,
            0.7,
            baseline_hash="baseline-secret-hash",
            current_hash="current-secret-hash",
        ),
        "Behavioral drift detected.",
        ViolationCategory.DRIFT,
        ("0.91", "0.7", "baseline-secret-hash", "current-secret-hash"),
    ),
]

REDACTABLE_PATTERN_CASES: list[tuple[str, Callable[..., PolicyCheckResult]]] = [
    ("blocked_pattern_input", deny_blocked_pattern_input),
    ("blocked_pattern_tool", deny_blocked_pattern_tool),
    ("blocked_pattern_output", deny_blocked_pattern_output),
    ("blocked_pattern_memory", deny_blocked_pattern_memory),
]


class TestPolicyCheckResultNoLeak:
    """Verify policy decisions separate public text from audit detail."""

    @pytest.mark.parametrize(
        ("case_name", "builder", "public_message", "expected_category", "sensitive_values"),
        FACTORY_CASES,
        ids=[case[0] for case in FACTORY_CASES],
    )
    def test_factory_public_message_is_sanitized(
        self,
        case_name: str,
        builder: FactoryBuilder,
        public_message: str,
        expected_category: ViolationCategory,
        sensitive_values: tuple[str, ...],
    ) -> None:
        result = builder()

        assert case_name
        assert result.public_message == public_message
        assert result.action == "deny"
        assert result.allowed is False
        assert result.category is expected_category
        for sensitive in sensitive_values:
            assert sensitive not in result.public_message
            assert sensitive in f"{result.detail} {result.matched_pattern} {result.audit_entry}"
        assert result.matched_text is None

    @pytest.mark.parametrize(
        ("case_name", "builder", "public_message", "expected_category", "sensitive_values"),
        FACTORY_CASES,
        ids=[case[0] for case in FACTORY_CASES],
    )
    def test_public_dict_omits_restricted_fields(
        self,
        case_name: str,
        builder: FactoryBuilder,
        public_message: str,
        expected_category: ViolationCategory,
        sensitive_values: tuple[str, ...],
    ) -> None:
        result = builder()
        public_dict = result.to_public_dict()

        assert case_name
        assert public_message
        assert expected_category
        assert sensitive_values
        assert set(public_dict) == PUBLIC_KEYS
        assert "detail" not in public_dict
        assert "matched_pattern" not in public_dict
        assert "matched_text" not in public_dict
        assert "audit_entry" not in public_dict

    @pytest.mark.parametrize(
        ("case_name", "builder", "public_message", "expected_category", "sensitive_values"),
        FACTORY_CASES,
        ids=[case[0] for case in FACTORY_CASES],
    )
    def test_model_dump_round_trips(
        self,
        case_name: str,
        builder: FactoryBuilder,
        public_message: str,
        expected_category: ViolationCategory,
        sensitive_values: tuple[str, ...],
    ) -> None:
        result = builder()
        roundtripped = PolicyCheckResult.model_validate(result.model_dump())

        assert case_name
        assert public_message
        assert expected_category
        assert sensitive_values
        assert roundtripped == result

    @pytest.mark.parametrize(
        ("case_name", "factory"),
        REDACTABLE_PATTERN_CASES,
        ids=[case[0] for case in REDACTABLE_PATTERN_CASES],
    )
    def test_redactable_factories_preserve_text_only_when_requested(
        self,
        case_name: str,
        factory: Callable[..., PolicyCheckResult],
    ) -> None:
        text = f"matched text for {case_name}"
        redacted = factory("secret-pattern", matched_text=text)
        unredacted = factory("secret-pattern", matched_text=text, redact_user_text=False)

        assert redacted.matched_text is None
        assert unredacted.matched_text == text
