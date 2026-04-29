# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Factories for structured policy-denial decisions."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .decision import PolicyCheckResult, ViolationCategory

_PUBLIC_MESSAGES: dict[ViolationCategory, str] = {
    ViolationCategory.BLOCKED_PATTERN_INPUT: "Content blocked by governance policy.",
    ViolationCategory.BLOCKED_PATTERN_TOOL: "Content blocked by governance policy.",
    ViolationCategory.BLOCKED_PATTERN_OUTPUT: "Content blocked by governance policy.",
    ViolationCategory.BLOCKED_PATTERN_MEMORY: "Content blocked by governance policy.",
    ViolationCategory.NOT_ALLOWED_TOOL: "Tool not permitted by governance policy.",
    ViolationCategory.BLOCKED_TOOL: "Tool blocked by governance policy.",
    ViolationCategory.MAX_TOOL_CALLS: "Tool-call limit exceeded.",
    ViolationCategory.TIMEOUT: "Execution timeout exceeded.",
    ViolationCategory.HUMAN_APPROVAL: "Human approval required.",
    ViolationCategory.CONFIDENCE_THRESHOLD: "Confidence below required threshold.",
    ViolationCategory.POLICY_ERROR: "Policy evaluation error.",
    ViolationCategory.DRIFT: "Behavioral drift detected.",
}


def _deny_result(
    *,
    category: ViolationCategory,
    detail: str,
    matched_rule: str | None = None,
    matched_pattern: str | None = None,
    matched_text: str | None = None,
    scope: str | None = None,
    operation: str | None = None,
    tool_name: str | None = None,
    index: int | None = None,
    audit_entry: dict[str, Any] | None = None,
) -> PolicyCheckResult:
    """Build a common denied policy-check result."""

    return PolicyCheckResult(
        allowed=False,
        action="deny",
        category=category,
        matched_rule=matched_rule,
        public_message=_PUBLIC_MESSAGES[category],
        detail=detail,
        reason=detail,
        matched_pattern=matched_pattern,
        matched_text=matched_text,
        scope=scope,
        operation=operation,
        tool_name=tool_name,
        index=index,
        audit_entry=audit_entry or {},
    )


def deny_blocked_pattern_input(
    matched_pattern: str,
    matched_text: str | None = None,
    *,
    rule_name: str | None = None,
    redact_user_text: bool = True,
) -> PolicyCheckResult:
    """Return a denial for an input blocked-pattern match."""

    detail = f"Blocked pattern detected: {matched_pattern}"
    return _deny_result(
        category=ViolationCategory.BLOCKED_PATTERN_INPUT,
        detail=detail,
        matched_rule=rule_name,
        matched_pattern=matched_pattern,
        matched_text=None if redact_user_text else matched_text,
        scope="input",
        audit_entry={"matched_pattern": matched_pattern},
    )


def deny_blocked_pattern_tool(
    matched_pattern: str,
    *,
    tool_name: str | None = None,
    scope_label: str = "tool",
    redact_user_text: bool = True,
    matched_text: str | None = None,
) -> PolicyCheckResult:
    """Return a denial for a tool-argument blocked-pattern match."""

    if tool_name:
        detail = f"Blocked pattern '{matched_pattern}' detected in tool '{tool_name}' arguments"
    else:
        detail = f"Blocked pattern '{matched_pattern}' detected in tool arguments"
    return _deny_result(
        category=ViolationCategory.BLOCKED_PATTERN_TOOL,
        detail=detail,
        matched_pattern=matched_pattern,
        matched_text=None if redact_user_text else matched_text,
        scope=scope_label,
        tool_name=tool_name,
        audit_entry={"matched_pattern": matched_pattern},
    )


def deny_blocked_pattern_output(
    matched_pattern: str,
    *,
    redact_user_text: bool = True,
    matched_text: str | None = None,
) -> PolicyCheckResult:
    """Return a denial for an output blocked-pattern match."""

    detail = f"Blocked pattern detected in output: {matched_pattern}"
    return _deny_result(
        category=ViolationCategory.BLOCKED_PATTERN_OUTPUT,
        detail=detail,
        matched_pattern=matched_pattern,
        matched_text=None if redact_user_text else matched_text,
        scope="output",
        audit_entry={"matched_pattern": matched_pattern},
    )


def deny_blocked_pattern_memory(
    matched_pattern: str,
    *,
    redact_user_text: bool = True,
    matched_text: str | None = None,
) -> PolicyCheckResult:
    """Return a denial for a memory-write blocked-pattern match."""

    detail = f"Memory write blocked: blocked pattern '{matched_pattern}' detected"
    return _deny_result(
        category=ViolationCategory.BLOCKED_PATTERN_MEMORY,
        detail=detail,
        matched_pattern=matched_pattern,
        matched_text=None if redact_user_text else matched_text,
        scope="memory",
        audit_entry={"matched_pattern": matched_pattern},
    )


def deny_blocked_tool(tool_name: str) -> PolicyCheckResult:
    """Return a denial for a tool that matches a blocked tool pattern."""

    detail = f"Tool '{tool_name}' matches blocked pattern"
    return _deny_result(
        category=ViolationCategory.BLOCKED_TOOL,
        detail=detail,
        scope="tool",
        tool_name=tool_name,
        audit_entry={"tool_name": tool_name},
    )


def deny_not_allowed_tool(tool_name: str, allowed: Sequence[str]) -> PolicyCheckResult:
    """Return a denial for a tool outside the configured allow-list."""

    detail = f"Tool '{tool_name}' not in allowed list: {allowed}"
    return _deny_result(
        category=ViolationCategory.NOT_ALLOWED_TOOL,
        detail=detail,
        scope="tool",
        tool_name=tool_name,
        audit_entry={"allowed_tools": list(allowed), "tool_name": tool_name},
    )


def deny_max_tool_calls(limit: int, current: int | None = None) -> PolicyCheckResult:
    """Return a denial for exceeding the configured tool-call limit."""

    detail = f"Max tool calls exceeded ({limit})"
    audit_entry: dict[str, Any] = {"limit": limit}
    if current is not None:
        audit_entry["current"] = current
    return _deny_result(
        category=ViolationCategory.MAX_TOOL_CALLS,
        detail=detail,
        scope="tool",
        audit_entry=audit_entry,
    )


def deny_timeout(limit_s: int | float, elapsed_s: int | float | None = None) -> PolicyCheckResult:
    """Return a denial for exceeding the configured execution timeout."""

    detail = f"Timeout exceeded ({limit_s}s)"
    audit_entry: dict[str, Any] = {"limit_s": limit_s}
    if elapsed_s is not None:
        audit_entry["elapsed_s"] = elapsed_s
    return _deny_result(
        category=ViolationCategory.TIMEOUT,
        detail=detail,
        audit_entry=audit_entry,
    )


def deny_human_approval(tool_name: str | None = None) -> PolicyCheckResult:
    """Return a denial for a human-approval requirement."""

    if tool_name:
        detail = f"Tool '{tool_name}' requires human approval per governance policy"
    else:
        detail = "Execution requires human approval per governance policy"
    return _deny_result(
        category=ViolationCategory.HUMAN_APPROVAL,
        detail=detail,
        scope="tool" if tool_name else None,
        tool_name=tool_name,
        audit_entry={"tool_name": tool_name} if tool_name else {},
    )


def deny_confidence_threshold(
    threshold: float,
    observed: float | None = None,
) -> PolicyCheckResult:
    """Return a denial for a confidence score below the configured threshold."""

    if observed is None:
        detail = f"Confidence below threshold of {threshold}"
    else:
        detail = f"Confidence {observed:.2f} below threshold {threshold:.2f}"
    audit_entry: dict[str, Any] = {"threshold": threshold}
    if observed is not None:
        audit_entry["observed"] = observed
    return _deny_result(
        category=ViolationCategory.CONFIDENCE_THRESHOLD,
        detail=detail,
        audit_entry=audit_entry,
    )


def deny_policy_error(detail: str, *, matched_rule: str | None = None) -> PolicyCheckResult:
    """Return a denial for a policy evaluation error or fail-closed decision."""

    return _deny_result(
        category=ViolationCategory.POLICY_ERROR,
        detail=detail,
        matched_rule=matched_rule,
        audit_entry={"matched_rule": matched_rule} if matched_rule else {},
    )


def deny_drift(
    score: float,
    threshold: float,
    *,
    baseline_hash: str | None = None,
    current_hash: str | None = None,
) -> PolicyCheckResult:
    """Return a denial for behavioral drift above the configured threshold."""

    detail = f"Drift score {score:.2f} exceeds threshold {threshold:.2f}"
    audit_entry: dict[str, Any] = {"drift_score": score, "threshold": threshold}
    if baseline_hash is not None:
        audit_entry["baseline_hash"] = baseline_hash
    if current_hash is not None:
        audit_entry["current_hash"] = current_hash
    return _deny_result(
        category=ViolationCategory.DRIFT,
        detail=detail,
        scope="output",
        audit_entry=audit_entry,
    )
