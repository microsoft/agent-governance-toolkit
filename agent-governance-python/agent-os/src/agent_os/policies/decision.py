# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Structured policy check decisions for integration-layer governance."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ViolationCategory(str, Enum):
    """Categories for integration-layer policy violations."""

    BLOCKED_TOOL = "blocked_tool"
    NOT_ALLOWED_TOOL = "not_allowed_tool"
    BLOCKED_PATTERN_INPUT = "blocked_pattern_input"
    BLOCKED_PATTERN_TOOL = "blocked_pattern_tool"
    BLOCKED_PATTERN_OUTPUT = "blocked_pattern_output"
    BLOCKED_PATTERN_MEMORY = "blocked_pattern_memory"
    MAX_TOOL_CALLS = "max_tool_calls"
    TIMEOUT = "timeout"
    HUMAN_APPROVAL = "human_approval_required"
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    DRIFT = "drift"
    POLICY_ERROR = "policy_error"


class PolicyCheckResult(BaseModel):
    """Structured result of an integration-layer policy check.

    Attributes:
        allowed: Whether the policy check allows the operation.
        action: Policy action associated with the result.
        category: Optional structured violation category.
        matched_rule: Optional declarative or legacy rule identifier.
        public_message: Sanitized message safe for end users.
        detail: Restricted details for logs and audits.
        reason: Legacy free-form reason returned by tuple wrappers.
        matched_pattern: Policy pattern that matched, when applicable.
        matched_text: User text span that matched; omitted by default.
        scope: Scope checked by the policy decision.
        operation: Adapter-defined operation name.
        tool_name: Tool name associated with the result.
        index: Batch index associated with the result.
        audit_entry: Additional structured audit metadata.
    """

    allowed: bool = True
    action: str = "allow"
    category: ViolationCategory | None = None
    matched_rule: str | None = None
    public_message: str = ""
    detail: str = ""
    reason: str = ""
    matched_pattern: str | None = None
    matched_text: str | None = None
    scope: str | None = None
    operation: str | None = None
    tool_name: str | None = None
    index: int | None = None
    audit_entry: dict[str, Any] = Field(default_factory=dict)

    def to_legacy_tuple(self) -> tuple[bool, str | None]:
        """Convert this result to the legacy ``(allowed, reason)`` tuple."""

        return self.allowed, (None if self.allowed else (self.reason or self.detail))

    def to_public_dict(self) -> dict[str, Any]:
        """Return a sanitized public representation of this result."""

        return {
            "allowed": self.allowed,
            "action": self.action,
            "category": self.category.value if self.category else None,
            "matched_rule": self.matched_rule,
            "public_message": self.public_message,
        }
