# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Audit event categories shared by the Pydantic AI integration."""

from enum import Enum


class GovernanceEventType(Enum):
    """Events emitted by surviving audit and trust features."""

    POLICY_CHECK = "policy_check"
    POLICY_VIOLATION = "policy_violation"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    TOOL_CALL_ALLOWED = "tool_call_allowed"
    TRUST_CHECK = "trust_check"
