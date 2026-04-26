# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Bridge between legacy GovernancePolicy and declarative PolicyDocument.

Provides bidirectional conversion so existing code continues to work while
new code can use the declarative policy format.
"""

from __future__ import annotations

from ..integrations.base import GovernancePolicy, PatternType
from .schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


def governance_to_document(policy: GovernancePolicy) -> PolicyDocument:
    """Convert an existing GovernancePolicy to a declarative PolicyDocument."""
    rules: list[PolicyRule] = []
    priority = 100

    # Token limit rule
    rules.append(
        PolicyRule(
            name="max_tokens",
            condition=PolicyCondition(
                field="token_count",
                operator=PolicyOperator.GT,
                value=policy.max_tokens,
            ),
            action=PolicyAction.DENY,
            priority=priority,
            message=f"Token count exceeds limit of {policy.max_tokens}",
        )
    )
    priority -= 1

    # Tool call limit rule
    rules.append(
        PolicyRule(
            name="max_tool_calls",
            condition=PolicyCondition(
                field="tool_call_count",
                operator=PolicyOperator.GT,
                value=policy.max_tool_calls,
            ),
            action=PolicyAction.DENY,
            priority=priority,
            message=f"Tool call count exceeds limit of {policy.max_tool_calls}",
        )
    )
    priority -= 1

    # Allowed tools rule (if a tool is not in the allowed list, deny)
    if policy.allowed_tools:
        rules.append(
            PolicyRule(
                name="allowed_tools",
                condition=PolicyCondition(
                    field="tool_name",
                    operator=PolicyOperator.IN,
                    value=policy.allowed_tools,
                ),
                action=PolicyAction.ALLOW,
                priority=priority,
                message="Tool is in the allowed list",
            )
        )
        priority -= 1

    # Blocked patterns
    for i, pattern in enumerate(policy.blocked_patterns):
        if isinstance(pattern, str):
            pat_str = pattern
            operator = PolicyOperator.CONTAINS
        else:
            pat_str, pat_type = pattern
            if pat_type == PatternType.REGEX:
                operator = PolicyOperator.MATCHES
            elif pat_type == PatternType.GLOB:
                operator = PolicyOperator.MATCHES
            else:
                operator = PolicyOperator.CONTAINS

        rules.append(
            PolicyRule(
                name=f"blocked_pattern_{i}",
                condition=PolicyCondition(
                    field="content",
                    operator=operator,
                    value=pat_str,
                ),
                action=PolicyAction.BLOCK,
                priority=priority,
                message=f"Content matches blocked pattern: {pat_str}",
            )
        )
        priority -= 1

    # Confidence threshold rule
    rules.append(
        PolicyRule(
            name="confidence_threshold",
            condition=PolicyCondition(
                field="confidence",
                operator=PolicyOperator.LT,
                value=policy.confidence_threshold,
            ),
            action=PolicyAction.DENY,
            priority=priority,
            message=f"Confidence below threshold of {policy.confidence_threshold}",
        )
    )

    return PolicyDocument(
        version=policy.version,
        name=policy.name,
        description=f"Auto-converted from GovernancePolicy '{policy.name}'",
        rules=rules,
        defaults=PolicyDefaults(
            action=PolicyAction.ALLOW,
            max_tokens=policy.max_tokens,
            max_tool_calls=policy.max_tool_calls,
            confidence_threshold=policy.confidence_threshold,
        ),
    )


def document_to_governance(doc: PolicyDocument) -> GovernancePolicy:
    """Convert a declarative PolicyDocument back to a GovernancePolicy."""
    max_tokens = doc.defaults.max_tokens
    max_tool_calls = doc.defaults.max_tool_calls
    confidence_threshold = doc.defaults.confidence_threshold
    allowed_tools: list[str] = []
    blocked_patterns: list[str | tuple[str, PatternType]] = []

    for rule in doc.rules:
        cond = rule.condition

        if rule.name == "max_tokens" and cond.field == "token_count":
            max_tokens = int(cond.value)
        elif rule.name == "max_tool_calls" and cond.field == "tool_call_count":
            max_tool_calls = int(cond.value)
        elif rule.name == "allowed_tools" and cond.field == "tool_name":
            if isinstance(cond.value, list):
                allowed_tools = list(cond.value)
        elif rule.name.startswith("blocked_pattern_") and cond.field == "content":
            if cond.operator == PolicyOperator.MATCHES:
                blocked_patterns.append((str(cond.value), PatternType.REGEX))
            elif cond.operator == PolicyOperator.CONTAINS:
                blocked_patterns.append(str(cond.value))
        elif rule.name == "confidence_threshold" and cond.field == "confidence":
            confidence_threshold = float(cond.value)

    return GovernancePolicy(
        name=doc.name,
        max_tokens=max_tokens,
        max_tool_calls=max_tool_calls,
        allowed_tools=allowed_tools,
        blocked_patterns=blocked_patterns,
        confidence_threshold=confidence_threshold,
        version=doc.version,
    )
