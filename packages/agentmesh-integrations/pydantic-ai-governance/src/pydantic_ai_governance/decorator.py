"""govern() decorator for PydanticAI tool functions.

Wraps tool functions with governance policy checks, semantic intent
classification, and audit logging.
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Optional, TypeVar

from pydantic_ai_governance.audit import AuditTrail
from pydantic_ai_governance.intent import classify_intent
from pydantic_ai_governance.policy import (
    GovernanceEventType,
    GovernancePolicy,
    PolicyCheckResult,
)

F = TypeVar("F", bound=Callable[..., Any])

# Module-level shared state for call counting per policy
_call_counters: dict[int, int] = {}


def govern(
    policy: GovernancePolicy,
    audit: Optional[AuditTrail] = None,
    on_violation: Optional[Callable[[PolicyCheckResult], Any]] = None,
) -> Callable[[F], F]:
    """Decorator that enforces governance policy on a PydanticAI tool.

    Checks tool name allowlist, argument content against blocked patterns,
    semantic intent classification, and call count limits before execution.

    Args:
        policy: Governance policy to enforce.
        audit: Optional audit trail for logging decisions.
        on_violation: Optional callback when a violation is detected.

    Returns:
        Decorated function that raises GovernanceViolation on policy breach.

    Example:
        @agent.tool
        @govern(policy)
        async def dangerous_tool(ctx, query: str) -> str:
            ...
    """

    def decorator(func: F) -> F:
        tool_name = getattr(func, "__name__", str(func))
        policy_id = id(policy)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Track call count
            _call_counters[policy_id] = _call_counters.get(policy_id, 0) + 1
            current_count = _call_counters[policy_id]

            # 1. Check tool allowlist
            result = policy.check_tool(tool_name)
            if not result.allowed:
                _record_and_raise(result, tool_name, audit, on_violation)

            # 2. Check call count limit
            result = policy.check_call_count(current_count)
            if not result.allowed:
                _record_and_raise(result, tool_name, audit, on_violation)

            # 3. Check argument content against blocked patterns
            arg_text = _extract_arg_text(args, kwargs)
            if arg_text:
                result = policy.check_content(arg_text)
                if not result.allowed:
                    _record_and_raise(result, tool_name, audit, on_violation)

                # 4. Semantic intent classification
                classification = classify_intent(
                    arg_text, tool_name=tool_name
                )
                if (
                    classification.confidence >= policy.confidence_threshold
                    and classification.intent.value
                    not in ("benign", "data_read")
                ):
                    violation = PolicyCheckResult(
                        allowed=False,
                        reason=(
                            f"Semantic intent '{classification.intent.value}' "
                            f"detected with confidence {classification.confidence:.2f} "
                            f"(threshold: {policy.confidence_threshold}). "
                            f"Signals: {', '.join(classification.signals)}"
                        ),
                        event_type=GovernanceEventType.TOOL_CALL_BLOCKED,
                        metadata={
                            "intent": classification.intent.value,
                            "confidence": classification.confidence,
                            "signals": classification.signals,
                        },
                    )
                    _record_and_raise(violation, tool_name, audit, on_violation)

            # All checks passed — record and execute
            if audit:
                audit.record(
                    event_type=GovernanceEventType.TOOL_CALL_ALLOWED,
                    tool_name=tool_name,
                    allowed=True,
                    reason="all policy checks passed",
                )

            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            _call_counters[policy_id] = _call_counters.get(policy_id, 0) + 1
            current_count = _call_counters[policy_id]

            result = policy.check_tool(tool_name)
            if not result.allowed:
                _record_and_raise(result, tool_name, audit, on_violation)

            result = policy.check_call_count(current_count)
            if not result.allowed:
                _record_and_raise(result, tool_name, audit, on_violation)

            arg_text = _extract_arg_text(args, kwargs)
            if arg_text:
                result = policy.check_content(arg_text)
                if not result.allowed:
                    _record_and_raise(result, tool_name, audit, on_violation)

                classification = classify_intent(arg_text, tool_name=tool_name)
                if (
                    classification.confidence >= policy.confidence_threshold
                    and classification.intent.value
                    not in ("benign", "data_read")
                ):
                    violation = PolicyCheckResult(
                        allowed=False,
                        reason=(
                            f"Semantic intent '{classification.intent.value}' "
                            f"detected with confidence {classification.confidence:.2f} "
                            f"(threshold: {policy.confidence_threshold}). "
                            f"Signals: {', '.join(classification.signals)}"
                        ),
                        event_type=GovernanceEventType.TOOL_CALL_BLOCKED,
                        metadata={
                            "intent": classification.intent.value,
                            "confidence": classification.confidence,
                            "signals": classification.signals,
                        },
                    )
                    _record_and_raise(violation, tool_name, audit, on_violation)

            if audit:
                audit.record(
                    event_type=GovernanceEventType.TOOL_CALL_ALLOWED,
                    tool_name=tool_name,
                    allowed=True,
                    reason="all policy checks passed",
                )

            return func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def reset_call_counter(policy: GovernancePolicy) -> None:
    """Reset the call counter for a policy (e.g., between requests)."""
    policy_id = id(policy)
    _call_counters.pop(policy_id, None)


class GovernanceViolation(Exception):
    """Raised when a governance policy is violated."""

    def __init__(self, result: PolicyCheckResult) -> None:
        self.result = result
        super().__init__(result.reason)


def _record_and_raise(
    result: PolicyCheckResult,
    tool_name: str,
    audit: Optional[AuditTrail],
    on_violation: Optional[Callable[[PolicyCheckResult], Any]],
) -> None:
    """Record violation in audit trail and raise exception."""
    if audit:
        audit.record(
            event_type=result.event_type,
            tool_name=tool_name,
            allowed=False,
            reason=result.reason,
            metadata=result.metadata,
        )
    if on_violation:
        on_violation(result)
    raise GovernanceViolation(result)


def _extract_arg_text(args: tuple, kwargs: dict) -> str:
    """Extract text content from tool arguments for content checking."""
    parts = []
    # Skip first arg (typically RunContext in PydanticAI tools)
    for arg in args[1:]:
        if isinstance(arg, str):
            parts.append(arg)
        elif isinstance(arg, dict):
            parts.append(json.dumps(arg))
    for val in kwargs.values():
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, dict):
            parts.append(json.dumps(val))
    return " ".join(parts)
