"""GovernanceToolset — apply governance to all tools in a PydanticAI agent.

Wraps PydanticAI's toolset pattern to intercept every tool call
with policy checks before execution.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from pydantic_ai_governance.audit import AuditTrail
from pydantic_ai_governance.intent import classify_intent
from pydantic_ai_governance.policy import (
    GovernanceEventType,
    GovernancePolicy,
    PolicyCheckResult,
)


class GovernanceViolation(Exception):
    """Raised when a governance policy is violated."""

    def __init__(self, result: PolicyCheckResult) -> None:
        self.result = result
        super().__init__(result.reason)


class GovernanceToolset:
    """Toolset wrapper that applies governance policy to all tools.

    Designed to work with PydanticAI's toolset/WrapperToolset pattern.
    Intercepts tool calls with policy checks, semantic intent classification,
    and audit logging.

    Example:
        from pydantic_ai_governance import GovernancePolicy, GovernanceToolset

        policy = GovernancePolicy(
            max_tool_calls_per_request=10,
            blocked_patterns=[("rm -rf", PatternType.SUBSTRING)],
        )
        toolset = GovernanceToolset(policy=policy)

        # Use with PydanticAI agent
        result = toolset.check_tool_call("search", {"query": "hello"})
        assert result.allowed
    """

    def __init__(
        self,
        policy: GovernancePolicy,
        audit: Optional[AuditTrail] = None,
        on_violation: Optional[Callable[[PolicyCheckResult], Any]] = None,
    ) -> None:
        self.policy = policy
        self.audit = audit or AuditTrail()
        self.on_violation = on_violation
        self._call_count = 0

    def reset(self) -> None:
        """Reset call counter (call between requests)."""
        self._call_count = 0

    def check_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_id: Optional[str] = None,
    ) -> PolicyCheckResult:
        """Check if a tool call is allowed by policy.

        Runs all governance checks: allowlist, call count, content,
        and semantic intent classification.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments.
            agent_id: Optional agent identifier for audit.

        Returns:
            PolicyCheckResult indicating if the call is allowed.
        """
        self._call_count += 1

        # 1. Tool allowlist
        result = self.policy.check_tool(tool_name)
        if not result.allowed:
            self._record(result, tool_name, agent_id)
            return result

        # 2. Call count limit
        result = self.policy.check_call_count(self._call_count)
        if not result.allowed:
            self._record(result, tool_name, agent_id)
            return result

        # 3. Content check on arguments
        arg_text = " ".join(
            str(v) for v in arguments.values() if isinstance(v, (str, int, float))
        )
        if arg_text:
            result = self.policy.check_content(arg_text)
            if not result.allowed:
                self._record(result, tool_name, agent_id)
                return result

            # 4. Semantic intent classification
            classification = classify_intent(
                arg_text,
                tool_name=tool_name,
                arguments={k: str(v) for k, v in arguments.items()},
            )
            if (
                classification.confidence >= self.policy.confidence_threshold
                and classification.intent.value not in ("benign", "data_read")
            ):
                result = PolicyCheckResult(
                    allowed=False,
                    reason=(
                        f"Semantic intent '{classification.intent.value}' "
                        f"detected with confidence {classification.confidence:.2f}. "
                        f"Signals: {', '.join(classification.signals)}"
                    ),
                    event_type=GovernanceEventType.TOOL_CALL_BLOCKED,
                    metadata={
                        "intent": classification.intent.value,
                        "confidence": classification.confidence,
                        "signals": classification.signals,
                    },
                )
                self._record(result, tool_name, agent_id)
                return result

        # All checks passed
        allowed = PolicyCheckResult(
            allowed=True,
            event_type=GovernanceEventType.TOOL_CALL_ALLOWED,
        )
        self.audit.record(
            event_type=GovernanceEventType.TOOL_CALL_ALLOWED,
            tool_name=tool_name,
            allowed=True,
            reason="all policy checks passed",
            agent_id=agent_id,
        )
        return allowed

    def _record(
        self,
        result: PolicyCheckResult,
        tool_name: str,
        agent_id: Optional[str],
    ) -> None:
        """Record a violation in the audit trail."""
        self.audit.record(
            event_type=result.event_type,
            tool_name=tool_name,
            allowed=False,
            reason=result.reason,
            agent_id=agent_id,
            metadata=result.metadata,
        )
