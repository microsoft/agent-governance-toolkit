# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Google ADK (Agent Development Kit) Integration for Agent-OS
============================================================

Provides kernel-level governance for Google ADK agent workflows.

Features:
- Extends BaseIntegration with wrap/unwrap for ADK agents
- Policy enforcement via ADK's native callback hooks
- before_tool_callback / after_tool_callback for tool governance
- before_agent_callback / after_agent_callback for agent lifecycle
- Content filtering with blocked patterns
- Tool allow/block lists
- Human approval workflow for sensitive tools
- Token/call budget tracking
- Full audit trail of tool calls and agent runs
- Works without google-adk installed (graceful import handling)
- Compatible with LlmAgent, SequentialAgent, ParallelAgent, LoopAgent

Example:
    >>> from agent_os.integrations.google_adk_adapter import GoogleADKKernel
    >>> from google.adk.agents import LlmAgent
    >>>
    >>> kernel = GoogleADKKernel(
    ...     max_tool_calls=10,
    ...     blocked_tools=["exec_code", "shell"],
    ...     blocked_patterns=["DROP TABLE", "rm -rf"],
    ...     require_human_approval=True,
    ...     sensitive_tools=["delete_file", "send_email"],
    ... )
    >>>
    >>> # Option A: callback injection
    >>> agent = LlmAgent(
    ...     model="gemini-2.5-flash",
    ...     name="assistant",
    ...     tools=[my_tool],
    ...     **kernel.get_callbacks(),
    ... )
    >>>
    >>> # Option B: wrap the agent object
    >>> agent = kernel.wrap(LlmAgent(model="gemini-2.5-flash", name="assistant"))
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .base import BaseIntegration, GovernancePolicy

logger = logging.getLogger(__name__)

# Graceful import of google-adk
try:
    from google.adk.agents import Agent as _ADKAgent  # noqa: F401

    _HAS_ADK = True
except ImportError:
    _HAS_ADK = False


def _check_adk_available() -> None:
    """Raise a helpful error when the ``google-adk`` package is missing."""
    if not _HAS_ADK:
        raise ImportError(
            "The 'google-adk' package is required for live ADK agent wrapping. "
            "Install it with: pip install google-adk"
        )


@dataclass
class PolicyConfig:
    """Policy configuration for Google ADK governance."""

    max_tool_calls: int = 50
    max_agent_calls: int = 20
    timeout_seconds: int = 300

    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)

    blocked_patterns: list[str] = field(default_factory=list)
    pii_detection: bool = True

    log_all_calls: bool = True

    require_human_approval: bool = False
    sensitive_tools: list[str] = field(default_factory=list)

    max_budget: float | None = None


class PolicyViolationError(Exception):
    """Raised when a governance policy is violated."""

    def __init__(self, policy_name: str, description: str, severity: str = "high"):
        self.policy_name = policy_name
        self.description = description
        self.severity = severity
        super().__init__(f"Policy violation ({policy_name}): {description}")


@dataclass
class AuditEvent:
    """Single audit trail entry."""

    timestamp: float
    event_type: str
    agent_name: str
    details: dict[str, Any]


class GoogleADKKernel(BaseIntegration):
    """
    Governance kernel for Google ADK.

    Extends BaseIntegration and provides callback functions that plug
    directly into ADK's before_tool_callback, after_tool_callback,
    before_agent_callback, and after_agent_callback hooks.

    Supports human approval workflows for sensitive tools and
    token/call budget tracking.
    """

    def __init__(
        self,
        policy: PolicyConfig | None = None,
        on_violation: Callable[[PolicyViolationError], None] | None = None,
        *,
        # Convenience kwargs (create PolicyConfig automatically)
        max_tool_calls: int = 50,
        max_agent_calls: int = 20,
        timeout_seconds: int = 300,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
        blocked_patterns: list[str] | None = None,
        require_human_approval: bool = False,
        sensitive_tools: list[str] | None = None,
        max_budget: float | None = None,
    ):
        if policy is not None:
            self._adk_config = policy
        else:
            self._adk_config = PolicyConfig(
                max_tool_calls=max_tool_calls,
                max_agent_calls=max_agent_calls,
                timeout_seconds=timeout_seconds,
                allowed_tools=allowed_tools or [],
                blocked_tools=blocked_tools or [],
                blocked_patterns=blocked_patterns or [],
                require_human_approval=require_human_approval,
                sensitive_tools=sensitive_tools or [],
                max_budget=max_budget,
            )

        # Initialize BaseIntegration with a GovernancePolicy mapped from PolicyConfig
        governance_policy = GovernancePolicy(
            max_tool_calls=self._adk_config.max_tool_calls,
            timeout_seconds=self._adk_config.timeout_seconds,
            allowed_tools=list(self._adk_config.allowed_tools),
            blocked_patterns=list(self._adk_config.blocked_patterns),
            require_human_approval=self._adk_config.require_human_approval,
            log_all_calls=self._adk_config.log_all_calls,
        )
        super().__init__(policy=governance_policy)

        self.on_violation = on_violation or self._default_violation_handler

        # Counters
        self._tool_call_count: int = 0
        self._agent_call_count: int = 0
        self._start_time: float = time.time()
        self._budget_spent: float = 0.0

        # Audit trail
        self._audit_log: list[AuditEvent] = []

        # Violations collected
        self._violations: list[PolicyViolationError] = []

        # Human approval tracking
        self._pending_approvals: dict[str, dict[str, Any]] = {}
        self._approved_calls: dict[str, bool] = {}

        # Wrapped agents registry
        self._wrapped_agents: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # BaseIntegration abstract methods
    # ------------------------------------------------------------------

    def wrap(self, agent: Any) -> Any:
        """
        Wrap an ADK agent with governance callbacks.

        Injects before/after callbacks into the agent if it has the
        expected ADK callback attributes. Otherwise returns a wrapper
        object that delegates attribute access to the original agent.

        Works without google-adk installed (for testing with mocks).
        """
        agent_name = getattr(agent, "name", None) or str(id(agent))

        # Inject callbacks if the agent supports them
        for attr, cb in self.get_callbacks().items():
            if hasattr(agent, attr):
                setattr(agent, attr, cb)

        self._wrapped_agents[agent_name] = agent
        self._record("agent_wrapped", agent_name, {"agent_type": type(agent).__name__})
        logger.info("Wrapped ADK agent '%s' with governance kernel", agent_name)
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper and return the original agent.

        Since ``wrap`` modifies agents in-place (injecting callbacks),
        ``unwrap`` clears the callbacks back to ``None``.
        """
        for attr in self.get_callbacks():
            if hasattr(governed_agent, attr):
                setattr(governed_agent, attr, None)
        agent_name = getattr(governed_agent, "name", None) or str(id(governed_agent))
        self._wrapped_agents.pop(agent_name, None)
        return governed_agent

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_violation_handler(self, error: PolicyViolationError) -> None:
        """Default handler called when a policy violation occurs.

        Logs the violation at ERROR level. Override by passing a custom
        on_violation callable to the kernel constructor.

        Args:
            error: The PolicyViolationError that was raised.
        """
        logger.error(f"Policy violation: {error}")

    def _record(self, event_type: str, agent_name: str, details: dict[str, Any]) -> None:
        """Append an audit event to the internal audit log.

        Records the event only when log_all_calls is enabled.

        Args:
            event_type: Short string label for the event.
            agent_name: Name of the ADK agent generating the event.
            details: Arbitrary dict of additional context.
        """
        if self._adk_config.log_all_calls:
            self._audit_log.append(
                AuditEvent(
                    timestamp=time.time(),
                    event_type=event_type,
                    agent_name=agent_name,
                    details=details,
                )
            )

    def _check_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check whether a tool is permitted by the active ADK policy.

        Args:
            tool_name: Name of the ADK tool to check.

        Returns:
            Tuple of (allowed: bool, reason: str).
        """
        if tool_name in self._adk_config.blocked_tools:
            return False, f"Tool '{tool_name}' is blocked by policy"
        if self._adk_config.allowed_tools and tool_name not in self._adk_config.allowed_tools:
            return False, f"Tool '{tool_name}' not in allowed list"
        return True, ""

    def _check_content(self, content: str) -> tuple[bool, str]:
        """Scan a string for policy-blocked patterns.

        Args:
            content: The text to scan.

        Returns:
            Tuple of (allowed: bool, reason: str).
        """
        content_lower = content.lower()
        for pattern in self._adk_config.blocked_patterns:
            if pattern.lower() in content_lower:
                return False, f"Content matches blocked pattern: '{pattern}'"
        return True, ""

    def _check_timeout(self) -> tuple[bool, str]:
        """Check whether the kernel has exceeded its configured timeout.

        Returns:
            Tuple of (within_limit: bool, reason: str).
        """
        elapsed = time.time() - self._start_time
        if elapsed > self._adk_config.timeout_seconds:
            return False, f"Execution timeout ({elapsed:.0f}s > {self._adk_config.timeout_seconds}s)"
        return True, ""

    def _check_budget(self, cost: float = 1.0) -> tuple[bool, str]:
        """Check whether a tool call would exceed the configured cost budget.

        Args:
            cost: Cost units to add for this call (default 1.0).

        Returns:
            Tuple of (within_budget: bool, reason: str).
        """
        if self._adk_config.max_budget is not None:
            if self._budget_spent + cost > self._adk_config.max_budget:
                return False, (
                    f"Budget exceeded: spent {self._budget_spent} + {cost} "
                    f"> limit {self._adk_config.max_budget}"
                )
        return True, ""

    def _needs_approval(self, tool_name: str) -> bool:
        """Check if a tool call requires human approval."""
        if not self._adk_config.require_human_approval:
            return False
        # If sensitive_tools is specified, only those need approval
        if self._adk_config.sensitive_tools:
            return tool_name in self._adk_config.sensitive_tools
        # Otherwise all tools need approval when require_human_approval is True
        return True

    def _raise_violation(self, policy_name: str, description: str) -> PolicyViolationError:
        """Create, record, and surface a PolicyViolationError.

        Appends the error to the violations list and calls on_violation.

        Args:
            policy_name: Short identifier for the violated policy rule.
            description: Human-readable description of the violation.

        Returns:
            The constructed PolicyViolationError (caller may raise it).
        """
        error = PolicyViolationError(policy_name, description)
        self._violations.append(error)
        self.on_violation(error)
        return error

    # ------------------------------------------------------------------
    # ADK Callback Hooks
    # ------------------------------------------------------------------

    def before_tool_callback(self, tool_context: Any = None, **kwargs: Any) -> dict[str, Any] | None:
        """
        ADK before_tool_callback — called before each tool execution.

        Compatible with ADK's ToolContext. If tool_context is not an ADK
        ToolContext (e.g., in tests), falls back to kwargs for tool_name/tool_args.

        Returns:
            None to allow execution, or a dict with an error to block it.
        """
        tool_name = getattr(tool_context, "tool_name", kwargs.get("tool_name", "unknown"))
        tool_args = getattr(tool_context, "tool_args", kwargs.get("tool_args", {}))
        agent_name = getattr(tool_context, "agent_name", kwargs.get("agent_name", "unknown"))

        self._record("before_tool", agent_name, {"tool": tool_name, "args": tool_args})

        # Check timeout
        ok, reason = self._check_timeout()
        if not ok:
            error = self._raise_violation("timeout", reason)
            return {"error": str(error)}

        # Check tool count
        self._tool_call_count += 1
        if self._tool_call_count > self._adk_config.max_tool_calls:
            error = self._raise_violation(
                "tool_limit",
                f"Tool call count ({self._tool_call_count}) exceeds limit ({self._adk_config.max_tool_calls})",
            )
            return {"error": str(error)}

        # Check budget
        cost = kwargs.get("cost", 1.0)
        ok, reason = self._check_budget(cost)
        if not ok:
            error = self._raise_violation("budget_exceeded", reason)
            return {"error": str(error)}

        # Check tool allowed
        ok, reason = self._check_tool_allowed(tool_name)
        if not ok:
            error = self._raise_violation("tool_filter", reason)
            return {"error": str(error)}

        # Check content in arguments
        if isinstance(tool_args, dict):
            for value in tool_args.values():
                if isinstance(value, str):
                    ok, reason = self._check_content(value)
                    if not ok:
                        error = self._raise_violation("content_filter", reason)
                        return {"error": str(error)}

        # Human approval check
        if self._needs_approval(tool_name):
            call_id = f"{agent_name}:{tool_name}:{self._tool_call_count}"
            if call_id not in self._approved_calls:
                self._pending_approvals[call_id] = {
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "agent_name": agent_name,
                    "timestamp": time.time(),
                }
                self._record("approval_required", agent_name, {
                    "tool": tool_name, "call_id": call_id,
                })
                error = self._raise_violation(
                    "human_approval_required",
                    f"Tool '{tool_name}' requires human approval (call_id={call_id})",
                )
                return {"error": str(error), "call_id": call_id, "needs_approval": True}

        # Track budget spend
        self._budget_spent += cost

        return None  # Allow execution

    def after_tool_callback(
        self,
        tool_context: Any = None,
        tool_result: Any = None,
        **kwargs: Any,
    ) -> Any:
        """
        ADK after_tool_callback — called after each tool execution.

        Inspects tool output for blocked patterns.

        Returns:
            The (possibly modified) tool_result, or a dict with error if blocked.
        """
        tool_name = getattr(tool_context, "tool_name", kwargs.get("tool_name", "unknown"))
        agent_name = getattr(tool_context, "agent_name", kwargs.get("agent_name", "unknown"))

        self._record("after_tool", agent_name, {"tool": tool_name, "result_type": type(tool_result).__name__})

        # Check output content
        if isinstance(tool_result, str):
            ok, reason = self._check_content(tool_result)
            if not ok:
                error = self._raise_violation("output_filter", reason)
                return {"error": str(error)}

        if isinstance(tool_result, dict):
            for value in tool_result.values():
                if isinstance(value, str):
                    ok, reason = self._check_content(value)
                    if not ok:
                        error = self._raise_violation("output_filter", reason)
                        return {"error": str(error)}

        return tool_result

    def before_agent_callback(self, callback_context: Any = None, **kwargs: Any) -> Any:
        """
        ADK before_agent_callback — called before agent starts processing.

        Returns:
            None to allow, or a Content-like object to skip the agent.
        """
        agent_name = getattr(callback_context, "agent_name", kwargs.get("agent_name", "unknown"))

        self._record("before_agent", agent_name, {})

        # Check timeout
        ok, reason = self._check_timeout()
        if not ok:
            error = self._raise_violation("timeout", reason)
            return {"error": str(error)}

        # Check agent call count
        self._agent_call_count += 1
        if self._agent_call_count > self._adk_config.max_agent_calls:
            error = self._raise_violation(
                "agent_limit",
                f"Agent call count ({self._agent_call_count}) exceeds limit ({self._adk_config.max_agent_calls})",
            )
            return {"error": str(error)}

        return None

    def after_agent_callback(
        self,
        callback_context: Any = None,
        content: Any = None,
        **kwargs: Any,
    ) -> Any:
        """
        ADK after_agent_callback — called after agent finishes.

        Checks agent output for blocked content.

        Returns:
            The content (possibly modified), or a dict with error if blocked.
        """
        agent_name = getattr(callback_context, "agent_name", kwargs.get("agent_name", "unknown"))

        self._record("after_agent", agent_name, {"has_content": content is not None})

        # Check output content if it's a string
        if isinstance(content, str):
            ok, reason = self._check_content(content)
            if not ok:
                error = self._raise_violation("output_filter", reason)
                return {"error": str(error)}

        return content

    # ------------------------------------------------------------------
    # Human Approval API
    # ------------------------------------------------------------------

    def approve(self, call_id: str) -> bool:
        """Approve a pending tool call by its call_id.

        Returns True if the call was pending and is now approved.
        """
        if call_id in self._pending_approvals:
            self._approved_calls[call_id] = True
            info = self._pending_approvals.pop(call_id)
            self._record("approval_granted", info.get("agent_name", "unknown"), {
                "call_id": call_id, "tool": info.get("tool_name"),
            })
            return True
        return False

    def deny(self, call_id: str) -> bool:
        """Deny a pending tool call by its call_id.

        Returns True if the call was pending and is now denied.
        """
        if call_id in self._pending_approvals:
            info = self._pending_approvals.pop(call_id)
            self._record("approval_denied", info.get("agent_name", "unknown"), {
                "call_id": call_id, "tool": info.get("tool_name"),
            })
            return True
        return False

    def get_pending_approvals(self) -> dict[str, dict[str, Any]]:
        """Return all pending approval requests."""
        return dict(self._pending_approvals)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset counters and start time (for new execution runs)."""
        self._tool_call_count = 0
        self._agent_call_count = 0
        self._start_time = time.time()
        self._budget_spent = 0.0

    def get_audit_log(self) -> list[AuditEvent]:
        """Return the full audit trail."""
        return list(self._audit_log)

    def get_violations(self) -> list[PolicyViolationError]:
        """Return all collected violations."""
        return list(self._violations)

    def get_stats(self) -> dict[str, Any]:
        """Get governance statistics."""
        return {
            "tool_calls": self._tool_call_count,
            "agent_calls": self._agent_call_count,
            "violations": len(self._violations),
            "audit_events": len(self._audit_log),
            "elapsed_seconds": round(time.time() - self._start_time, 2),
            "budget_spent": self._budget_spent,
            "budget_limit": self._adk_config.max_budget,
            "pending_approvals": len(self._pending_approvals),
            "policy": {
                "max_tool_calls": self._adk_config.max_tool_calls,
                "max_agent_calls": self._adk_config.max_agent_calls,
                "blocked_tools": self._adk_config.blocked_tools,
                "allowed_tools": self._adk_config.allowed_tools,
                "require_human_approval": self._adk_config.require_human_approval,
                "sensitive_tools": self._adk_config.sensitive_tools,
            },
        }

    def get_callbacks(self) -> dict[str, Any]:
        """
        Return a dict of all callbacks suitable for unpacking into LlmAgent.

        Usage:
            agent = LlmAgent(..., **kernel.get_callbacks())
        """
        return {
            "before_tool_callback": self.before_tool_callback,
            "after_tool_callback": self.after_tool_callback,
            "before_agent_callback": self.before_agent_callback,
            "after_agent_callback": self.after_agent_callback,
        }

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        elapsed = time.time() - self._start_time
        has_violations = len(self._violations) > 0
        return {
            "status": "degraded" if has_violations else "healthy",
            "backend": "google_adk",
            "adk_available": _HAS_ADK,
            "wrapped_agents": len(self._wrapped_agents),
            "violations": len(self._violations),
            "uptime_seconds": round(elapsed, 2),
        }


__all__ = [
    "GoogleADKKernel",
    "PolicyConfig",
    "PolicyViolationError",
    "AuditEvent",
    "_HAS_ADK",
    "_check_adk_available",
]
