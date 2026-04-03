# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HuggingFace smolagents Integration for Agent-OS
================================================

Provides kernel-level governance for smolagents agent workflows.

Features:
- Extends BaseIntegration with wrap/unwrap for smolagents agents
- Policy enforcement via tool-call interception
- Tool allow/block lists
- Content filtering with blocked patterns
- Human approval workflow for sensitive tools
- Token/call budget tracking
- Full audit trail of tool calls and agent runs
- Works without smolagents installed (graceful import handling)
- Compatible with CodeAgent and ToolCallingAgent

Example:
    >>> from agent_os.integrations.smolagents_adapter import SmolagentsKernel
    >>>
    >>> kernel = SmolagentsKernel(
    ...     max_tool_calls=10,
    ...     blocked_tools=["exec_code", "shell"],
    ...     blocked_patterns=["DROP TABLE", "rm -rf"],
    ...     require_human_approval=True,
    ...     sensitive_tools=["delete_file", "send_email"],
    ... )
    >>>
    >>> # Wrap an existing agent
    >>> from smolagents import CodeAgent, HfApiModel
    >>> agent = CodeAgent(tools=[my_tool], model=HfApiModel())
    >>> governed = kernel.wrap(agent)
    >>> result = governed.run("Summarize this document")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .base import BaseIntegration, GovernancePolicy

logger = logging.getLogger(__name__)

# Graceful import of smolagents
try:
    import smolagents as _smolagents  # noqa: F401

    _HAS_SMOLAGENTS = True
except ImportError:
    _HAS_SMOLAGENTS = False


def _check_smolagents_available() -> None:
    """Raise a helpful error when the ``smolagents`` package is missing."""
    if not _HAS_SMOLAGENTS:
        raise ImportError(
            "The 'smolagents' package is required for live smolagents agent wrapping. "
            "Install it with: pip install smolagents"
        )


@dataclass
class PolicyConfig:
    """Policy configuration for smolagents governance."""

    max_tool_calls: int = 50
    max_agent_calls: int = 20
    timeout_seconds: int = 300

    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)

    blocked_patterns: list[str] = field(default_factory=list)

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


class SmolagentsKernel(BaseIntegration):
    """
    Governance kernel for HuggingFace smolagents.

    Extends BaseIntegration and intercepts tool calls on smolagents
    CodeAgent and ToolCallingAgent instances by wrapping each tool's
    ``forward`` method with governance checks.

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
            self._sm_config = policy
        else:
            self._sm_config = PolicyConfig(
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
            max_tool_calls=self._sm_config.max_tool_calls,
            timeout_seconds=self._sm_config.timeout_seconds,
            allowed_tools=list(self._sm_config.allowed_tools),
            blocked_patterns=list(self._sm_config.blocked_patterns),
            require_human_approval=self._sm_config.require_human_approval,
            log_all_calls=self._sm_config.log_all_calls,
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

        # Wrapped agents registry and original forward methods
        self._wrapped_agents: dict[str, Any] = {}
        self._original_forwards: dict[str, Callable[..., Any]] = {}

    # ------------------------------------------------------------------
    # BaseIntegration abstract methods
    # ------------------------------------------------------------------

    def wrap(self, agent: Any) -> Any:
        """
        Wrap a smolagents agent with governance.

        Intercepts each tool's ``forward`` method so that every tool call
        passes through policy checks before execution.  The agent's
        ``toolbox`` (dict of tool-name → Tool) is iterated and each tool
        is wrapped in-place.

        Works without smolagents installed (for testing with mocks).
        """
        agent_name = getattr(agent, "name", None) or str(id(agent))

        # smolagents stores tools in agent.toolbox (dict-like or has .tools)
        tools = self._get_tools(agent)
        for tool_name, tool_obj in tools.items():
            self._wrap_tool(tool_obj, tool_name, agent_name)

        self._wrapped_agents[agent_name] = agent
        self._record("agent_wrapped", agent_name, {"agent_type": type(agent).__name__})
        logger.info("Wrapped smolagents agent '%s' with governance kernel", agent_name)
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper and restore original tool forwards."""
        agent_name = getattr(governed_agent, "name", None) or str(id(governed_agent))

        tools = self._get_tools(governed_agent)
        for tool_name, tool_obj in tools.items():
            key = f"{agent_name}:{tool_name}"
            if key in self._original_forwards:
                tool_obj.forward = self._original_forwards.pop(key)

        self._wrapped_agents.pop(agent_name, None)
        return governed_agent

    # ------------------------------------------------------------------
    # Tool wrapping
    # ------------------------------------------------------------------

    @staticmethod
    def _get_tools(agent: Any) -> dict[str, Any]:
        """Extract the tool dict from a smolagents agent.

        smolagents agents expose tools via ``agent.toolbox`` which may be
        a ``Toolbox`` object (with a ``.tools`` dict) or a plain dict.
        Falls back to an empty dict when no toolbox is found.
        """
        toolbox = getattr(agent, "toolbox", None)
        if toolbox is None:
            return {}
        # Toolbox object has a .tools dict
        if hasattr(toolbox, "tools"):
            return toolbox.tools
        # Plain dict
        if isinstance(toolbox, dict):
            return toolbox
        return {}

    def _wrap_tool(self, tool: Any, tool_name: str, agent_name: str) -> None:
        """Replace ``tool.forward`` with a governed version."""
        original_forward = tool.forward
        key = f"{agent_name}:{tool_name}"
        self._original_forwards[key] = original_forward

        kernel = self

        def governed_forward(*args: Any, **kwargs: Any) -> Any:
            """Governed wrapper around a smolagents tool's forward method.

            Intercepts the tool invocation, validates the call against
            the active policy, updates call counters and the audit log,
            then delegates to the original forward implementation.

            Args:
                *args: Positional arguments forwarded to the original tool.
                **kwargs: Keyword arguments forwarded to the original tool.

            Returns:
                The result from the original tool's forward method.

            Raises:
                PolicyViolationError: If the call violates the active policy.
            """
            # Pre-execution governance check
            result = kernel.before_tool_call(
                tool_name=tool_name,
                tool_args=kwargs or (args[0] if args else {}),
                agent_name=agent_name,
            )
            if result is not None:
                raise PolicyViolationError(
                    result.get("policy", "governance"),
                    result.get("error", "Tool call blocked by policy"),
                )

            # Execute original tool
            output = original_forward(*args, **kwargs)

            # Post-execution governance check
            filtered = kernel.after_tool_call(
                tool_name=tool_name,
                tool_result=output,
                agent_name=agent_name,
            )
            return filtered

        tool.forward = governed_forward

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_violation_handler(self, error: PolicyViolationError) -> None:
        """Default handler called when a policy violation occurs.

        Logs the violation as an error. Override by passing a custom
        on_violation callback to the kernel constructor.

        Args:
            error: The PolicyViolationError that was raised.
        """
        logger.error(f"Policy violation: {error}")

    def _record(self, event_type: str, agent_name: str, details: dict[str, Any]) -> None:
        """Append an audit event to the internal audit log.

        Records the event only when log_all_calls is enabled.

        Args:
            event_type: Short string label for the event.
            agent_name: ID or name of the agent generating the event.
            details: Arbitrary dict of additional context.
        """
        if self._sm_config.log_all_calls:
            self._audit_log.append(
                AuditEvent(
                    timestamp=time.time(),
                    event_type=event_type,
                    agent_name=agent_name,
                    details=details,
                )
            )

    def _check_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check whether a tool is permitted by the active policy.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            Tuple of (allowed: bool, reason: str).
        """
        if tool_name in self._sm_config.blocked_tools:
            return False, f"Tool '{tool_name}' is blocked by policy"
        if self._sm_config.allowed_tools and tool_name not in self._sm_config.allowed_tools:
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
        for pattern in self._sm_config.blocked_patterns:
            if pattern.lower() in content_lower:
                return False, f"Content matches blocked pattern: '{pattern}'"
        return True, ""

    def _check_timeout(self) -> tuple[bool, str]:
        """Check whether the kernel has exceeded its configured timeout.

        Returns:
            Tuple of (within_limit: bool, reason: str).
        """
        elapsed = time.time() - self._start_time
        if elapsed > self._sm_config.timeout_seconds:
            return False, f"Execution timeout ({elapsed:.0f}s > {self._sm_config.timeout_seconds}s)"
        return True, ""

    def _check_budget(self, cost: float = 1.0) -> tuple[bool, str]:
        """Check whether a tool call would exceed the configured cost budget.

        Args:
            cost: Cost units to add for this call (default 1.0).

        Returns:
            Tuple of (within_budget: bool, reason: str).
        """
        if self._sm_config.max_budget is not None:
            if self._budget_spent + cost > self._sm_config.max_budget:
                return False, (
                    f"Budget exceeded: spent {self._budget_spent} + {cost} "
                    f"> limit {self._sm_config.max_budget}"
                )
        return True, ""

    def _needs_approval(self, tool_name: str) -> bool:
        """Check if a tool call requires human approval."""
        if not self._sm_config.require_human_approval:
            return False
        if self._sm_config.sensitive_tools:
            return tool_name in self._sm_config.sensitive_tools
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
    # Tool-call governance hooks
    # ------------------------------------------------------------------

    def before_tool_call(
        self,
        tool_name: str = "unknown",
        tool_args: Any = None,
        agent_name: str = "unknown",
        cost: float = 1.0,
    ) -> dict[str, Any] | None:
        """
        Pre-execution governance check for a tool call.

        Returns None to allow execution, or a dict with error info to block it.
        """
        if tool_args is None:
            tool_args = {}

        self._record("before_tool", agent_name, {"tool": tool_name, "args": tool_args})

        # Check timeout
        ok, reason = self._check_timeout()
        if not ok:
            error = self._raise_violation("timeout", reason)
            return {"error": str(error), "policy": "timeout"}

        # Check tool count
        self._tool_call_count += 1
        if self._tool_call_count > self._sm_config.max_tool_calls:
            error = self._raise_violation(
                "tool_limit",
                f"Tool call count ({self._tool_call_count}) exceeds limit ({self._sm_config.max_tool_calls})",
            )
            return {"error": str(error), "policy": "tool_limit"}

        # Check budget
        ok, reason = self._check_budget(cost)
        if not ok:
            error = self._raise_violation("budget_exceeded", reason)
            return {"error": str(error), "policy": "budget_exceeded"}

        # Check tool allowed
        ok, reason = self._check_tool_allowed(tool_name)
        if not ok:
            error = self._raise_violation("tool_filter", reason)
            return {"error": str(error), "policy": "tool_filter"}

        # Check content in arguments
        if isinstance(tool_args, dict):
            for value in tool_args.values():
                if isinstance(value, str):
                    ok, reason = self._check_content(value)
                    if not ok:
                        error = self._raise_violation("content_filter", reason)
                        return {"error": str(error), "policy": "content_filter"}
        elif isinstance(tool_args, str):
            ok, reason = self._check_content(tool_args)
            if not ok:
                error = self._raise_violation("content_filter", reason)
                return {"error": str(error), "policy": "content_filter"}

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
                return {
                    "error": str(error),
                    "call_id": call_id,
                    "needs_approval": True,
                    "policy": "human_approval_required",
                }

        # Track budget spend
        self._budget_spent += cost

        return None  # Allow execution

    def after_tool_call(
        self,
        tool_name: str = "unknown",
        tool_result: Any = None,
        agent_name: str = "unknown",
    ) -> Any:
        """
        Post-execution governance check for a tool call.

        Inspects tool output for blocked patterns.
        Returns the (possibly modified) tool_result, or raises on violation.
        """
        self._record("after_tool", agent_name, {
            "tool": tool_name,
            "result_type": type(tool_result).__name__,
        })

        if isinstance(tool_result, str):
            ok, reason = self._check_content(tool_result)
            if not ok:
                self._raise_violation("output_filter", reason)
                return f"[BLOCKED] {reason}"

        if isinstance(tool_result, dict):
            for value in tool_result.values():
                if isinstance(value, str):
                    ok, reason = self._check_content(value)
                    if not ok:
                        self._raise_violation("output_filter", reason)
                        return {"error": reason}

        return tool_result

    # ------------------------------------------------------------------
    # Human Approval API
    # ------------------------------------------------------------------

    def approve(self, call_id: str) -> bool:
        """Approve a pending tool call by its call_id."""
        if call_id in self._pending_approvals:
            self._approved_calls[call_id] = True
            info = self._pending_approvals.pop(call_id)
            self._record("approval_granted", info.get("agent_name", "unknown"), {
                "call_id": call_id, "tool": info.get("tool_name"),
            })
            return True
        return False

    def deny(self, call_id: str) -> bool:
        """Deny a pending tool call by its call_id."""
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
            "budget_limit": self._sm_config.max_budget,
            "pending_approvals": len(self._pending_approvals),
            "policy": {
                "max_tool_calls": self._sm_config.max_tool_calls,
                "max_agent_calls": self._sm_config.max_agent_calls,
                "blocked_tools": self._sm_config.blocked_tools,
                "allowed_tools": self._sm_config.allowed_tools,
                "require_human_approval": self._sm_config.require_human_approval,
                "sensitive_tools": self._sm_config.sensitive_tools,
            },
        }

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        elapsed = time.time() - self._start_time
        has_violations = len(self._violations) > 0
        return {
            "status": "degraded" if has_violations else "healthy",
            "backend": "smolagents",
            "smolagents_available": _HAS_SMOLAGENTS,
            "wrapped_agents": len(self._wrapped_agents),
            "violations": len(self._violations),
            "uptime_seconds": round(elapsed, 2),
        }


__all__ = [
    "SmolagentsKernel",
    "PolicyConfig",
    "PolicyViolationError",
    "AuditEvent",
    "_HAS_SMOLAGENTS",
    "_check_smolagents_available",
]
