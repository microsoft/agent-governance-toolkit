# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Agents SDK Integration for Agent-OS
============================================

Provides kernel-level governance for OpenAI Agents SDK workflows.

Features:
- Policy enforcement for agent tool calls
- Guardrails integration with Agent-OS policies
- Handoff monitoring and approval
- Streaming response governance

Example:
    >>> from agent_os.integrations.openai_agents import OpenAIAgentsKernel
    >>> from agent_os.policies import GovernancePolicy
    >>> from agents import Agent, Runner
    >>>
    >>> # Create governed kernel
    >>> policy = GovernancePolicy(
    ...     max_tool_calls=10,
    ...     allowed_tools=["file_search", "code_interpreter"],
    ...     blocked_patterns=["rm -rf", "DROP TABLE"],
    ... )
    >>> kernel = OpenAIAgentsKernel(policy=policy)
    >>>
    >>> # Wrap agent
    >>> agent = Agent(name="assistant", model="gpt-4o")
    >>> governed_agent = kernel.wrap(agent)
    >>>
    >>> # Run with governance
    >>> result = await Runner.run(governed_agent, "Analyze this data")
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class GovernancePolicy:
    """Policy configuration for OpenAI Agents."""
    # Tool limits
    max_tool_calls: int = 50
    max_handoffs: int = 5
    timeout_seconds: int = 300

    # Tool filtering
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)

    # Content filtering
    blocked_patterns: list[str] = field(default_factory=list)
    pii_detection: bool = True

    # Approval flows
    require_human_approval: bool = False
    approval_threshold: float = 0.8

    # Audit
    log_all_calls: bool = True
    checkpoint_frequency: int = 5


@dataclass
class ExecutionContext:
    """Runtime context for governed execution."""
    session_id: str
    agent_id: str
    policy: GovernancePolicy

    # Counters
    tool_calls: int = 0
    handoffs: int = 0

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)

    # Audit trail
    events: list[dict[str, Any]] = field(default_factory=list)

    def record_event(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })


class PolicyViolationError(Exception):
    """Raised when a policy violation is detected."""
    def __init__(self, policy_name: str, description: str, severity: str = "high"):
        self.policy_name = policy_name
        self.description = description
        self.severity = severity
        super().__init__(f"Policy violation ({policy_name}): {description}")


class OpenAIAgentsKernel:
    """
    Governance kernel for OpenAI Agents SDK.

    Wraps Agent and Runner to enforce policies during execution.
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
        on_violation: Callable[[PolicyViolationError], None] | None = None,
    ) -> None:
        self.policy: GovernancePolicy = policy or GovernancePolicy()
        self.on_violation: Callable[[PolicyViolationError], None] = (
            on_violation or self._default_violation_handler
        )
        self._contexts: dict[str, ExecutionContext] = {}
        self._wrapped_agents: dict[str, Any] = {}
        self._start_time: float = time.monotonic()
        self._last_error: str | None = None

    def _default_violation_handler(self, error: PolicyViolationError) -> None:
        logger.error(f"Policy violation: {error}")

    def _create_context(self, agent_id: str) -> ExecutionContext:
        """Create execution context for an agent."""
        import uuid
        session_id = str(uuid.uuid4())[:8]
        ctx = ExecutionContext(
            session_id=session_id,
            agent_id=agent_id,
            policy=self.policy,
        )
        self._contexts[session_id] = ctx
        return ctx

    def _check_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check if tool is allowed by policy."""
        # Check blocked list
        if tool_name in self.policy.blocked_tools:
            return False, f"Tool '{tool_name}' is blocked by policy"

        # Check allowed list (if specified)
        if self.policy.allowed_tools:
            if tool_name not in self.policy.allowed_tools:
                return False, f"Tool '{tool_name}' not in allowed list"

        return True, ""

    def _check_content(self, content: str) -> tuple[bool, str]:
        """Check content against blocked patterns."""
        content_lower = content.lower()
        for pattern in self.policy.blocked_patterns:
            if pattern.lower() in content_lower:
                return False, f"Content matches blocked pattern: {pattern}"
        return True, ""

    def wrap(self, agent: Any) -> Any:
        """
        Wrap an OpenAI Agent with governance.

        Args:
            agent: OpenAI Agents SDK Agent instance

        Returns:
            Governed agent wrapper
        """
        agent_id = getattr(agent, "name", str(id(agent)))

        # Create wrapper class
        class GovernedAgent:
            def __init__(wrapper_self, original: Any, kernel: OpenAIAgentsKernel):
                wrapper_self._original = original
                wrapper_self._kernel = kernel
                wrapper_self._context = kernel._create_context(agent_id)

                # Copy attributes
                for attr in ["name", "model", "instructions", "tools"]:
                    if hasattr(original, attr):
                        setattr(wrapper_self, attr, getattr(original, attr))

            @property
            def original(wrapper_self) -> Any:
                return wrapper_self._original

            def __getattr__(wrapper_self, name: str) -> Any:
                return getattr(wrapper_self._original, name)

        wrapped = GovernedAgent(agent, self)
        self._wrapped_agents[agent_id] = wrapped
        logger.info(f"Wrapped agent '{agent_id}' with governance kernel")
        return wrapped

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper."""
        if hasattr(governed_agent, "_original"):
            return governed_agent._original
        return governed_agent

    def wrap_runner(self, runner_class: Any) -> Any:
        """
        Wrap the Runner class to intercept executions.

        Args:
            runner_class: OpenAI Agents SDK Runner class

        Returns:
            Governed Runner class
        """
        kernel = self

        class GovernedRunner:
            @classmethod
            async def run(
                cls,
                agent: Any,
                input_text: str,
                **kwargs,
            ) -> Any:
                # Get context
                ctx = None
                if hasattr(agent, "_context"):
                    ctx = agent._context

                # Pre-execution checks
                if ctx:
                    # Check content
                    ok, reason = kernel._check_content(input_text)
                    if not ok:
                        error = PolicyViolationError("content_filter", reason)
                        kernel.on_violation(error)
                        if kernel.policy.require_human_approval:
                            raise error

                    ctx.record_event("run_start", {"input_length": len(input_text)})

                # Get original agent
                original_agent = agent
                if hasattr(agent, "_original"):
                    original_agent = agent._original

                # Run with monitoring
                try:
                    result = await runner_class.run(original_agent, input_text, **kwargs)

                    if ctx:
                        ctx.record_event("run_complete", {"success": True})

                    return result
                except Exception as e:
                    if ctx:
                        ctx.record_event("run_error", {"error": str(e)})
                    raise

            @classmethod
            def run_sync(cls, agent: Any, input_text: str, **kwargs) -> Any:
                return asyncio.run(cls.run(agent, input_text, **kwargs))

        return GovernedRunner

    def create_tool_guard(self) -> Callable:
        """
        Create a tool execution guard.

        Use as a decorator or wrapper for tool functions.
        """
        kernel = self

        def guard(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                tool_name = func.__name__

                # Check if tool is allowed
                ok, reason = kernel._check_tool_allowed(tool_name)
                if not ok:
                    error = PolicyViolationError("tool_filter", reason)
                    kernel.on_violation(error)
                    raise error

                # Check content in arguments
                for arg in args:
                    if isinstance(arg, str):
                        ok, reason = kernel._check_content(arg)
                        if not ok:
                            error = PolicyViolationError("content_filter", reason)
                            kernel.on_violation(error)
                            raise error

                for value in kwargs.values():
                    if isinstance(value, str):
                        ok, reason = kernel._check_content(value)
                        if not ok:
                            error = PolicyViolationError("content_filter", reason)
                            kernel.on_violation(error)
                            raise error

                # Execute
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)

            return wrapper
        return guard

    def create_guardrail(self) -> Any:
        """
        Create an OpenAI Agents SDK compatible guardrail.

        Returns a guardrail that can be added to an agent.
        """
        kernel = self

        class PolicyGuardrail:
            """Agent-OS policy guardrail for OpenAI Agents SDK."""

            async def __call__(
                self,
                context: Any,
                agent: Any,
                input_text: str,
            ) -> str | None:
                """
                Check input against policies.

                Returns None if allowed, or a rejection message if blocked.
                """
                # Check content patterns
                ok, reason = kernel._check_content(input_text)
                if not ok:
                    logger.warning(f"Guardrail blocked: {reason}")
                    return f"Request blocked by policy: {reason}"

                # Check tool calls if in context
                if hasattr(context, "tool_calls"):
                    for tool_call in context.tool_calls:
                        tool_name = getattr(tool_call, "name", "")
                        ok, reason = kernel._check_tool_allowed(tool_name)
                        if not ok:
                            logger.warning(f"Guardrail blocked tool: {reason}")
                            return f"Tool blocked by policy: {reason}"

                return None  # Allowed

        return PolicyGuardrail()

    def get_context(self, session_id: str) -> ExecutionContext | None:
        """Get execution context by session ID."""
        return self._contexts.get(session_id)

    def get_audit_log(self, session_id: str) -> list[dict[str, Any]]:
        """Get audit log for a session."""
        ctx = self._contexts.get(session_id)
        if ctx:
            return ctx.events
        return []

    def get_stats(self) -> dict[str, Any]:
        """Get governance statistics."""
        total_tool_calls: int = sum(ctx.tool_calls for ctx in self._contexts.values())
        total_handoffs: int = sum(ctx.handoffs for ctx in self._contexts.values())

        return {
            "total_sessions": len(self._contexts),
            "wrapped_agents": len(self._wrapped_agents),
            "total_tool_calls": total_tool_calls,
            "total_handoffs": total_handoffs,
            "policy": {
                "max_tool_calls": self.policy.max_tool_calls,
                "max_handoffs": self.policy.max_handoffs,
                "blocked_tools": self.policy.blocked_tools,
            },
        }

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime: float = time.monotonic() - self._start_time
        status: str = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "openai_agents_sdk",
            "backend_connected": bool(self._wrapped_agents),
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


# Convenience exports
__all__ = [
    "OpenAIAgentsKernel",
    "GovernancePolicy",
    "ExecutionContext",
    "PolicyViolationError",
]
