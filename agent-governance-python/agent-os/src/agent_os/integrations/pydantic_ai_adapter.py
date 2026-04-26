# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
PydanticAI Integration for Agent-OS
====================================

Provides kernel-level governance for PydanticAI agent workflows.

Features:
- Policy enforcement for agent tool calls
- Tool call interception via PydanticAI's tool system
- Human approval workflows for sensitive operations
- Call budget enforcement (max_tool_calls)
- Audit logging for all tool executions
- Blocked pattern detection in tool arguments
- Graceful degradation when pydantic-ai is not installed

Example:
    >>> from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
    >>> from agent_os.integrations.base import GovernancePolicy
    >>> from pydantic_ai import Agent
    >>>
    >>> policy = GovernancePolicy(
    ...     max_tool_calls=10,
    ...     allowed_tools=["search", "read_file"],
    ...     blocked_patterns=["rm -rf", "DROP TABLE"],
    ... )
    >>> kernel = PydanticAIKernel(policy=policy)
    >>>
    >>> agent = Agent("openai:gpt-4o", system_prompt="You are helpful.")
    >>> governed = kernel.wrap(agent)
    >>>
    >>> result = await governed.run("Analyze this data")
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

from .base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    PolicyInterceptor,
    PolicyViolationError,
    ToolCallRequest,
    ToolCallResult,
)

logger = logging.getLogger(__name__)

# Graceful import handling for pydantic-ai
try:
    import pydantic_ai  # noqa: F401
    HAS_PYDANTIC_AI = True
except ImportError:
    HAS_PYDANTIC_AI = False


class HumanApprovalRequired(PolicyViolationError):
    """Raised when a tool call requires human approval."""

    def __init__(self, tool_name: str, arguments: dict[str, Any]):
        self.tool_name = tool_name
        self.arguments = arguments
        super().__init__(
            f"Tool '{tool_name}' requires human approval before execution"
        )


class PydanticAIKernel(BaseIntegration):
    """
    PydanticAI adapter for Agent OS.

    Supports:
    - Agent wrapping with governance (run / run_sync)
    - Individual tool call interception (allowed_tools, blocked_patterns)
    - Human approval workflows for sensitive tools
    - Call budget enforcement (max_tool_calls)
    - Audit logging of all tool executions
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
        approval_callback: Callable[[str, dict[str, Any]], bool] | None = None,
    ) -> None:
        super().__init__(policy)
        self._wrapped_agents: dict[int, Any] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._approval_callback = approval_callback
        self._start_time: float = time.monotonic()
        self._last_error: str | None = None
        logger.debug("PydanticAIKernel initialized with policy=%s", policy)

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Return the full audit log."""
        return list(self._audit_log)

    def _record_audit(
        self,
        event_type: str,
        tool_name: str = "",
        allowed: bool = True,
        reason: str = "",
        arguments: dict[str, Any] | None = None,
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Record an audit entry and return it."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "tool_name": tool_name,
            "allowed": allowed,
            "reason": reason,
            "arguments": arguments or {},
            "agent_id": agent_id,
        }
        if self.policy.log_all_calls:
            self._audit_log.append(entry)
        return entry

    def wrap(self, agent: Any) -> Any:
        """
        Wrap a PydanticAI Agent with governance.

        Intercepts:
        - agent.run() / agent.run_sync()
        - All registered tool calls
        - Result validation

        Args:
            agent: A pydantic_ai.Agent instance (or mock).

        Returns:
            A governed wrapper around the agent.
        """
        agent_id = getattr(agent, "name", None) or f"agent-{id(agent)}"
        ctx = self.create_context(agent_id)
        self._wrapped_agents[id(agent)] = agent

        logger.info(
            "Wrapping PydanticAI agent with governance: agent_id=%s", agent_id
        )

        original = agent
        kernel = self

        class GovernedPydanticAIAgent:
            """PydanticAI agent wrapped with Agent OS governance."""

            def __init__(self_inner):
                self_inner._original = original
                self_inner._ctx = ctx
                self_inner._kernel = kernel
                self_inner._agent_id = agent_id
                self_inner._wrap_tools()

            def _wrap_tools(self_inner):
                """Intercept all tools registered on the agent."""
                tools = _get_agent_tools(self_inner._original)
                for tool_entry in tools:
                    _wrap_single_tool(tool_entry, self_inner, kernel, ctx)

            async def run(self_inner, prompt: str, **kwargs) -> Any:
                """Governed async run."""
                allowed, reason = kernel.pre_execute(ctx, prompt)
                if not allowed:
                    kernel._last_error = reason
                    kernel._record_audit(
                        "run_blocked",
                        reason=reason or "",
                        agent_id=agent_id,
                    )
                    raise PolicyViolationError(reason or "Pre-execution check failed")

                kernel._record_audit(
                    "run_start",
                    agent_id=agent_id,
                    reason=f"prompt_length={len(prompt)}",
                )

                try:
                    result = await self_inner._original.run(prompt, **kwargs)
                    kernel._record_audit("run_complete", agent_id=agent_id)
                    return result
                except PolicyViolationError:
                    raise
                except Exception as exc:
                    kernel._last_error = str(exc)
                    kernel._record_audit(
                        "run_error",
                        agent_id=agent_id,
                        reason=str(exc),
                        allowed=False,
                    )
                    raise

            def run_sync(self_inner, prompt: str, **kwargs) -> Any:
                """Governed sync run."""
                allowed, reason = kernel.pre_execute(ctx, prompt)
                if not allowed:
                    kernel._last_error = reason
                    kernel._record_audit(
                        "run_blocked",
                        reason=reason or "",
                        agent_id=agent_id,
                    )
                    raise PolicyViolationError(reason or "Pre-execution check failed")

                kernel._record_audit(
                    "run_start",
                    agent_id=agent_id,
                    reason=f"prompt_length={len(prompt)}",
                )

                try:
                    result = self_inner._original.run_sync(prompt, **kwargs)
                    kernel._record_audit("run_complete", agent_id=agent_id)
                    return result
                except PolicyViolationError:
                    raise
                except Exception as exc:
                    kernel._last_error = str(exc)
                    kernel._record_audit(
                        "run_error",
                        agent_id=agent_id,
                        reason=str(exc),
                        allowed=False,
                    )
                    raise

            @property
            def original(self_inner) -> Any:
                """Return the original unwrapped agent before governance wrapping."""
                return self_inner._original

            @property
            def context(self_inner) -> ExecutionContext:
                """Return the ExecutionContext tracking call counts and session state."""
                return self_inner._ctx

            def __getattr__(self_inner, name: str) -> Any:
                return getattr(self_inner._original, name)

        return GovernedPydanticAIAgent()

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper and return original agent."""
        if hasattr(governed_agent, "_original"):
            return governed_agent._original
        return governed_agent

    def intercept_tool_call(
        self,
        ctx: ExecutionContext,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        """
        Evaluate a tool call against the governance policy.

        Returns a ToolCallResult indicating whether the call is allowed.
        """
        # Handle human approval callback before the interceptor
        if self.policy.require_human_approval:
            if self._approval_callback:
                approved = self._approval_callback(tool_name, arguments)
                if not approved:
                    return ToolCallResult(
                        allowed=False,
                        reason=f"Human approval denied for tool '{tool_name}'",
                    )
                # Approved — skip the interceptor's require_human_approval check
                # by using a policy copy without the flag
                from dataclasses import replace
                policy_for_interceptor = replace(self.policy, require_human_approval=False)
            else:
                return ToolCallResult(
                    allowed=False,
                    reason=f"Tool '{tool_name}' requires human approval",
                )
        else:
            policy_for_interceptor = self.policy

        interceptor = PolicyInterceptor(policy_for_interceptor, ctx)
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=ctx.agent_id,
        )
        return interceptor.intercept(request)

    def get_stats(self) -> dict[str, Any]:
        """Get governance statistics."""
        total_calls = sum(c.call_count for c in self.contexts.values())
        return {
            "total_sessions": len(self.contexts),
            "wrapped_agents": len(self._wrapped_agents),
            "total_tool_calls": total_calls,
            "audit_entries": len(self._audit_log),
            "policy": {
                "max_tool_calls": self.policy.max_tool_calls,
                "allowed_tools": self.policy.allowed_tools,
                "blocked_patterns": [
                    p if isinstance(p, str) else p[0]
                    for p in self.policy.blocked_patterns
                ],
                "require_human_approval": self.policy.require_human_approval,
            },
        }

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        uptime = time.monotonic() - self._start_time
        status = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "pydantic_ai",
            "backend_available": HAS_PYDANTIC_AI,
            "backend_connected": bool(self._wrapped_agents),
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


# ── Helper functions ──────────────────────────────────────────


def _get_agent_tools(agent: Any) -> list:
    """Extract the list of tool entries from a PydanticAI agent."""
    # PydanticAI stores tools in _function_tools (list of Tool objects)
    if hasattr(agent, "_function_tools"):
        return list(agent._function_tools)
    # Fallback for mocks or alternative structures
    if hasattr(agent, "tools"):
        tools = agent.tools
        return list(tools) if tools else []
    return []


def _wrap_single_tool(
    tool_entry: Any,
    governed: Any,
    kernel: PydanticAIKernel,
    ctx: ExecutionContext,
) -> None:
    """Wrap a single tool's function with governance interception."""
    if getattr(tool_entry, "_governed", False):
        return

    # Determine the tool name and callable
    tool_name = getattr(tool_entry, "name", None) or getattr(
        tool_entry, "__name__", str(tool_entry)
    )
    original_fn = getattr(tool_entry, "function", None) or getattr(
        tool_entry, "_run", None
    )
    if original_fn is None:
        return

    @wraps(original_fn)
    def governed_fn(*args: Any, **kwargs: Any) -> Any:
        """Governed wrapper that validates and delegates PydanticAI tool calls."""
        # Build arguments dict for policy check
        call_args: dict[str, Any] = kwargs.copy()
        if args:
            call_args["_positional"] = list(args)

        result = kernel.intercept_tool_call(ctx, tool_name, call_args)

        if not result.allowed:
            kernel._record_audit(
                "tool_blocked",
                tool_name=tool_name,
                allowed=False,
                reason=result.reason or "",
                arguments=call_args,
                agent_id=ctx.agent_id,
            )
            raise PolicyViolationError(
                result.reason or f"Tool '{tool_name}' blocked by policy"
            )

        ctx.call_count += 1
        kernel._record_audit(
            "tool_executed",
            tool_name=tool_name,
            allowed=True,
            arguments=call_args,
            agent_id=ctx.agent_id,
        )
        return original_fn(*args, **kwargs)

    # Patch the tool entry
    if hasattr(tool_entry, "function"):
        tool_entry.function = governed_fn
    elif hasattr(tool_entry, "_run"):
        tool_entry._run = governed_fn

    tool_entry._governed = True


# Convenience function
def wrap(agent: Any, policy: GovernancePolicy | None = None, **kwargs) -> Any:
    """Quick wrapper for PydanticAI agents."""
    return PydanticAIKernel(policy, **kwargs).wrap(agent)


__all__ = [
    "PydanticAIKernel",
    "HumanApprovalRequired",
    "HAS_PYDANTIC_AI",
    "wrap",
]
