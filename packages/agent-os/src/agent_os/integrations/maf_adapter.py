# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Agent Framework (MAF) Integration

Adds Agent OS governance to MAF agents via the native middleware pipeline.
Three middleware layers enforce policy at every level of the agent stack:

- AgentMiddleware: Policy enforcement on agent runs
- FunctionMiddleware: Capability guard on tool invocations
- ChatMiddleware: Output validation on LLM responses

Usage:
    from agent_framework import Agent
    from agent_os.integrations.maf_adapter import GovernanceMiddleware

    middleware = GovernanceMiddleware()

    agent = Agent(
        name="researcher",
        instructions="You are a research assistant.",
        middleware=[middleware.agent, middleware.function, middleware.chat],
    )

    # All agent runs, tool calls, and LLM responses are now governed.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .base import BaseIntegration, ExecutionContext, GovernancePolicy, PatternType, PolicyViolationError

logger = logging.getLogger("agent_os.maf")

# Import MiddlewareTermination from MAF if available, else use a local fallback
try:
    from agent_framework import MiddlewareTermination
except ImportError:

    class MiddlewareTermination(Exception):
        """Local fallback when agent_framework is not installed."""

        pass


class GovernancePolicyMiddleware:
    """AgentMiddleware that enforces governance policy on agent runs.

    Intercepts every agent invocation and validates against the active
    policy before allowing execution. Blocked runs raise
    MiddlewareTermination with the denial reason.

    This middleware implements the ``process(context, call_next)`` pattern
    expected by ``agent_framework.AgentMiddleware``.
    """

    def __init__(self, kernel: "MAFKernel"):
        self._kernel = kernel

    async def process(self, context: Any, call_next: Any) -> None:
        agent_name = getattr(context.agent, "name", "unknown")
        agent_id = f"maf-{agent_name}"

        if self._kernel._stopped.get(agent_id):
            raise MiddlewareTermination(
                f"Agent '{agent_id}' is stopped (SIGSTOP)"
            )

        exec_ctx = self._kernel.create_context(agent_id)

        messages = context.messages if hasattr(context, "messages") else []
        payload = {
            "agent": agent_name,
            "message_count": len(messages),
            "stream": getattr(context, "stream", False),
        }

        allowed, reason = self._kernel.pre_execute(exec_ctx, payload)
        if not allowed:
            logger.info("Policy DENY on agent run for %s: %s", agent_id, reason)
            raise MiddlewareTermination(reason)

        self._kernel._active_agents[agent_id] = context.agent
        context.metadata["agent_os_context"] = exec_ctx
        context.metadata["agent_os_start"] = time.monotonic()

        await call_next()

        elapsed = time.monotonic() - context.metadata.get("agent_os_start", 0)
        self._kernel.post_execute(exec_ctx, context.result)
        self._kernel._audit_log.append({
            "type": "agent_run",
            "agent_id": agent_id,
            "elapsed_seconds": round(elapsed, 3),
            "timestamp": time.time(),
        })


class CapabilityGuardMiddleware:
    """FunctionMiddleware that enforces capability model on tool calls.

    Checks each tool invocation against the allowed_tools list and
    blocked_patterns in the active policy. Denied calls raise
    MiddlewareTermination.

    This middleware implements the ``process(context, call_next)`` pattern
    expected by ``agent_framework.FunctionMiddleware``.
    """

    def __init__(self, kernel: "MAFKernel"):
        self._kernel = kernel

    async def process(self, context: Any, call_next: Any) -> None:
        func_name = getattr(context.function, "name", "unknown")
        policy = self._kernel.policy

        # Check allowed tools
        if policy.allowed_tools and func_name not in policy.allowed_tools:
            logger.info("Capability DENY: tool '%s' not in allowed_tools", func_name)
            raise MiddlewareTermination(
                f"Tool '{func_name}' is not permitted by governance policy '{policy.name}'"
            )

        # Check tool call count
        exec_ctx = context.metadata.get("agent_os_context")
        if exec_ctx:
            exec_ctx.tool_calls.append({"tool": func_name, "timestamp": time.time()})
            if len(exec_ctx.tool_calls) > policy.max_tool_calls:
                logger.info(
                    "Capability DENY: tool call count %d exceeds max %d",
                    len(exec_ctx.tool_calls), policy.max_tool_calls,
                )
                raise MiddlewareTermination(
                    f"Tool call limit exceeded ({policy.max_tool_calls})"
                )

        # Check blocked patterns in arguments
        args_str = str(context.arguments)
        violation = self._kernel._check_blocked_patterns(args_str)
        if violation:
            logger.info("Capability DENY: blocked pattern '%s' in args", violation)
            raise MiddlewareTermination(
                f"Tool arguments contain blocked pattern: {violation}"
            )

        self._kernel._audit_log.append({
            "type": "tool_call",
            "tool": func_name,
            "allowed": True,
            "timestamp": time.time(),
        })

        await call_next()


class OutputValidationMiddleware:
    """ChatMiddleware that validates LLM outputs against content policy.

    Inspects the LLM response after generation and checks for blocked
    patterns and drift from the agent's stated instructions.

    This middleware implements the ``process(context, call_next)`` pattern
    expected by ``agent_framework.ChatMiddleware``.
    """

    def __init__(self, kernel: "MAFKernel"):
        self._kernel = kernel

    async def process(self, context: Any, call_next: Any) -> None:
        await call_next()

        # Validate output if non-streaming
        if not getattr(context, "stream", False) and context.result is not None:
            result_text = ""
            if hasattr(context.result, "content"):
                result_text = str(context.result.content)
            elif hasattr(context.result, "message"):
                result_text = str(context.result.message)

            violation = self._kernel._check_blocked_patterns(result_text)
            if violation:
                logger.info("Output DENY: blocked pattern '%s' in response", violation)
                raise MiddlewareTermination(
                    f"LLM output contains blocked content: {violation}"
                )

            # Drift detection
            exec_ctx = context.metadata.get("agent_os_context")
            if exec_ctx:
                drift_result = self._kernel._check_drift(exec_ctx, result_text)
                if drift_result and drift_result.exceeded:
                    logger.warning(
                        "Drift detected (score=%.4f, threshold=%.4f)",
                        drift_result.score, drift_result.threshold,
                    )
                    self._kernel._audit_log.append({
                        "type": "drift_detected",
                        "score": drift_result.score,
                        "threshold": drift_result.threshold,
                        "timestamp": time.time(),
                    })


class MAFKernel(BaseIntegration):
    """Microsoft Agent Framework adapter for Agent OS.

    Provides governance middleware that plugs into MAF's native middleware
    pipeline. Instead of monkey-patching (like the AutoGen adapter), this
    uses MAF's first-class ``AgentMiddleware``, ``FunctionMiddleware``, and
    ``ChatMiddleware`` extension points.

    Example:
        >>> from agent_framework import Agent
        >>> from agent_os.integrations.maf_adapter import MAFKernel
        >>>
        >>> kernel = MAFKernel(policy=GovernancePolicy(
        ...     allowed_tools=["web_search", "file_read"],
        ...     blocked_patterns=["password", "secret"],
        ... ))
        >>>
        >>> agent = Agent(
        ...     name="researcher",
        ...     instructions="Research assistant",
        ...     middleware=[kernel.agent, kernel.function, kernel.chat],
        ... )
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        timeout_seconds: float = 300.0,
    ):
        super().__init__(policy)
        self.timeout_seconds = timeout_seconds
        self._active_agents: dict[str, Any] = {}
        self._original_agents: dict[str, Any] = {}
        self._stopped: dict[str, bool] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None

        # Create middleware instances
        self.agent = GovernancePolicyMiddleware(self)
        self.function = CapabilityGuardMiddleware(self)
        self.chat = OutputValidationMiddleware(self)

    def wrap(self, agent: Any) -> Any:
        """Attach governance middleware to a MAF agent.

        For MAF agents, governance is applied via the middleware pipeline
        rather than monkey-patching. This stores the original agent reference
        and returns it (middleware is already configured on the kernel).
        """
        agent_id = f"maf-{getattr(agent, 'name', 'unknown')}"
        self._active_agents[agent_id] = agent
        self._original_agents[agent_id] = agent
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        """Return the original (unwrapped) MAF agent."""
        agent_id = f"maf-{getattr(governed_agent, 'name', 'unknown')}"
        return self._original_agents.pop(agent_id, governed_agent)

    @property
    def middleware(self) -> list:
        """Return all three middleware layers for convenient unpacking.

        Usage:
            agent = Agent(name="x", middleware=kernel.middleware)
        """
        return [self.agent, self.function, self.chat]

    def signal(self, agent_id: str, signal: str):
        """Send a governance signal to a MAF agent.

        Args:
            agent_id: Agent identifier (format: "maf-{agent_name}").
            signal: One of SIGSTOP, SIGCONT, SIGKILL.
        """
        if signal == "SIGSTOP":
            self._stopped[agent_id] = True
        elif signal == "SIGCONT":
            self._stopped[agent_id] = False
        elif signal == "SIGKILL":
            self._stopped[agent_id] = True
            self._active_agents.pop(agent_id, None)

        super().signal(agent_id, signal)

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status."""
        uptime = time.monotonic() - self._start_time
        return {
            "status": "degraded" if self._last_error else "healthy",
            "backend": "microsoft-agent-framework",
            "active_agents": len(self._active_agents),
            "stopped_agents": sum(1 for v in self._stopped.values() if v),
            "audit_log_size": len(self._audit_log),
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }

    def _check_blocked_patterns(self, text: str) -> Optional[str]:
        """Check text against blocked patterns in the policy.

        Returns the matched pattern string if a violation is found, else None.
        """
        if not text:
            return None
        for pattern_str, pattern_type, compiled in self.policy._compiled_patterns:
            if pattern_type == PatternType.SUBSTRING:
                if pattern_str.lower() in text.lower():
                    return pattern_str
            elif compiled and compiled.search(text):
                return pattern_str
        return None

    def _check_drift(self, exec_ctx: ExecutionContext, text: str) -> Any:
        """Check for instruction drift (stub — returns None for now)."""
        return None


# Convenience function
def govern(
    policy: Optional[GovernancePolicy] = None,
    timeout_seconds: float = 300.0,
) -> MAFKernel:
    """Create a governance kernel for Microsoft Agent Framework.

    Returns a MAFKernel with three middleware layers ready to attach
    to any MAF Agent.

    Args:
        policy: Governance policy to enforce (uses defaults if None).
        timeout_seconds: Default timeout for agent runs.

    Returns:
        MAFKernel instance. Use ``.middleware`` to get all three layers
        or ``.agent``, ``.function``, ``.chat`` individually.

    Example:
        >>> from agent_os.integrations.maf_adapter import govern
        >>> kernel = govern(policy=GovernancePolicy(max_tool_calls=5))
        >>> agent = Agent(name="x", middleware=kernel.middleware)
    """
    return MAFKernel(policy=policy, timeout_seconds=timeout_seconds)
