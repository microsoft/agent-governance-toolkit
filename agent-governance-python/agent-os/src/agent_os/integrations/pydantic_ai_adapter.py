# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""PydanticAI integration backed by a required native ACS runtime.

Native hooks mediate prompts and tool calls before PydanticAI executes them.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from .base import (
    get_adapter_runtime,
    BaseIntegration,
    AdapterExecutionState,
)
from ..exceptions import PolicyViolationError

logger = logging.getLogger(__name__)

# Graceful import handling for pydantic-ai
try:
    import pydantic_ai  # noqa: F401
    HAS_PYDANTIC_AI = True
except ImportError:
    HAS_PYDANTIC_AI = False


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

    def __init__(self, *, runtime: Any) -> None:
        super().__init__(runtime=runtime)
        self._audit_log: list[dict[str, Any]] = []
        self._start_time = time.monotonic()
        self._last_error: str | None = None
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)
        logger.debug("PydanticAIKernel initialized")

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: AdapterExecutionState, input_data: Any
    ) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        body: Any
        if isinstance(input_data, (str, dict)):
            body = input_data
        elif hasattr(input_data, "content"):
            body = str(getattr(input_data, "content"))
        else:
            body = str(input_data)
        return self._bridge.evaluate_input(ctx, body=body)

    def evaluate_pre_tool_call(
        self,
        ctx: AdapterExecutionState,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for a PydanticAI tool invocation."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

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
        self._audit_log.append(entry)
        return entry

    def as_capability(self) -> "GovernanceCapability":
        """Create a ``GovernanceCapability`` for PydanticAI's native hook system.

        Returns a capability that can be passed to the ``Agent`` constructor's
        ``capabilities=`` parameter::

            kernel = PydanticAIKernel(policy=policy)
            capability = kernel.as_capability()

            agent = Agent(
                "openai:gpt-4o",
                capabilities=[capability],
            )

        This is the **recommended** integration pattern for PydanticAI
        because it uses the framework's native ``Hooks``/``Capability``
        system instead of monkey-patching tool functions.

        Returns:
            A ``GovernanceCapability`` instance.
        """
        return GovernanceCapability(self)

    def get_stats(self) -> dict[str, Any]:
        """Get native runtime statistics."""
        return {
            "total_sessions": len(self.contexts),
            "total_tool_calls": sum(c.call_count for c in self.contexts.values()),
            "audit_entries": len(self._audit_log),
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
    ctx: AdapterExecutionState,
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

        # AGT-DELTA D1.1: if the engine rewrote the arguments via a
        # transform verdict, swap them in for the downstream tool call
        # so the host sees the redacted payload.
        effective_kwargs = kwargs
        effective_args = args
        if result.modified_arguments is not None:
            mod = dict(result.modified_arguments)
            positional = mod.pop("_positional", None)
            if positional is not None:
                effective_args = tuple(positional)
            effective_kwargs = mod

        ctx.call_count += 1
        kernel._record_audit(
            "tool_executed",
            tool_name=tool_name,
            allowed=True,
            arguments=call_args,
            agent_id=ctx.agent_id,
        )
        return original_fn(*effective_args, **effective_kwargs)

    # Patch the tool entry
    if hasattr(tool_entry, "function"):
        tool_entry.function = governed_fn
    elif hasattr(tool_entry, "_run"):
        tool_entry._run = governed_fn

    tool_entry._governed = True


# Convenience function
class GovernanceCapability:
    """Governance capability for PydanticAI's native hook system.

    Prompts and tool calls are mediated through the kernel's native runtime.
    Hook completion is recorded for host audit.
    """

    def __init__(self, kernel: PydanticAIKernel) -> None:
        self._kernel = kernel
        self._ctx = kernel.create_context("pydantic-ai-hooks")
        self._tool_call_count: int = 0
        self._audit: list[dict[str, Any]] = []

    @property
    def kernel(self) -> PydanticAIKernel:
        """Return the governing kernel."""
        return self._kernel

    @property
    def context(self) -> AdapterExecutionState:
        """Return the execution context."""
        return self._ctx

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Return the audit log."""
        return list(self._audit)

    def before_run(self, prompt: str, **kwargs: Any) -> str:
        """Pre-run hook: scan prompt for governance violations.

        Routes the prompt through the AGT 5.0 ACS engine at the
        ``input`` intervention point. ``transform`` verdicts (AGT-DELTA
        D1.1) rewrite the prompt before PydanticAI sees it;
        ``escalate`` verdicts route through the configured approval
        resolver per AGT-DELTA D1.4.

        Args:
            prompt: The user prompt to validate.
            **kwargs: Additional run context.

        Returns:
            The prompt, possibly rewritten by a transform verdict.

        Raises:
            PolicyViolationError: If the prompt violates policy.
        """
        bridge_result = self._kernel.evaluate_input(self._ctx, prompt)
        if not bridge_result.allowed:
            self._audit.append({
                "event": "run_blocked",
                "reason": bridge_result.reason,
            })
            raise bridge_result.to_policy_violation(PolicyViolationError)
        effective_prompt = prompt
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, str
        ):
            effective_prompt = bridge_result.transform.value
        self._audit.append(
            {"event": "run_start", "prompt_length": len(effective_prompt)}
        )
        return effective_prompt

    def after_run(self, result: Any, **kwargs: Any) -> Any:
        """Post-run hook: drift detection on result.

        Args:
            result: The agent run result.
            **kwargs: Additional run context.

        Returns:
            The result (unmodified).
        """
        evaluation = self._kernel.bridge.evaluate_output(self._ctx, content=result)
        if not evaluation.allowed:
            raise evaluation.to_policy_violation(PolicyViolationError)
        self._audit.append({"event": "run_complete"})
        if evaluation.transform is not None:
            return evaluation.transform.value
        return result

    def before_tool_execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Pre-tool hook: validate tool call against governance policy.

        Routes the call through the AGT 5.0 ACS engine at the
        ``pre_tool_call`` intervention point via
        :meth:`PydanticAIKernel.intercept_tool_call`. ``transform``
        verdicts (AGT-DELTA D1.1) rewrite the outbound arguments;
        ``escalate`` verdicts route through the configured approval
        resolver per AGT-DELTA D1.4.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments.
            **kwargs: Additional context.

        Returns:
            The arguments, possibly rewritten by a transform verdict.

        Raises:
            PolicyViolationError: If the tool call violates policy.
        """
        evaluation = self._kernel.evaluate_pre_tool_call(
            self._ctx, tool_name=tool_name, args=arguments,
            call_id=f"pydantic-ai-{self._tool_call_count + 1}",
        )
        if not evaluation.allowed:
            self._audit.append({
                "event": "tool_blocked",
                "tool": tool_name,
                "reason": evaluation.reason,
            })
            raise evaluation.to_policy_violation(PolicyViolationError)
        effective_args = arguments
        if evaluation.transform is not None and isinstance(
            evaluation.transform.value, dict
        ):
            effective_args = evaluation.transform.value
        self._tool_call_count += 1
        self._ctx.call_count += 1
        self._audit.append({
            "event": "tool_allowed",
            "tool": tool_name,
            "call_number": self._tool_call_count,
        })
        return effective_args

    def after_tool_execute(
        self,
        tool_name: str,
        result: Any,
        **kwargs: Any,
    ) -> Any:
        """Post-tool hook: audit the tool execution result.

        Args:
            tool_name: Name of the tool that was called.
            result: The tool's return value.
            **kwargs: Additional context.

        Returns:
            The result (unmodified).
        """
        evaluation = self._kernel.bridge.evaluate_output(self._ctx, content=result)
        if not evaluation.allowed:
            raise evaluation.to_policy_violation(PolicyViolationError)
        self._audit.append({
            "event": "tool_executed",
            "tool": tool_name,
        })
        if evaluation.transform is not None:
            return evaluation.transform.value
        return result

    def __repr__(self) -> str:
        return f"GovernanceCapability(calls={self._tool_call_count})"


__all__ = [
    "PydanticAIKernel",
    "GovernanceCapability",
    "HAS_PYDANTIC_AI",
]
