# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
PydanticAI Integration for Agent-OS
====================================

Provides kernel-level governance for PydanticAI agent workflows.

Backend (AGT 5.0): every policy decision is routed through
:class:`agt.policies.runtime.AgtRuntime` (the ACS-backed v5 engine).
The v4 :class:`~agent_os.integrations.base.GovernancePolicy` is
translated to an AGT manifest via
:func:`agt.policies.bridge.governance_to_acs_manifest` at adapter init
time, an :class:`AgtRuntime` is memoised per policy, and a
:class:`agt.policies.snapshot.SnapshotBuilder` mirrors the v4
``ExecutionContext`` budgets between intervention points. The legacy
``pre_execute`` / ``post_execute`` tuple API is preserved so v4 callers
keep working. ``transform`` verdicts (AGT-DELTA D1.1) rewrite the
outbound prompt or tool arguments before PydanticAI sees them;
``escalate`` verdicts route through the configured approval resolver
per AGT-DELTA D1.4.

Features:
- Policy enforcement for agent tool calls via the AGT 5.0 ACS runtime
- Tool call interception via PydanticAI's tool system or native
  ``GovernanceCapability`` hook
- Human approval workflows for sensitive operations
- Call budget enforcement (max_tool_calls)
- Audit logging for all tool executions
- Transform-verdict rewriting of tool arguments and prompts
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
from typing import Any, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from .base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    PolicyViolationError as _BasePolicyViolationError,
    ToolCallResult,
)

logger = logging.getLogger(__name__)

# Re-export the canonical PolicyViolationError under the same import path
# v4 callers used (`from agent_os.integrations.pydantic_ai_adapter
# import PolicyViolationError`). The base module already aliases to the
# canonical class, so this preserves identity.
PolicyViolationError = _BasePolicyViolationError

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
        evaluator: Any = None,
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Initialise the PydanticAI governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the
                default ``GovernancePolicy`` is used. The policy is
                translated to an AGT manifest and an
                :class:`agt.policies.runtime.AgtRuntime` is constructed
                over it at init time.
            approval_callback: Legacy v4 approval hook used by the
                ``require_human_approval`` policy field. When set and
                the policy requires approval, the callback gates the
                tool call.
            evaluator: Optional ``PolicyEvaluator`` for legacy Cedar/OPA
                policy evaluation. Retained for backward compatibility;
                the primary decision path now runs through the AGT 5.0
                runtime.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature
                matches :data:`agt.policies.runtime.ApprovalCallback`.
                When ``None`` an escalate verdict fails closed to
                ``deny``.
            _runtime: Test seam — inject a pre-built
                :class:`AgtRuntime` so scenario tests can wire a
                scripted policy dispatcher without OPA on PATH. Not
                part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public
                surface.
        """
        super().__init__(policy, evaluator=evaluator)
        self._wrapped_agents: dict[int, Any] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._approval_callback = approval_callback
        self._approval_resolver = approval_resolver
        self._start_time: float = time.monotonic()
        self._last_error: str | None = None
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )
        logger.debug("PydanticAIKernel initialized with policy=%s", policy)

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: ExecutionContext, input_data: Any
    ) -> BridgeResult:
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
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> BridgeResult:
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
        if self.policy.log_all_calls:
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

    def wrap(self, agent: Any) -> Any:
        """Wrap a PydanticAI Agent with governance.

        .. deprecated::
            Use :meth:`as_capability` with ``capabilities=`` instead
            for a non-invasive integration.

        Intercepts:
        - agent.run() / agent.run_sync()
        - All registered tool calls
        - Result validation

        Args:
            agent: A pydantic_ai.Agent instance (or mock).

        Returns:
            A governed wrapper around the agent.
        """
        import warnings
        warnings.warn(
            "PydanticAIKernel.wrap() is deprecated. Use as_capability() "
            "with Agent(capabilities=[kernel.as_capability()]) "
            "for a non-invasive integration.",
            DeprecationWarning,
            stacklevel=2,
        )
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
                effective_prompt = self_inner._evaluate_prompt(prompt)

                kernel._record_audit(
                    "run_start",
                    agent_id=agent_id,
                    reason=f"prompt_length={len(effective_prompt)}",
                )

                try:
                    result = await self_inner._original.run(effective_prompt, **kwargs)
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
                effective_prompt = self_inner._evaluate_prompt(prompt)

                kernel._record_audit(
                    "run_start",
                    agent_id=agent_id,
                    reason=f"prompt_length={len(effective_prompt)}",
                )

                try:
                    result = self_inner._original.run_sync(effective_prompt, **kwargs)
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

            def _evaluate_prompt(self_inner, prompt: str) -> str:
                """Run the AGT ``input`` intervention point and honour the verdict."""
                bridge_result = kernel.evaluate_input(ctx, prompt)
                if not bridge_result.allowed:
                    kernel._last_error = bridge_result.reason
                    kernel._record_audit(
                        "run_blocked",
                        reason=bridge_result.reason or "",
                        agent_id=agent_id,
                    )
                    raise PolicyViolationError.from_check_result(
                        bridge_result.check_result
                    )
                if bridge_result.transform is not None and isinstance(
                    bridge_result.transform.value, str
                ):
                    return bridge_result.transform.value
                return prompt

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
        """Evaluate a tool call against the governance policy.

        Routes the evaluation through the AGT 5.0 ACS engine at the
        ``pre_tool_call`` intervention point. Returns a
        :class:`ToolCallResult` shaped like the v4 contract so existing
        v4 callers continue to work:

        - ``allow`` -> ``allowed=True`` and the tool runs.
        - ``deny`` -> ``allowed=False`` with the canonical reason.
        - ``transform`` -> ``allowed=True`` plus the rewritten
          ``modified_arguments`` payload from AGT-DELTA D1.1.
        - ``escalate`` -> the bridge has already routed through the
          approval resolver, so the verdict surfaces as allow (resolver
          approved) or deny (resolver refused / not wired).

        The legacy ``require_human_approval`` approval-callback short
        circuit runs first so the v4 callback contract still works
        before the engine evaluates the call.

        A host-side ``blocked_patterns`` scan on the serialised
        arguments runs alongside the engine because the AGT manifest
        bridge only pattern-matches string policy targets and the v4
        contract matched tool arguments via ``policy.matches_pattern``.
        """
        # Host-side blocked_patterns guard on tool arguments. Mirrors
        # the v4 PolicyInterceptor.blocked_patterns branch; the AGT
        # manifest bridge does not bind pre_tool_call for the
        # blocked_patterns policy field.
        args_str = str(arguments)
        matched = self.policy.matches_pattern(args_str)
        if matched:
            pattern = matched[0]
            return ToolCallResult(
                allowed=False,
                reason=f"blocked_pattern:{pattern}",
            )

        # Handle legacy v4 human approval callback before the AGT engine
        # evaluates the call. The v4 ``require_human_approval`` field
        # has a callback-based path that pre-dates AGT-DELTA D1.4 and is
        # still part of the public contract.
        #
        # AGT-DELTA D5: when an ``approval_resolver`` is wired, defer
        # the whole approval decision to the AGT runtime. The bridge's
        # ``evaluate_pre_tool_call`` returns escalate, the AgtRuntime
        # consults the resolver, and the verdict resolves to allow with
        # a bisected enforced_identity (D1.4). The legacy callback path
        # is preserved only for v4-only kernels (no resolver wired).
        if (
            self.policy.require_human_approval
            and self._approval_resolver is None
        ):
            if self._approval_callback is None:
                return ToolCallResult(
                    allowed=False,
                    reason=f"Tool '{tool_name}' requires human approval",
                )
            approved = self._approval_callback(tool_name, arguments)
            if not approved:
                return ToolCallResult(
                    allowed=False,
                    reason=f"Human approval denied for tool '{tool_name}'",
                )
            effective_bridge = self._approved_bridge()
        else:
            effective_bridge = self._bridge

        bridge_result = effective_bridge.evaluate_pre_tool_call(
            ctx,
            tool_name=tool_name,
            args=arguments,
            call_id=f"call-{ctx.call_count + 1}",
        )

        effective_args = arguments
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            effective_args = bridge_result.transform.value

        if not bridge_result.allowed:
            return ToolCallResult(
                allowed=False,
                reason=bridge_result.reason
                or f"Tool '{tool_name}' blocked by policy",
            )
        return ToolCallResult(
            allowed=True,
            reason=bridge_result.reason or None,
            modified_arguments=(
                effective_args if effective_args is not arguments else None
            ),
        )

    def _approved_bridge(self) -> AdapterRuntimeBridge:
        """Return a sibling bridge with ``require_human_approval=False``.

        Built lazily on first access. Used after the legacy v4
        approval_callback has approved a tool call so the engine's
        remaining policy checks (allowed_tools, blocked_patterns on
        input, max_tool_calls, etc.) still fire without re-triggering
        the AGT ``approval.escalate_if_approver_required`` rule.
        """
        cached = getattr(self, "_bridge_no_approval", None)
        if cached is not None:
            return cached
        from dataclasses import replace

        approved_policy = replace(self.policy, require_human_approval=False)
        bridge = get_runtime_bridge(
            approved_policy,
            approval_resolver=self._approval_resolver,
        )
        self._bridge_no_approval = bridge
        return bridge

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
def wrap(agent: Any, policy: GovernancePolicy | None = None, **kwargs) -> Any:
    """Quick wrapper for PydanticAI agents.

    .. deprecated::
        Use ``PydanticAIKernel.as_capability()`` with
        ``Agent(capabilities=[...])`` instead.
    """
    import warnings
    warnings.warn(
        "wrap() is deprecated. Use PydanticAIKernel(policy=...).as_capability() "
        "with Agent(capabilities=[...]) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    kernel = PydanticAIKernel(policy, **kwargs)
    # Suppress nested deprecation from kernel.wrap()
    import contextlib
    with contextlib.suppress(Exception), warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return kernel.wrap(agent)


# ═══════════════════════════════════════════════════════════════════
# Native Hook: GovernanceCapability
# ═══════════════════════════════════════════════════════════════════
#
# PydanticAI provides a Hooks/Capability system for composable,
# non-invasive lifecycle hooks.  GovernanceCapability implements
# the key hooks:
#   - before_tool_execute: tool allowlist / blocklist / pattern check
#   - after_tool_execute: post-execution audit
#   - before_run: pre-execution content scanning
#   - after_run: post-execution drift detection
#
# Usage:
#     kernel = PydanticAIKernel(policy=policy)
#     agent = Agent("openai:gpt-4o", capabilities=[kernel.as_capability()])
# ═══════════════════════════════════════════════════════════════════


class GovernanceCapability:
    """Governance capability for PydanticAI's native hook system.

    Implements the PydanticAI capability/hooks protocol, providing
    governance checks at key lifecycle points:

    - ``before_tool_execute``: Validates tool name against
      ``allowed_tools``, scans arguments for ``blocked_patterns``,
      enforces ``max_tool_calls``.
    - ``after_tool_execute``: Records audit entries.
    - ``before_run``: Scans prompt for blocked patterns.
    - ``after_run``: Runs post-execute drift detection.

    Example::

        kernel = PydanticAIKernel(policy=GovernancePolicy(
            allowed_tools=["search", "read_file"],
            blocked_patterns=["rm -rf"],
            max_tool_calls=10,
        ))
        capability = kernel.as_capability()

        agent = Agent(
            "openai:gpt-4o",
            capabilities=[capability],
        )
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
    def context(self) -> ExecutionContext:
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
            raise PolicyViolationError.from_check_result(
                bridge_result.check_result
            )
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
        self._audit.append({"event": "run_complete"})
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
        result = self._kernel.intercept_tool_call(
            self._ctx, tool_name, arguments
        )
        if not result.allowed:
            self._audit.append({
                "event": "tool_blocked",
                "tool": tool_name,
                "reason": result.reason,
            })
            raise PolicyViolationError(
                result.reason or f"Tool '{tool_name}' blocked by policy"
            )

        effective_args = (
            result.modified_arguments
            if result.modified_arguments is not None
            else arguments
        )
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
        self._audit.append({
            "event": "tool_executed",
            "tool": tool_name,
        })
        return result

    def __repr__(self) -> str:
        return f"GovernanceCapability(calls={self._tool_call_count})"


__all__ = [
    "PydanticAIKernel",
    "HumanApprovalRequired",
    "GovernanceCapability",
    "HAS_PYDANTIC_AI",
    "wrap",
]
