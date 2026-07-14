# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Google ADK (Agent Development Kit) Integration for Agent-OS
============================================================

Provides kernel-level governance for Google ADK agent workflows.

Features:
- Extends BaseIntegration with wrap/unwrap for ADK agents
- Runner-scoped GovernancePlugin with all 12 ADK lifecycle hooks
- ADKExecutionContext for per-run state, token, and cancellation tracking
- Policy enforcement via ADK's native callback hooks
- before_tool_callback / after_tool_callback for tool governance
- before_agent_callback / after_agent_callback for agent lifecycle
- Content filtering with blocked patterns
- Tool allow/block lists
- Human approval workflow for sensitive tools
- Token/call budget tracking
- SIGKILL / cancellation support for running invocations
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
    >>>
    >>> # Option C: Runner-scoped plugin (recommended for production)
    >>> from google.adk import Runner
    >>> runner = Runner(
    ...     agent=root_agent,
    ...     plugins=[kernel.as_plugin()],
    ... )
"""

from __future__ import annotations

import logging
import time
import uuid
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .base import BaseIntegration, AdapterExecutionState, GovernanceEventType, get_adapter_runtime
from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError

logger = logging.getLogger(__name__)

# Graceful import of google-adk
try:
    from google.adk.agents import Agent as _ADKAgent  # noqa: F401

    _HAS_ADK = True
except ImportError:
    _HAS_ADK = False

# Graceful import of BasePlugin (ADK v1.7.0+)
try:
    from google.adk.plugins.base_plugin import BasePlugin as _ADKBasePlugin

    _HAS_ADK_PLUGINS = True
except ImportError:
    _ADKBasePlugin = None  # type: ignore[assignment,misc]
    _HAS_ADK_PLUGINS = False


def _check_adk_available() -> None:
    """Raise a helpful error when the ``google-adk`` package is missing."""
    if not _HAS_ADK:
        raise ImportError(
            "The 'google-adk' package is required for live ADK agent wrapping. "
            "Install it with: pip install google-adk"
        )


@dataclass
class AuditEvent:
    """Single audit trail entry."""

    timestamp: float
    event_type: str
    agent_name: str
    details: dict[str, Any]
    skill_name: str | None = None
    skill_origin: str | None = None
    provenance_source_trust: str | None = None
    context_hash_before: str | None = None
    context_hash_after: str | None = None



@dataclass
class ADKExecutionContext(AdapterExecutionState):
    """Extended execution context for Google ADK runs.

    Tracks ADK-specific state including invocation IDs, agent names,
    model call history, and cumulative token usage for governance
    enforcement.  Analogous to ``AssistantContext`` in the OpenAI
    adapter.

    Attributes:
        invocation_id: Current ADK invocation identifier.
        agent_names: Agent names encountered during the run.
        run_history: Timestamped history entries.
        prompt_tokens: Cumulative prompt tokens consumed.
        completion_tokens: Cumulative completion tokens consumed.
        model_calls: Count of LLM invocations in this context.
        cancelled: Whether this run has been SIGKILL'd.
    """

    invocation_id: str = ""
    agent_names: list[str] = field(default_factory=list)
    run_history: list[dict[str, Any]] = field(default_factory=list)

    # Token tracking
    prompt_tokens: int = 0
    completion_tokens: int = 0

    # Model tracking
    model_calls: int = 0

    # Cancellation
    cancelled: bool = False


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
        on_violation: Callable[[PolicyViolationError], None] | None = None,
        *,
        runtime: Any,
    ):
        super().__init__(runtime=runtime)

        self.on_violation = on_violation or self._default_violation_handler

        # Counters
        self._tool_call_count: int = 0
        self._agent_call_count: int = 0
        self._start_time: float = time.time()
        # Audit trail
        self._audit_log: list[AuditEvent] = []

        # Violations collected
        self._violations: list[PolicyViolationError] = []

        # Wrapped agents registry
        self._wrapped_agents: dict[str, Any] = {}

        # SIGKILL / run cancellation
        self._cancelled_runs: set[str] = set()

        # Model-level tracking
        self._model_call_count: int = 0
        self._prompt_tokens: int = 0
        self._completion_tokens: int = 0

        # Execution contexts (keyed by invocation_id)
        self._contexts: dict[str, ADKExecutionContext] = {}

        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)
        self._adapter_ctx = AdapterExecutionState(
            agent_id="google-adk-kernel",
            session_id=f"adk-{int(time.time())}-{id(self)}",
        )

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: AdapterExecutionState | None, input_data: Any
    ) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation.

        Falls back to the shared adapter-level :class:`AdapterExecutionState`
        when ``ctx`` is ``None`` (the ADK callbacks generally do not
        have a per-run :class:`ADKExecutionContext` at the time the
        callback fires).
        """
        body: Any
        if isinstance(input_data, (str, dict)):
            body = input_data
        elif hasattr(input_data, "content"):
            body = str(getattr(input_data, "content"))
        else:
            body = str(input_data)
        return self._bridge.evaluate_input(ctx or self._adapter_ctx, body=body)

    def evaluate_pre_tool_call(
        self,
        ctx: AdapterExecutionState | None,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for an ADK tool invocation."""
        return self._bridge.evaluate_pre_tool_call(
            ctx or self._adapter_ctx,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    def evaluate_output(
        self, ctx: AdapterExecutionState | None, content: Any
    ) -> AdapterResult:
        """AGT ``output`` intervention point evaluation for an ADK result."""
        body: Any
        if isinstance(content, (str, dict)):
            body = content
        elif hasattr(content, "content"):
            body = str(getattr(content, "content"))
        else:
            body = str(content)
        return self._bridge.evaluate_output(
            ctx or self._adapter_ctx, content=body
        )

    # ------------------------------------------------------------------
    # BaseIntegration abstract methods
    # ------------------------------------------------------------------

    def wrap(self, agent: Any) -> Any:
        """
        Wrap an ADK agent with governance callbacks.

        .. deprecated::
            Use :meth:`as_plugin` instead.  ``wrap()`` will be removed
            in v1.0.
        """
        warnings.warn(
            "GoogleADKKernel.wrap() is deprecated. Use kernel.as_plugin() "
            "instead, which leverages ADK's native plugin lifecycle. "
            "wrap() will be removed in v1.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        agent_name = getattr(agent, "name", None) or str(id(agent))

        # Inject callbacks if the agent supports them
        for attr, cb in self._get_callbacks_internal().items():
            if hasattr(agent, attr):
                setattr(agent, attr, cb)

        self._wrapped_agents[agent_name] = agent
        self._record("agent_wrapped", agent_name, {"agent_type": type(agent).__name__})
        logger.info("Wrapped ADK agent '%s' with governance kernel", agent_name)
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper and return the original agent.

        .. deprecated::
            Use :meth:`as_plugin` instead.  ``unwrap()`` will be removed
            in v1.0.
        """
        warnings.warn(
            "GoogleADKKernel.unwrap() is deprecated. Use kernel.as_plugin() "
            "instead. unwrap() will be removed in v1.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        for attr in self._get_callbacks_internal():
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

    def _record(
        self,
        event_type: str,
        agent_name: str,
        details: dict[str, Any],
        *,
        skill_name: str | None = None,
        skill_origin: str | None = None,
        provenance_source_trust: str | None = None,
        context_hash_before: str | None = None,
        context_hash_after: str | None = None,
    ) -> None:
        """Append an audit event to the internal audit log.

        Records the event only when log_all_calls is enabled.

        Args:
        event_type: Short string label for the event.
        agent_name: Name of the ADK agent generating the event.
        details: Arbitrary dict of additional context.
        """
        self._audit_log.append(
            AuditEvent(
                timestamp=time.time(),
                event_type=event_type,
                agent_name=agent_name,
                details=details,
                skill_name=skill_name,
                skill_origin=skill_origin,
                provenance_source_trust=provenance_source_trust,
                context_hash_before=context_hash_before,
                context_hash_after=context_hash_after,
            )
        )


    def _raise_violation(self, result: AdapterResult) -> PolicyViolationError:
        """Create, record, and surface a PolicyViolationError.

        Appends the error to the violations list and calls on_violation.
        """
        error = result.to_policy_violation(PolicyViolationError)
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

        trusted_skill_sources = self.trusted_sources_from_attrs(tool_context)

        emitted = self.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=agent_name,
            action="adk.before_tool_callback",
            trusted_sources=trusted_skill_sources,
            default_origin="adk",
            context_before=tool_args,
            tool_name=tool_name,
        )

        self._record(
            "before_tool",
            agent_name,
            {"tool": tool_name, "args": tool_args},
            skill_name=emitted.get("skill_name"),
            skill_origin=emitted.get("skill_origin"),
            provenance_source_trust=emitted.get("provenance_source_trust"),
            context_hash_before=emitted.get("context_hash_before"),
            context_hash_after=emitted.get("context_hash_after"),
        )

        self._tool_call_count += 1
        bridge_args = tool_args if isinstance(tool_args, dict) else {"value": tool_args}
        bridge_result = self._bridge.evaluate_pre_tool_call(
            self._adapter_ctx,
            tool_name=tool_name,
            args=bridge_args,
            call_id=f"call-{self._tool_call_count}",
        )
        # AGT-DELTA D1.4: propagate the bisected input_identity /
        # enforced_identity from the bridge evaluation into the kernel
        # audit log so resolver-driven approvals are auditable.
        identity_audit = {
            key: value
            for key, value in (
                ("input_identity", bridge_result.input_identity),
                ("enforced_identity", bridge_result.enforced_identity),
            )
            if value is not None
        }
        # Only emit the D1.4 identity-audit record on the resolver-driven
        # approval path. Without a wired ``approval_resolver`` there is no
        # bisected identity worth auditing, and emitting here would pollute
        # the host audit sequence for tool and agent runs.
        if identity_audit:
            self._record(
                "agt_pre_tool_call",
                agent_name,
                {
                    "tool": tool_name,
                    "verdict": bridge_result.verdict,
                    **identity_audit,
                },
            )
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            if isinstance(tool_args, dict):
                tool_args.clear()
                tool_args.update(bridge_result.transform.value)
                if tool_context is not None and hasattr(tool_context, "tool_args"):
                    try:
                        tool_context.tool_args = tool_args
                    except Exception:  # noqa: BLE001 — best-effort rewrite on opaque context
                        pass
        if not bridge_result.allowed:
            error = self._raise_violation(bridge_result)
            return {"error": str(error)}

        # Track budget spend. Increment the AdapterExecutionState counter so both
        # the default `_bridge` and the sensitive-tools `_approval_bridge`
        # observe the same running tool-call budget — each bridge's
        # SnapshotBuilder mirrors `ctx.call_count` on every `builder_for`
        # call so this single mutation propagates to both. We deliberately
        # do NOT also call `record_post_execute(tool_calls=1)` because that
        # would double-count (the mirror in `builder_for` already advances
        # the builder by 1, then `record_tool_call` would add another 1,
        # causing `max_tool_calls=N` policies to deny on call N rather
        # than N+1). The smolagents adapter uses the same single-mutation
        # pattern at `smolagents_adapter.py:734-738` for the same reason —
        # this is the AGT-M3 round-4 Opus regression fix.
        self._adapter_ctx.call_count += 1

        return None  # Allow execution

    def after_tool_callback(
        self,
        tool_context: Any = None,
        tool_result: Any = None,
        **kwargs: Any,
    ) -> Any:
        """
        ADK after_tool_callback — called after each tool execution.

        Inspects tool output for blocked patterns and routes through the
        AGT 5.0 ACS bridge at the ``output`` intervention point.

        Returns:
            The (possibly modified) tool_result, or a dict with error if blocked.
        """
        tool_name = getattr(tool_context, "tool_name", kwargs.get("tool_name", "unknown"))
        agent_name = getattr(tool_context, "agent_name", kwargs.get("agent_name", "unknown"))

        trusted_skill_sources = self.trusted_sources_from_attrs(tool_context)

        emitted = self.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=agent_name,
            action="adk.after_tool_callback",
            trusted_sources=trusted_skill_sources,
            default_origin="adk",
            context_after=tool_result,
            tool_name=tool_name,
        )

        self._record(
            "after_tool",
            agent_name,
            {"tool": tool_name, "result_type": type(tool_result).__name__},
            skill_name=emitted.get("skill_name"),
            skill_origin=emitted.get("skill_origin"),
            provenance_source_trust=emitted.get("provenance_source_trust"),
            context_hash_before=emitted.get("context_hash_before"),
            context_hash_after=emitted.get("context_hash_after"),
        )

        # Native output evaluation may rewrite the tool result before ADK
        # consumers observe it. Denials surface as sanitized errors.
        if tool_result is not None:
            bridge_result = self._bridge.evaluate_output(
                self._adapter_ctx, content=tool_result
            )
            if not bridge_result.allowed:
                error = self._raise_violation(bridge_result)
                return {"error": str(error)}
            if bridge_result.transform is not None:
                if isinstance(tool_result, str) and isinstance(
                    bridge_result.transform.value, str
                ):
                    tool_result = bridge_result.transform.value
                elif isinstance(tool_result, dict) and isinstance(
                    bridge_result.transform.value, dict
                ):
                    tool_result = bridge_result.transform.value

        return tool_result

    def before_agent_callback(self, callback_context: Any = None, **kwargs: Any) -> Any:
        """
        ADK before_agent_callback — called before agent starts processing.

        Returns:
            None to allow, or a Content-like object to skip the agent.
        """
        agent_name = getattr(callback_context, "agent_name", kwargs.get("agent_name", "unknown"))

        trusted_skill_sources = self.trusted_sources_from_attrs(callback_context)

        skill_fields = self.build_skill_audit_fields(
            trusted_sources=trusted_skill_sources,
            default_origin="adk",
        )

        self._record("before_agent", agent_name, {}, **skill_fields)

        self._agent_call_count += 1

        # Treat an agent invocation as input so ACS can enforce content and
        # approval gates before the run starts.
        bridge_result = self._bridge.evaluate_input(
            self._adapter_ctx,
            body=f"agent:{agent_name}",
        )
        if not bridge_result.allowed:
            error = self._raise_violation(bridge_result)
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

        Checks agent output for blocked content and routes through the
        AGT 5.0 ACS bridge at the ``output`` intervention point.

        Returns:
            The content (possibly modified), or a dict with error if blocked.
        """
        agent_name = getattr(callback_context, "agent_name", kwargs.get("agent_name", "unknown"))

        trusted_skill_sources = self.trusted_sources_from_attrs(callback_context)

        skill_fields = self.build_skill_audit_fields(
            trusted_sources=trusted_skill_sources,
            default_origin="adk",
            context_after=content,
        )

        self._record(
            "after_agent",
            agent_name,
            {"has_content": content is not None},
            **skill_fields,
        )

        # Native output evaluation may rewrite content before ADK receives it.
        if content is not None:
            bridge_result = self._bridge.evaluate_output(
                self._adapter_ctx, content=content
            )
            if not bridge_result.allowed:
                error = self._raise_violation(bridge_result)
                return {"error": str(error)}
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, str
            ):
                content = bridge_result.transform.value

        return content

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset counters and start time (for new execution runs)."""
        self._tool_call_count = 0
        self._agent_call_count = 0
        self._start_time = time.time()
        self._model_call_count = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0
        # Rotate the adapter-level execution context so the bridge
        # builds a fresh :class:`SnapshotBuilder` for subsequent calls.
        # Without this, the bridge would keep enforcing budgets against
        # the cumulative counters from before reset.
        self._adapter_ctx = AdapterExecutionState(
            agent_id="google-adk-kernel",
            session_id=f"adk-{int(time.time())}-{id(self)}-r",
        )

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
        }

    def _get_callbacks_internal(self) -> dict[str, Any]:
        """Return callback dict without deprecation warning (internal use)."""
        return {
            "before_tool_callback": self.before_tool_callback,
            "after_tool_callback": self.after_tool_callback,
            "before_agent_callback": self.before_agent_callback,
            "after_agent_callback": self.after_agent_callback,
        }

    def get_callbacks(self) -> dict[str, Any]:
        """
        Return a dict of all callbacks suitable for unpacking into LlmAgent.

        .. deprecated::
            Use :meth:`as_plugin` instead.  ``get_callbacks()`` will be
            removed in v1.0.
        """
        warnings.warn(
            "GoogleADKKernel.get_callbacks() is deprecated. Use "
            "kernel.as_plugin() instead. get_callbacks() will be removed "
            "in v1.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._get_callbacks_internal()

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Includes model-call counts, token usage, and cancellation
        metrics alongside the original health fields.
        """
        elapsed = time.time() - self._start_time
        has_violations = len(self._violations) > 0
        return {
            "status": "degraded" if has_violations else "healthy",
            "backend": "google_adk",
            "adk_available": _HAS_ADK,
            "adk_plugins_available": _HAS_ADK_PLUGINS,
            "wrapped_agents": len(self._wrapped_agents),
            "violations": len(self._violations),
            "uptime_seconds": round(elapsed, 2),
            "model_calls": self._model_call_count,
            "token_usage": {
                "prompt": self._prompt_tokens,
                "completion": self._completion_tokens,
                "total": self._prompt_tokens + self._completion_tokens,
            },
            "cancelled_runs": len(self._cancelled_runs),
            "context_count": len(self._contexts),
        }

    # ------------------------------------------------------------------
    # SIGKILL / Run Cancellation
    # ------------------------------------------------------------------

    def cancel_run(self, invocation_id: str) -> None:
        """Cancel a run (SIGKILL equivalent).

        ADK runs are local, so cancellation works by setting a flag
        that every governance hook checks. When detected, callbacks
        return a blocking response immediately.

        Args:
            invocation_id: The ADK invocation ID to cancel.
        """
        self._cancelled_runs.add(invocation_id)
        ctx = self._contexts.get(invocation_id)
        if ctx is not None:
            ctx.cancelled = True
        self._record("run_cancelled", "kernel", {"invocation_id": invocation_id})
        logger.warning("Run cancelled (SIGKILL): %s", invocation_id)

    def is_cancelled(self, invocation_id: str) -> bool:
        """Check whether a run has been cancelled.

        Args:
            invocation_id: The ADK invocation ID to check.

        Returns:
            True if the run was previously cancelled via :meth:`cancel_run`.
        """
        return invocation_id in self._cancelled_runs

    # ------------------------------------------------------------------
    # Plugin Factory
    # ------------------------------------------------------------------

    def as_plugin(self, name: str = "governance") -> "GovernancePlugin":
        """Return a :class:`GovernancePlugin` backed by this kernel.

        The plugin implements all 12 ADK ``BasePlugin`` lifecycle hooks
        and delegates governance decisions to this kernel's policy engine.

        Register the returned plugin on the ADK ``Runner``::

            kernel = GoogleADKKernel(blocked_tools=["shell"])
            runner = Runner(
                agent=root_agent,
                plugins=[kernel.as_plugin()],
            )

        Args:
            name: Plugin name registered with the runner.

        Returns:
            A :class:`GovernancePlugin` instance.
        """
        return GovernancePlugin(kernel=self, name=name)



# =====================================================================
# Governance Plugin (ADK BasePlugin)
# =====================================================================


# Build the base class list dynamically so the module loads even when
# google-adk is not installed.
_PluginBase: type = _ADKBasePlugin if _ADKBasePlugin is not None else object


class GovernancePlugin(_PluginBase):  # type: ignore[misc]
    """Runner-scoped governance plugin for Google ADK.

    Implements all 12 ADK ``BasePlugin`` lifecycle hooks and delegates
    governance decisions to a :class:`GoogleADKKernel` instance.

    Register on the ``Runner`` via :meth:`GoogleADKKernel.as_plugin`::

        kernel = GoogleADKKernel(
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE"],
        )
        runner = Runner(
            agent=root_agent,
            plugins=[kernel.as_plugin()],
        )

    Plugin callbacks execute **before** agent-level callbacks and can
    short-circuit execution by returning a non-None value.
    """

    def __init__(self, kernel: GoogleADKKernel, name: str = "governance") -> None:
        # Only call super().__init__ when the real BasePlugin is available
        if _ADKBasePlugin is not None:
            super().__init__(name=name)
        self._kernel = kernel
        self._name = name

    # Expose for introspection even when BasePlugin is absent
    @property
    def plugin_name(self) -> str:
        return self._name

    # ── helpers ────────────────────────────────────────────────────

    def _get_invocation_id(self, ctx: Any) -> str:
        """Extract invocation_id from an InvocationContext or CallbackContext."""
        # InvocationContext has .invocation_id directly
        inv_id = getattr(ctx, "invocation_id", None)
        if inv_id:
            return str(inv_id)
        # Fallback: generate a transient id
        return str(uuid.uuid4())

    def _check_cancelled(self, ctx: Any) -> Optional[dict[str, Any]]:
        """Return a blocking response if the invocation has been cancelled."""
        inv_id = self._get_invocation_id(ctx)
        if self._kernel.is_cancelled(inv_id):
            return {"error": f"Run cancelled (SIGKILL): {inv_id}"}
        return None

    def _extract_agent_name(self, agent: Any = None, ctx: Any = None) -> str:
        """Best-effort agent name extraction."""
        if agent is not None:
            name = getattr(agent, "name", None)
            if name:
                return str(name)
        if ctx is not None:
            name = getattr(ctx, "agent_name", None)
            if name:
                return str(name)
        return "unknown"

    # ── 1. User Message ────────────────────────────────────────────

    async def on_user_message_callback(
        self, *, invocation_context: Any, user_message: Any
    ) -> Any:
        """Content-filter the raw user message.

        Validates the ``user_message`` structure defensively: if ``parts``
        is not iterable or individual parts lack a ``text`` attribute the
        method degrades gracefully without raising.
        """
        cancelled = self._check_cancelled(invocation_context)
        if cancelled:
            return cancelled  # type: ignore[return-value]

        # Extract text from Content object — defensive against malformed input
        text = ""
        parts = getattr(user_message, "parts", None)
        if parts is not None:
            # Ensure parts is actually iterable (not a scalar or string)
            if not hasattr(parts, "__iter__") or isinstance(parts, (str, bytes)):
                parts = []
            for part in parts:
                t = getattr(part, "text", None)
                if t:
                    text += str(t)

        if text:
            result = self._kernel.evaluate_input(None, text)
            if not result.allowed:
                self._kernel._record(
                    "user_message_blocked",
                    "plugin",
                    {"reason": result.reason},
                )
                raise self._kernel._raise_violation(result)

        return None

    # ── 2. Before Run ──────────────────────────────────────────────

    async def before_run_callback(
        self, *, invocation_context: Any
    ) -> Any:
        """Initialize execution context and check cancellation."""
        inv_id = self._get_invocation_id(invocation_context)

        cancelled = self._check_cancelled(invocation_context)
        if cancelled:
            return cancelled  # type: ignore[return-value]

        # Create a fresh ADKExecutionContext for this run
        ctx = ADKExecutionContext(
            agent_id=inv_id,
            session_id=getattr(invocation_context, "session_id", inv_id),
            invocation_id=inv_id,
        )
        self._kernel._contexts[inv_id] = ctx
        self._kernel._record("run_started", "plugin", {"invocation_id": inv_id})
        return None

    # ── 3. Before Agent ────────────────────────────────────────────

    async def before_agent_callback(
        self, *, agent: Any = None, callback_context: Any = None
    ) -> Any:
        """Agent call limits and timeout enforcement."""
        ctx = callback_context or agent
        cancelled = self._check_cancelled(ctx)
        if cancelled:
            return cancelled  # type: ignore[return-value]

        # Delegate to kernel's existing agent governance
        result = self._kernel.before_agent_callback(
            callback_context=callback_context, agent_name=self._extract_agent_name(agent, callback_context)
        )

        # Track agent name in context
        inv_id = self._get_invocation_id(ctx)
        exec_ctx = self._kernel._contexts.get(inv_id)
        if exec_ctx is not None:
            name = self._extract_agent_name(agent, callback_context)
            if name not in exec_ctx.agent_names:
                exec_ctx.agent_names.append(name)

        return result

    # ── 4. After Agent ─────────────────────────────────────────────

    async def after_agent_callback(
        self, *, agent: Any = None, callback_context: Any = None
    ) -> Any:
        """Output content filtering and audit logging."""
        agent_name = self._extract_agent_name(agent, callback_context)
        self._kernel._record("after_agent", agent_name, {})
        return None

    # ── 5. Before Model ────────────────────────────────────────────

    async def before_model_callback(
        self, *, callback_context: Any = None, llm_request: Any = None
    ) -> Any:
        """Token budget pre-check and model call counting."""
        cancelled = self._check_cancelled(callback_context)
        if cancelled:
            return cancelled  # type: ignore[return-value]

        self._kernel._model_call_count += 1

        inv_id = self._get_invocation_id(callback_context)
        exec_ctx = self._kernel._contexts.get(inv_id)
        if exec_ctx is not None:
            exec_ctx.model_calls += 1

        self._kernel._record(
            "before_model",
            self._extract_agent_name(ctx=callback_context),
            {"model_call": self._kernel._model_call_count},
        )
        return None

    # ── 6. After Model ─────────────────────────────────────────────

    async def after_model_callback(
        self, *, callback_context: Any = None, llm_response: Any = None
    ) -> Any:
        """Token usage tracking from LlmResponse."""
        # Attempt to extract token usage — graceful if missing
        usage = getattr(llm_response, "usage_metadata", None)
        if usage is None:
            usage = getattr(llm_response, "usage", None)

        prompt_tok = 0
        completion_tok = 0
        if usage is not None:
            prompt_tok = getattr(usage, "prompt_token_count", 0) or 0
            completion_tok = getattr(usage, "candidates_token_count", 0) or 0
            # Fallback field names (LiteLLM / OpenAI style)
            if not prompt_tok:
                prompt_tok = getattr(usage, "prompt_tokens", 0) or 0
            if not completion_tok:
                completion_tok = getattr(usage, "completion_tokens", 0) or 0

        self._kernel._prompt_tokens += prompt_tok
        self._kernel._completion_tokens += completion_tok

        inv_id = self._get_invocation_id(callback_context)
        exec_ctx = self._kernel._contexts.get(inv_id)
        if exec_ctx is not None:
            exec_ctx.prompt_tokens += prompt_tok
            exec_ctx.completion_tokens += completion_tok

        self._kernel._record(
            "after_model",
            self._extract_agent_name(ctx=callback_context),
            {"prompt_tokens": prompt_tok, "completion_tokens": completion_tok},
        )
        return None

    # ── 7. Model Error ─────────────────────────────────────────────

    async def on_model_error_callback(
        self,
        *,
        callback_context: Any = None,
        llm_request: Any = None,
        error: Exception | None = None,
    ) -> Any:
        """Record model errors for audit trail."""
        self._kernel._record(
            "model_error",
            self._extract_agent_name(ctx=callback_context),
            {"error": str(error) if error else "unknown"},
        )
        # Return None → let the original exception propagate
        return None

    # ── 8. Before Tool ─────────────────────────────────────────────

    async def before_tool_callback(
        self,
        *,
        tool: Any = None,
        tool_args: dict[str, Any] | None = None,
        tool_context: Any = None,
    ) -> Any:
        """Tool allow/block, content scan, human approval."""
        cancelled = self._check_cancelled(tool_context)
        if cancelled:
            return cancelled

        # Delegate to kernel's existing tool governance
        result = self._kernel.before_tool_callback(
            tool_context=tool_context,
            tool_name=getattr(tool, "name", "unknown") if tool else "unknown",
            tool_args=tool_args or {},
        )
        return result

    # ── 9. After Tool ──────────────────────────────────────────────

    async def after_tool_callback(
        self,
        *,
        tool: Any = None,
        tool_args: dict[str, Any] | None = None,
        tool_context: Any = None,
        tool_result: Any = None,
    ) -> Any:
        """Output content filtering on tool results."""
        result = self._kernel.after_tool_callback(
            tool_context=tool_context,
            tool_result=tool_result,
            tool_name=getattr(tool, "name", "unknown") if tool else "unknown",
        )
        return result

    # ── 10. Tool Error ─────────────────────────────────────────────

    async def on_tool_error_callback(
        self,
        *,
        tool: Any = None,
        tool_args: dict[str, Any] | None = None,
        tool_context: Any = None,
        error: Exception | None = None,
    ) -> Any:
        """Record tool errors for audit trail."""
        tool_name = getattr(tool, "name", "unknown") if tool else "unknown"
        self._kernel._record(
            "tool_error",
            self._extract_agent_name(ctx=tool_context),
            {"tool": tool_name, "error": str(error) if error else "unknown"},
        )
        # Return None → let the original exception propagate
        return None

    # ── 11. Event ──────────────────────────────────────────────────

    async def on_event_callback(
        self, *, invocation_context: Any = None, event: Any = None
    ) -> Any:
        """Event-level audit enrichment."""
        author = getattr(event, "author", "unknown")
        self._kernel._record(
            "event",
            str(author),
            {"event_type": type(event).__name__},
        )
        return None

    # ── 12. After Run ──────────────────────────────────────────────

    async def after_run_callback(
        self, *, invocation_context: Any = None
    ) -> None:
        """Final audit summary and context teardown."""
        inv_id = self._get_invocation_id(invocation_context)
        exec_ctx = self._kernel._contexts.get(inv_id)
        summary: dict[str, Any] = {"invocation_id": inv_id}
        if exec_ctx is not None:
            summary.update({
                "agent_names": exec_ctx.agent_names,
                "model_calls": exec_ctx.model_calls,
                "prompt_tokens": exec_ctx.prompt_tokens,
                "completion_tokens": exec_ctx.completion_tokens,
                "cancelled": exec_ctx.cancelled,
            })
        self._kernel._record("run_completed", "plugin", summary)


__all__ = [
    "GoogleADKKernel",
    "GovernancePlugin",
    "ADKExecutionContext",
    "PolicyViolationError",
    "AuditEvent",
]
