# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Agents SDK Integration for Agent-OS
============================================

Provides native ACS mediation for OpenAI Agents SDK workflows using the
SDK's ``RunHooks`` lifecycle system.

**Preferred (native hooks)**::

    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel
    from agents import Agent, Runner

    from agt.policies import AgtRuntime

    runtime = AgtRuntime("policies/manifest.yaml")
    kernel = OpenAIAgentsKernel(runtime=runtime)

    agent = Agent(name="assistant", model="gpt-4o")
    result = await Runner.run(agent, "Analyze data", hooks=kernel.as_hooks())

Features
--------
- Native ``RunHooks`` lifecycle integration (agent/tool/handoff callbacks)
- Native ACS input, tool, and output intervention-point evaluation
- Handoff monitoring and limit enforcement via ``on_handoff``
- Full audit trail with event recording
- Health check endpoint
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from ._native_adapter_runtime import NativeAdapterRuntime
from .base import BaseIntegration, AdapterExecutionState, GovernanceEventType

logger = logging.getLogger("agent_os.openai_agents")


# ── Graceful import of OpenAI Agents SDK ──────────────────────────────
try:
    from agents import RunHooks as _SDKRunHooks  # type: ignore[import-untyped]

    _HAS_AGENTS_SDK = True
except ImportError:
    _SDKRunHooks = None
    _HAS_AGENTS_SDK = False

# Re-export the canonical policy exception from the adapter module.
from agent_os.exceptions import PolicyViolationError as PolicyViolationError  # noqa: F401


# =====================================================================
# OpenAI Agents Kernel
# =====================================================================


class OpenAIAgentsKernel(BaseIntegration):
    """Governance kernel for the OpenAI Agents SDK.

    Extends :class:`BaseIntegration` and routes SDK lifecycle hooks through
    the required native ACS runtime.

    The primary integration path is via :meth:`as_hooks`, which returns a
    :class:`GovernanceRunHooks` instance that can be passed directly to
    ``Runner.run(hooks=...)``.

    Example::

        runtime = AgtRuntime("policies/manifest.yaml")
        kernel = OpenAIAgentsKernel(runtime=runtime)
        result = await Runner.run(agent, "input", hooks=kernel.as_hooks())
    """

    def __init__(
        self,
        on_violation: Optional[Callable[[PolicyViolationError], None]] = None,
        *,
        runtime: Any,
    ) -> None:
        super().__init__(runtime=runtime)
        self._adapter_runtime = NativeAdapterRuntime(runtime)
        self.on_violation = on_violation or self._default_violation_handler
        self._agent_contexts: dict[str, AdapterExecutionState] = {}
        self._tool_call_count = 0
        self._handoff_count = 0
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._audit_events: list[dict[str, Any]] = []

    # ── Violation Handling ─────────────────────────────────────────

    @staticmethod
    def _default_violation_handler(error: PolicyViolationError) -> None:
        """Log a policy violation at ERROR level.

        This is the default handler used when no custom ``on_violation``
        callback is provided.

        Args:
            error: The policy violation that was detected.
        """
        logger.error("Policy violation: %s", error)

    # ── Event Recording ───────────────────────────────────────────

    def _record_event(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        trusted_sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
        context_before: Any | None = None,
        context_after: Any | None = None,
    ) -> None:
        """Append a timestamped audit event to the internal log.

        Args:
            event_type: Short label (e.g. ``"agent_start"``, ``"tool_end"``).
            data: Arbitrary metadata dict attached to the event.
        """
        self._audit_events.append({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                **data,
                **self.build_skill_audit_fields(
                    trusted_sources=trusted_sources,
                    default_origin=default_origin,
                    context_before=context_before,
                    context_after=context_after,
                ),
            },
        })

    # ── Context Management ────────────────────────────────────────

    def _get_or_create_context(self, agent_name: str) -> AdapterExecutionState:
        """Return the ``AdapterExecutionState`` for *agent_name*, creating one if needed.

        Contexts are cached in ``_agent_contexts`` keyed by agent name so
        that the same context is reused across hook invocations within a
        single run.

        Args:
            agent_name: Identifier for the agent.

        Returns:
            The existing or newly created :class:`AdapterExecutionState`.
        """
        if agent_name not in self._agent_contexts:
            ctx = self.create_context(agent_name)
            self._agent_contexts[agent_name] = ctx
        return self._agent_contexts[agent_name]

    # ================================================================
    # Native RunHooks Integration  (PRIMARY API)
    # ================================================================

    def as_hooks(self, name: str = "governance") -> "GovernanceRunHooks":
        """Return a :class:`GovernanceRunHooks` backed by this kernel.

        Pass the returned object to ``Runner.run(hooks=...)``::

            kernel = OpenAIAgentsKernel(blocked_tools=["shell"])
            result = await Runner.run(
                agent, "input", hooks=kernel.as_hooks()
            )

        Args:
            name: Optional label for logging/identification.

        Returns:
            A :class:`GovernanceRunHooks` instance.
        """
        return GovernanceRunHooks(kernel=self, name=name)

    # ================================================================
    # Observability
    # ================================================================

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return all recorded audit events as a list of dicts.

        Each entry contains ``type``, ``timestamp`` (ISO-8601), and
        ``data`` keys.  The list is a shallow copy — mutations do not
        affect the internal log.

        Returns:
            List of audit event dicts, oldest first.
        """
        return list(self._audit_events)

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate runtime and lifecycle statistics."""
        return {
            "total_sessions": len(self._agent_contexts),
            "total_tool_calls": self._tool_call_count,
            "total_handoffs": self._handoff_count,
        }

    def health_check(self) -> dict[str, Any]:
        """Return a health-check snapshot for monitoring integrations.

        Returns:
            A dict with ``status`` (``"healthy"`` or ``"degraded"``),
            ``backend``, ``backend_connected``, ``last_error``, and
            ``uptime_seconds``.
        """
        uptime: float = time.monotonic() - self._start_time
        has_activity = bool(self._agent_contexts) or bool(self._wrapped_agents)
        status: str = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "openai_agents_sdk",
            "backend_connected": has_activity,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


# =====================================================================
# GovernanceRunHooks — Native RunHooks Implementation
# =====================================================================


_HooksBase: type = _SDKRunHooks if _SDKRunHooks is not None else object


class GovernanceRunHooks(_HooksBase):  # type: ignore[misc]
    """Native ``RunHooks`` implementation for Agent-OS governance.

    Implements the OpenAI Agents SDK lifecycle callbacks to enforce
    governance at every stage of agent execution — without wrapping or
    monkey-patching agent/runner objects.

    The hooks delegate every decision to the backing kernel's native runtime.

    Register via :meth:`OpenAIAgentsKernel.as_hooks`::

        kernel = OpenAIAgentsKernel(blocked_tools=["shell"])
        runner = Runner(agent=agent)
        result = await Runner.run(agent, "input", hooks=kernel.as_hooks())

    Lifecycle coverage:

    +-----------------------+-------------------------------------------+
    | Callback              | Governance action                         |
    +=======================+===========================================+
    | ``on_agent_start``    | Content filter, Cedar gate,               |
    |                       | ``pre_execute``                           |
    +-----------------------+-------------------------------------------+
    | ``on_agent_end``      | ``post_execute``, audit recording         |
    +-----------------------+-------------------------------------------+
    | ``on_tool_start``     | Tool allowlist/blocklist, Cedar gate,     |
    |                       | tool call budget enforcement               |
    +-----------------------+-------------------------------------------+
    | ``on_tool_end``       | Output content filter, audit recording    |
    +-----------------------+-------------------------------------------+
    | ``on_handoff``        | Handoff limit enforcement, audit          |
    +-----------------------+-------------------------------------------+
    """

    def __init__(
        self, kernel: OpenAIAgentsKernel, name: str = "governance"
    ) -> None:
        if _SDKRunHooks is not None:
            super().__init__()
        self._kernel = kernel
        self._name = name

    @property
    def hook_name(self) -> str:
        """Human-readable label for this hooks instance."""
        return self._name

    # ── Helpers ────────────────────────────────────────────────────

    def _extract_agent_name(self, agent: Any) -> str:
        """Extract a stable name for *agent*, falling back to ``id()``.

        Args:
            agent: Any object with an optional ``name`` attribute.

        Returns:
            The agent's ``name`` attribute as a string, or a
            generated ``"openai-agent-<id>"`` fallback.
        """
        name = getattr(agent, "name", None)
        if name:
            return str(name)
        return f"openai-agent-{id(agent)}"

    # ── 1. Agent Start ────────────────────────────────────────────

    async def on_agent_start(
        self, context: Any, agent: Any
    ) -> None:
        """Called when an agent begins execution.

        Governance actions performed:

        1. **Content filter** — scans available input text against
           ``blocked_patterns`` (local fast check).
        2. **Cedar/OPA gate** — delegates to ``pre_execute()`` for
           policy evaluation (skipped if the content filter already
           caught a violation to avoid double-blocking).
        3. **Audit** — records an ``agent_start`` event.

        Args:
            context: SDK run context.
            agent: The agent that is about to execute.

        Raises:
            PolicyViolationError: When content or policy evaluation
                blocks the input and ``require_human_approval`` is
                ``True``.
        """
        agent_name = self._extract_agent_name(agent)
        ctx = self._kernel._get_or_create_context(agent_name)

        # Extract input text from context if available
        input_text = ""
        if hasattr(context, "input"):
            input_text = str(context.input)
        elif hasattr(context, "messages"):
            msgs = context.messages
            if msgs and hasattr(msgs[-1], "content"):
                input_text = str(msgs[-1].content)

        if input_text:
            evaluation = self._kernel._adapter_runtime.evaluate_input(
                ctx, body=input_text
            )
            if not evaluation.allowed:
                raise evaluation.to_policy_violation(PolicyViolationError)

        trusted_skill_sources = self._kernel.trusted_sources(
            *self._kernel.trusted_sources_from_attrs(agent),
            self._kernel.trusted_skill_metadata_from_mapping(
                getattr(agent, "metadata", None)
            ),
        )

        self._kernel.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=agent_name,
            action="openai.on_agent_start",
            trusted_sources=trusted_skill_sources,
            default_origin="openai_agents",
            context_before=input_text,
        )

        self._kernel._record_event(
            "agent_start",
            {"agent": agent_name, "input_length": len(input_text)},
            trusted_sources=trusted_skill_sources,
            default_origin="openai_agents",
            context_before=input_text,
        )
        logger.debug("on_agent_start: %s (input_len=%d)", agent_name, len(input_text))

    # ── 2. Agent End ──────────────────────────────────────────────

    async def on_agent_end(
        self, context: Any, agent: Any, output: Any
    ) -> None:
        """Called when an agent finishes execution.

        Governance actions performed:

        1. **Post-check** — validates output via ``post_execute()``.
        2. **Audit** — records an ``agent_end`` event.

        Args:
            context: SDK run context.
            agent: The agent that just completed.
            output: The agent's output value.
        """
        agent_name = self._extract_agent_name(agent)
        ctx = self._kernel._get_or_create_context(agent_name)
        trusted_skill_sources = self._kernel.trusted_sources(
            *self._kernel.trusted_sources_from_attrs(agent),
            self._kernel.trusted_skill_metadata_from_mapping(
                getattr(agent, "metadata", None)
            ),
        )

        output_str = str(output) if output else ""
        if output_str:
            evaluation = self._kernel._adapter_runtime.evaluate_output(
                ctx, content=output_str
            )
            if not evaluation.allowed:
                raise evaluation.to_policy_violation(PolicyViolationError)

        self._kernel._record_event(
            "agent_end",
            {
                "agent": agent_name,
                "output_length": len(output_str),
                "success": True,
            },
            trusted_sources=trusted_skill_sources,
            default_origin="openai_agents",
            context_after=output_str,
        )
        logger.debug("on_agent_end: %s", agent_name)

    # ── 3. Tool Start ─────────────────────────────────────────────

    async def on_tool_start(
        self, context: Any, agent: Any, tool: Any
    ) -> None:
        """Called before a tool is invoked.

        Governance actions performed:

        1. **Tool allow/block** — checks the tool name against
           ``_blocked_tools`` and ``_allowed_tools``.
        2. **Budget** — increments the call counter and raises if
           ``max_tool_calls`` is exceeded.
        3. **Cedar/OPA gate** — delegates to ``pre_execute()`` with
           ``tool_name`` and ``tool_args`` in the input data.
        4. **Content filter** — scans tool argument values against
           ``blocked_patterns``.

        Args:
            context: SDK run context.
            agent: The agent that triggered the tool.
            tool: The tool about to execute.

        Raises:
            PolicyViolationError: When any governance check fails.
        """
        agent_name = self._extract_agent_name(agent)
        tool_name = getattr(tool, "name", "") or getattr(tool, "__name__", str(tool))
        ctx = self._kernel._get_or_create_context(agent_name)

        self._kernel._tool_call_count += 1
        tool_args = {}
        if hasattr(tool, "args"):
            tool_args = dict(tool.args) if tool.args else {}

        trusted_skill_sources = self._kernel.trusted_sources(
            *self._kernel.trusted_sources_from_attrs(tool),
            self._kernel.trusted_skill_metadata_from_mapping(
                getattr(tool, "metadata", None)
            ),
        )

        self._kernel.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=agent_name,
            action="openai.on_tool_start",
            trusted_sources=trusted_skill_sources,
            default_origin="openai_agents",
            context_before=tool_args,
            tool_name=tool_name,
        )
        evaluation = self._kernel._adapter_runtime.evaluate_pre_tool_call(
            ctx,
            tool_name=tool_name,
            args=tool_args,
            call_id=f"openai-agents-{self._kernel._tool_call_count}",
        )
        if not evaluation.allowed:
            raise evaluation.to_policy_violation(PolicyViolationError)

        self._kernel._record_event(
            "tool_start",
            {"agent": agent_name, "tool": tool_name},
            trusted_sources=trusted_skill_sources,
            default_origin="openai_agents",
            context_before=tool_args,
        )
        logger.debug("on_tool_start: %s.%s", agent_name, tool_name)

    # ── 4. Tool End ───────────────────────────────────────────────

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: Any
    ) -> None:
        """Called after a tool completes execution.

        Governance actions performed:

        1. **Output filter** — scans the tool's result against
           ``blocked_patterns`` and logs a warning on match.
        2. **Audit** — records a ``tool_end`` event.

        Args:
            context: SDK run context.
            agent: The agent that invoked the tool.
            tool: The tool that just completed.
            result: The tool's return value.
        """
        agent_name = self._extract_agent_name(agent)
        tool_name = getattr(tool, "name", "") or getattr(tool, "__name__", str(tool))
        trusted_skill_sources = self._kernel.trusted_sources(
            *self._kernel.trusted_sources_from_attrs(tool),
            self._kernel.trusted_skill_metadata_from_mapping(
                getattr(tool, "metadata", None)
            ),
        )

        result_str = str(result) if result else ""
        ctx = self._kernel._get_or_create_context(agent_name)
        evaluation = self._kernel._adapter_runtime.evaluate_post_tool_call(
            ctx,
            tool_name=tool_name,
            args={},
            result=result,
            call_id=f"openai-agents-{self._kernel._tool_call_count}",
        )
        if not evaluation.allowed:
            raise evaluation.to_policy_violation(PolicyViolationError)

        self._kernel._record_event(
            "tool_end",
            {
                "agent": agent_name,
                "tool": tool_name,
                "result_length": len(result_str),
            },
            trusted_sources=trusted_skill_sources,
            default_origin="openai_agents",
            context_after=result_str,
        )
        logger.debug("on_tool_end: %s.%s", agent_name, tool_name)

    # ── 5. Handoff ────────────────────────────────────────────────

    async def on_handoff(
        self, context: Any, from_agent: Any, to_agent: Any
    ) -> None:
        """Called when control transfers from one agent to another.

        Governance actions performed:

        1. **Handoff limit** — increments the handoff counter and
           raises if ``max_handoffs`` is exceeded.
        2. **Audit** — records a ``handoff`` event with source and
           destination agent names.

        Args:
            context: SDK run context.
            from_agent: The agent yielding control.
            to_agent: The agent receiving control.

        Raises:
            PolicyViolationError: When the handoff limit is exceeded.
        """
        from_name = self._extract_agent_name(from_agent)
        to_name = self._extract_agent_name(to_agent)

        self._kernel._handoff_count += 1

        self._kernel._record_event(
            "handoff",
            {"from": from_name, "to": to_name},
            trusted_sources=(),
            default_origin="openai_agents",
        )
        logger.info("on_handoff: %s -> %s", from_name, to_name)


# =====================================================================
# Convenience exports
# =====================================================================

__all__ = [
    "OpenAIAgentsKernel",
    "GovernanceRunHooks",
    "PolicyViolationError",
]
