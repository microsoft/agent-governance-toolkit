# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Agents SDK Integration for Agent-OS
============================================

Provides kernel-level governance for OpenAI Agents SDK workflows using
the SDK's native ``RunHooks`` lifecycle system.

**Preferred (native hooks)**::

    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel
    from agents import Agent, Runner

    kernel = OpenAIAgentsKernel(
        blocked_tools=["shell_exec"],
        blocked_patterns=["DROP TABLE"],
    )

    agent = Agent(name="assistant", model="gpt-4o")
    result = await Runner.run(agent, "Analyze data", hooks=kernel.as_hooks())

**With Cedar/OPA policy evaluation**::

    kernel = OpenAIAgentsKernel.from_cedar("policies/governance.cedar")
    result = await Runner.run(agent, "...", hooks=kernel.as_hooks())

**Legacy (deprecated — kept for backward compatibility)**::

    governed_agent = kernel.wrap(agent)
    GovernedRunner = kernel.wrap_runner(Runner)
    result = await GovernedRunner.run(governed_agent, "input")

Features
--------
- Native ``RunHooks`` lifecycle integration (agent/tool/handoff callbacks)
- Inherits ``BaseIntegration`` — Cedar/OPA, ``pre_execute``, ``post_execute``
- Tool allowlist/blocklist enforcement via ``on_tool_start``
- Content filtering via ``on_agent_start``
- Handoff monitoring and limit enforcement via ``on_handoff``
- Full audit trail with event recording
- Health check endpoint
- Backward-compatible ``wrap()`` / ``wrap_runner()`` / ``create_tool_guard()``
  (deprecated, will be removed in a future release)
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional

from .base import BaseIntegration, ExecutionContext, GovernancePolicy

logger = logging.getLogger("agent_os.openai_agents")


# ── Graceful import of OpenAI Agents SDK ──────────────────────────────
try:
    from agents import RunHooks as _SDKRunHooks  # type: ignore[import-untyped]

    _HAS_AGENTS_SDK = True
except ImportError:
    _SDKRunHooks = None
    _HAS_AGENTS_SDK = False

# Re-export PolicyViolationError for backward compatibility
from agent_os.exceptions import PolicyViolationError as PolicyViolationError  # noqa: F401


# =====================================================================
# OpenAI Agents Kernel
# =====================================================================


class OpenAIAgentsKernel(BaseIntegration):
    """Governance kernel for the OpenAI Agents SDK.

    Extends :class:`BaseIntegration` so that it inherits Cedar/OPA policy
    evaluation, ``pre_execute`` / ``post_execute`` governance, and
    ``from_cedar`` factory support.

    The primary integration path is via :meth:`as_hooks`, which returns a
    :class:`GovernanceRunHooks` instance that can be passed directly to
    ``Runner.run(hooks=...)``.

    Example::

        kernel = OpenAIAgentsKernel(
            blocked_tools=["shell"],
            blocked_patterns=["DROP TABLE"],
        )
        result = await Runner.run(agent, "input", hooks=kernel.as_hooks())
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        on_violation: Optional[Callable[[PolicyViolationError], None]] = None,
        *,
        evaluator: Any = None,
        # Convenience kwargs
        max_tool_calls: int = 50,
        max_handoffs: int = 5,
        timeout_seconds: int = 300,
        allowed_tools: Optional[list[str]] = None,
        blocked_tools: Optional[list[str]] = None,
        blocked_patterns: Optional[list[str]] = None,
        require_human_approval: bool = False,
    ) -> None:
        """Initialise the OpenAI Agents governance kernel.

        Args:
            policy: Full governance policy.  When ``None`` a policy is
                built from the convenience kwargs.
            on_violation: Optional callback invoked on every policy
                violation.
            evaluator: Optional ``PolicyEvaluator`` for Cedar/OPA policy
                evaluation.
            max_tool_calls: Max tool invocations before blocking.
            max_handoffs: Max agent handoffs before blocking.
            timeout_seconds: Global timeout in seconds.
            allowed_tools: If non-empty, only these tools may execute.
            blocked_tools: Tools that are always denied.
            blocked_patterns: Content substrings that are always denied.
            require_human_approval: When ``True``, violations raise
                immediately; otherwise they are logged via *on_violation*.
        """
        if policy is None:
            policy = GovernancePolicy(
                max_tool_calls=max_tool_calls,
                timeout_seconds=timeout_seconds,
                allowed_tools=allowed_tools or [],
                blocked_patterns=blocked_patterns or [],
                require_human_approval=require_human_approval,
            )
        super().__init__(policy, evaluator=evaluator)

        self.on_violation: Callable[[PolicyViolationError], None] = (
            on_violation or self._default_violation_handler
        )
        self._blocked_tools: set[str] = set(blocked_tools or [])
        self._allowed_tools: set[str] = set(
            policy.allowed_tools if policy.allowed_tools else (allowed_tools or [])
        )
        self._max_handoffs: int = max_handoffs
        self._require_human_approval: bool = (
            policy.require_human_approval
            if policy.require_human_approval
            else require_human_approval
        )

        # ── Runtime state ─────────────────────────────────────────
        self._agent_contexts: dict[str, ExecutionContext] = {}
        self._tool_call_count: int = 0
        self._handoff_count: int = 0
        self._start_time: float = time.monotonic()
        self._last_error: Optional[str] = None

        # Audit trail
        self._audit_events: list[dict[str, Any]] = []

        # Legacy wrapped agents registry (used by deprecated wrap())
        self._wrapped_agents: dict[str, Any] = {}

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

    # ── Tool / Content Checks ─────────────────────────────────────

    def _check_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check whether *tool_name* is permitted by the active policy.

        Evaluation order:

        1. If *tool_name* is in ``_blocked_tools`` → deny.
        2. If ``_allowed_tools`` is non-empty and *tool_name* is absent → deny.
        3. Otherwise → allow.

        Args:
            tool_name: The name of the tool to evaluate.

        Returns:
            A ``(allowed, reason)`` tuple.  *reason* is the empty string
            when *allowed* is ``True``.
        """
        if tool_name in self._blocked_tools:
            return False, f"Tool '{tool_name}' is blocked by policy"
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return False, f"Tool '{tool_name}' not in allowed list"
        return True, ""

    def _check_content(self, content: str) -> tuple[bool, str]:
        """Check *content* against ``blocked_patterns`` in the policy.

        Matching is case-insensitive substring search.

        Args:
            content: The text to scan.

        Returns:
            A ``(ok, reason)`` tuple.  *reason* describes the matched
            pattern when *ok* is ``False``.
        """
        content_lower = content.lower()
        for pattern in self.policy.blocked_patterns:
            if pattern.lower() in content_lower:
                return False, f"Content matches blocked pattern: {pattern}"
        return True, ""

    # ── Event Recording ───────────────────────────────────────────

    def _record_event(
        self, event_type: str, data: dict[str, Any]
    ) -> None:
        """Append a timestamped audit event to the internal log.

        Args:
            event_type: Short label (e.g. ``"agent_start"``, ``"tool_end"``).
            data: Arbitrary metadata dict attached to the event.
        """
        self._audit_events.append({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })

    # ── Context Management ────────────────────────────────────────

    def _get_or_create_context(self, agent_name: str) -> ExecutionContext:
        """Return the ``ExecutionContext`` for *agent_name*, creating one if needed.

        Contexts are cached in ``_agent_contexts`` keyed by agent name so
        that the same context is reused across hook invocations within a
        single run.

        Args:
            agent_name: Identifier for the agent.

        Returns:
            The existing or newly created :class:`ExecutionContext`.
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
    # Deprecated wrap()-Based API  (BACKWARD COMPAT)
    # ================================================================

    def wrap(self, agent: Any) -> Any:
        """Wrap an OpenAI Agent with a governance proxy.

        .. deprecated::
            Use :meth:`as_hooks` instead.  The ``wrap()`` approach creates
            a fragile proxy object that cannot intercept all SDK
            lifecycle events.  Prefer the native ``RunHooks`` path::

                result = await Runner.run(agent, "input",
                                          hooks=kernel.as_hooks())

        Args:
            agent: An OpenAI Agents SDK ``Agent`` instance.

        Returns:
            A ``GovernedAgent`` wrapper that delegates attribute access
            to *agent* and stores a governance :class:`ExecutionContext`.
        """
        warnings.warn(
            "OpenAIAgentsKernel.wrap() is deprecated. "
            "Use kernel.as_hooks() with Runner.run(hooks=...) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        agent_id = getattr(agent, "name", str(id(agent)))

        class GovernedAgent:
            def __init__(wrapper_self, original: Any, kernel: OpenAIAgentsKernel):
                wrapper_self._original = original
                wrapper_self._kernel = kernel
                wrapper_self._context = kernel._get_or_create_context(agent_id)
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
        logger.info("Wrapped agent '%s' with governance kernel (deprecated)", agent_id)
        return wrapped

    def unwrap(self, governed_agent: Any) -> Any:
        """Remove the governance wrapper and return the original agent.

        Args:
            governed_agent: A previously wrapped agent or any object.

        Returns:
            The original unwrapped agent.  If *governed_agent* was never
            wrapped, it is returned unchanged.
        """
        if hasattr(governed_agent, "_original"):
            return governed_agent._original
        return governed_agent

    def wrap_runner(self, runner_class: Any) -> Any:
        """Wrap the SDK ``Runner`` class to intercept ``run()`` calls.

        .. deprecated::
            Use :meth:`as_hooks` instead.  The ``wrap_runner()`` approach
            relies on class-level monkey-patching that cannot access
            lifecycle events between agent turns.

        Args:
            runner_class: The ``agents.Runner`` class to wrap.

        Returns:
            A ``GovernedRunner`` class with ``run()`` and ``run_sync()``
            class methods that apply governance before delegating.
        """
        warnings.warn(
            "OpenAIAgentsKernel.wrap_runner() is deprecated. "
            "Use kernel.as_hooks() with Runner.run(hooks=...) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        kernel = self

        class GovernedRunner:
            @classmethod
            async def run(cls, agent: Any, input_text: str, **kwargs) -> Any:
                ctx = getattr(agent, "_context", None)
                if ctx:
                    ok, reason = kernel._check_content(input_text)
                    if not ok:
                        error = PolicyViolationError(
                            f"Content blocked: {reason}"
                        )
                        kernel.on_violation(error)
                        if kernel._require_human_approval:
                            raise error
                    ctx.tool_calls.append({
                        "type": "run_start",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "data": {"input_length": len(input_text)},
                    })

                original_agent = getattr(agent, "_original", agent)
                try:
                    result = await runner_class.run(
                        original_agent, input_text, **kwargs
                    )
                    if ctx:
                        ctx.tool_calls.append({
                            "type": "run_complete",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "data": {"success": True},
                        })
                    return result
                except Exception as e:
                    if ctx:
                        ctx.tool_calls.append({
                            "type": "run_error",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "data": {"error": str(e)},
                        })
                    raise

            @classmethod
            def run_sync(cls, agent: Any, input_text: str, **kwargs) -> Any:
                return asyncio.run(cls.run(agent, input_text, **kwargs))

        return GovernedRunner

    def create_tool_guard(self) -> Callable:
        """Create a decorator that applies governance checks to tool functions.

        .. deprecated::
            Tool governance is now handled automatically via
            :meth:`as_hooks` through the ``on_tool_start`` hook.

        Returns:
            A decorator that wraps sync or async callables with tool
            allow/block and content-filter checks.

        Raises:
            PolicyViolationError: When the decorated tool's name is
                blocked or its arguments contain blocked content.
        """
        warnings.warn(
            "OpenAIAgentsKernel.create_tool_guard() is deprecated. "
            "Tool governance is handled via as_hooks() on_tool_start.",
            DeprecationWarning,
            stacklevel=2,
        )
        kernel = self

        def guard(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                tool_name = func.__name__
                ok, reason = kernel._check_tool_allowed(tool_name)
                if not ok:
                    error = PolicyViolationError(f"Tool blocked: {reason}")
                    kernel.on_violation(error)
                    raise error

                for arg in args:
                    if isinstance(arg, str):
                        ok, reason = kernel._check_content(arg)
                        if not ok:
                            error = PolicyViolationError(
                                f"Content blocked: {reason}"
                            )
                            kernel.on_violation(error)
                            raise error
                for value in kwargs.values():
                    if isinstance(value, str):
                        ok, reason = kernel._check_content(value)
                        if not ok:
                            error = PolicyViolationError(
                                f"Content blocked: {reason}"
                            )
                            kernel.on_violation(error)
                            raise error

                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)

            return wrapper
        return guard

    def create_guardrail(self) -> Any:
        """Create an OpenAI Agents SDK compatible guardrail callable.

        The returned object is an async callable with the guardrail
        signature ``(context, agent, input_text) -> str | None``.
        Returns ``None`` when the input passes all checks, or a
        human-readable rejection string when content or tool calls
        violate the active policy.

        Returns:
            A ``PolicyGuardrail`` instance.
        """
        kernel = self

        class PolicyGuardrail:
            """OpenAI Agents SDK guardrail backed by Agent-OS governance."""

            async def __call__(
                self,
                context: Any,
                agent: Any,
                input_text: str,
            ) -> str | None:
                """Evaluate governance rules and return a rejection or None.

                Args:
                    context: SDK run context (may contain ``tool_calls``).
                    agent: The agent being guarded.
                    input_text: The user input to check.

                Returns:
                    A rejection message string, or ``None`` if allowed.
                """
                ok, reason = kernel._check_content(input_text)
                if not ok:
                    logger.warning("Guardrail blocked: %s", reason)
                    return f"Request blocked by policy: {reason}"

                if hasattr(context, "tool_calls"):
                    for tool_call in context.tool_calls:
                        tool_name = getattr(tool_call, "name", "")
                        ok, reason = kernel._check_tool_allowed(tool_name)
                        if not ok:
                            logger.warning("Guardrail blocked tool: %s", reason)
                            return f"Tool blocked by policy: {reason}"
                return None

        return PolicyGuardrail()

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
        """Return aggregate governance statistics.

        Returns:
            A dict containing ``total_sessions``, ``total_tool_calls``,
            ``total_handoffs``, ``wrapped_agents``, and a ``policy``
            sub-dict with the active configuration.
        """
        return {
            "total_sessions": len(self._agent_contexts),
            "total_tool_calls": self._tool_call_count,
            "total_handoffs": self._handoff_count,
            "wrapped_agents": len(self._wrapped_agents),
            "policy": {
                "max_tool_calls": self.policy.max_tool_calls,
                "max_handoffs": self._max_handoffs,
                "blocked_tools": sorted(self._blocked_tools),
                "allowed_tools": sorted(self._allowed_tools),
            },
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

    The hooks delegate all governance decisions to the backing
    :class:`OpenAIAgentsKernel`, which in turn uses
    :class:`BaseIntegration`'s ``pre_execute``, Cedar/OPA evaluation,
    and ``GovernancePolicy`` checks.

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

        # Content filter (local fast check)
        content_violated = False
        if input_text:
            ok, reason = self._kernel._check_content(input_text)
            if not ok:
                content_violated = True
                error = PolicyViolationError(
                    f"Agent start blocked: {reason}"
                )
                self._kernel.on_violation(error)
                if self._kernel._require_human_approval:
                    raise error

        # Cedar/OPA + GovernancePolicy gate (skip if content already
        # failed locally and was logged — avoids double-block)
        if input_text and not content_violated:
            allowed, reason = self._kernel.pre_execute(ctx, input_text)
            if not allowed:
                raise PolicyViolationError(
                    f"Agent '{agent_name}' blocked by governance: {reason}"
                )

        self._kernel._record_event(
            "agent_start",
            {"agent": agent_name, "input_length": len(input_text)},
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

        # Post-check output
        output_str = str(output) if output else ""
        if output_str:
            valid, reason = self._kernel.post_execute(ctx, output_str)
            if not valid:
                logger.warning(
                    "Agent '%s' output violated policy: %s", agent_name, reason
                )

        self._kernel._record_event(
            "agent_end",
            {
                "agent": agent_name,
                "output_length": len(output_str),
                "success": True,
            },
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

        # (a) Tool allow/block check
        ok, reason = self._kernel._check_tool_allowed(tool_name)
        if not ok:
            error = PolicyViolationError(
                f"Tool '{tool_name}' blocked: {reason}"
            )
            self._kernel.on_violation(error)
            raise error

        # (b) Budget check
        self._kernel._tool_call_count += 1
        if self._kernel._tool_call_count > self._kernel.policy.max_tool_calls:
            error = PolicyViolationError(
                f"Tool call budget exceeded: "
                f"{self._kernel._tool_call_count}/{self._kernel.policy.max_tool_calls}"
            )
            self._kernel.on_violation(error)
            raise error

        # (c) Cedar/OPA gate with tool identity
        tool_args = {}
        if hasattr(tool, "args"):
            tool_args = dict(tool.args) if tool.args else {}
        allowed, reason = self._kernel.pre_execute(
            ctx,
            {"tool_name": tool_name, "tool_args": tool_args},
        )
        if not allowed:
            raise PolicyViolationError(
                f"Tool '{tool_name}' blocked by governance: {reason}"
            )

        # (d) Content filter on args
        for value in tool_args.values():
            if isinstance(value, str):
                ok, reason = self._kernel._check_content(value)
                if not ok:
                    error = PolicyViolationError(
                        f"Tool argument blocked: {reason}"
                    )
                    self._kernel.on_violation(error)
                    raise error

        self._kernel._record_event(
            "tool_start",
            {"agent": agent_name, "tool": tool_name},
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

        # Content filter on output
        result_str = str(result) if result else ""
        if result_str:
            ok, reason = self._kernel._check_content(result_str)
            if not ok:
                logger.warning(
                    "Tool '%s' output contains blocked pattern: %s",
                    tool_name,
                    reason,
                )

        self._kernel._record_event(
            "tool_end",
            {
                "agent": agent_name,
                "tool": tool_name,
                "result_length": len(result_str),
            },
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

        if self._kernel._handoff_count > self._kernel._max_handoffs:
            error = PolicyViolationError(
                f"Handoff limit exceeded: "
                f"{self._kernel._handoff_count}/{self._kernel._max_handoffs}"
            )
            self._kernel.on_violation(error)
            raise error

        self._kernel._record_event(
            "handoff",
            {"from": from_name, "to": to_name},
        )
        logger.info("on_handoff: %s -> %s", from_name, to_name)


# =====================================================================
# Convenience exports
# =====================================================================

__all__ = [
    "OpenAIAgentsKernel",
    "GovernanceRunHooks",
    "GovernancePolicy",
    "PolicyViolationError",
]
