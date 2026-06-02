# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CrewAI Integration

Provides governance for CrewAI crews and agents via **native execution hooks**
(``@before_tool_call``, ``@after_tool_call``, ``@before_llm_call``,
``@after_llm_call``) introduced in CrewAI 0.80+.

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
outbound LLM message text and tool result before CrewAI forwards them;
``escalate`` verdicts route through the configured approval resolver
per AGT-DELTA D1.4.

Recommended usage (native hooks)::

    from agent_os.integrations.crewai_adapter import CrewAIKernel, GovernancePolicy

    kernel = CrewAIKernel(policy=GovernancePolicy(
        blocked_patterns=["DROP TABLE"],
        allowed_tools=["search", "calculator"],
    ))
    hooks = kernel.as_hooks()        # registers governance hooks globally
    result = my_crew.kickoff()       # hooks intercept every tool & LLM call
    hooks.unregister()               # clean up when done

Legacy usage (deprecated)::

    governed_crew = kernel.wrap(my_crew)
    result = governed_crew.kickoff()
"""

import functools
import logging
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from .base import (
    PII_PATTERNS,
    BaseIntegration,
    GovernancePolicy,
    PolicyInterceptor,
    PolicyViolationError,
    ToolCallRequest,
)

# ── Graceful import of CrewAI native hooks ────────────────────────
# CrewAI 0.80+ provides decorator-based execution hooks.  When the
# hooks module is unavailable (older CrewAI or CrewAI not installed),
# we fall back to the legacy proxy approach.

try:
    from crewai.hooks import (
        before_tool_call as _before_tool_call,
        after_tool_call as _after_tool_call,
        before_llm_call as _before_llm_call,
        after_llm_call as _after_llm_call,
    )
    _HOOKS_AVAILABLE = True
except ImportError:
    _HOOKS_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════
# GovernanceHooks  – native CrewAI execution hooks
# ═══════════════════════════════════════════════════════════════════

class GovernanceHooks:
    """Native CrewAI governance hooks for Agent OS.

    Registers four global execution hooks that intercept every tool call
    and LLM call across all agents in a crew:

    * ``before_tool_call`` – allowlist / blocklist, blocked-pattern scan,
      Cedar/OPA ``pre_execute`` gate.
    * ``after_tool_call``  – blocked-pattern scan on tool output, drift
      detection via ``post_execute``.
    * ``before_llm_call``  – content filter on input messages.
    * ``after_llm_call``   – blocked-pattern scan on LLM response.

    Parameters
    ----------
    kernel : CrewAIKernel
        The governing kernel whose policy is enforced.
    name : str, optional
        Human-readable name for logging (default ``"governance"``).

    Notes
    -----
    CrewAI hooks are **global** – they apply to every crew in the
    current process.  Only one ``GovernanceHooks`` instance should be
    active at a time.  Call :meth:`unregister` to deactivate.

    Examples
    --------
    >>> kernel = CrewAIKernel(policy=GovernancePolicy(allowed_tools=["search"]))
    >>> hooks = kernel.as_hooks()
    >>> result = my_crew.kickoff()
    >>> hooks.unregister()
    """

    def __init__(self, kernel: "CrewAIKernel", name: str = "governance"):
        self._kernel = kernel
        self._name = name
        self._ctx = kernel.create_context(f"crewai-hooks-{name}")
        self._registered = False
        self._hook_fns: list[Any] = []
        logger.debug(
            "GovernanceHooks created: name=%s, hooks_available=%s",
            name,
            _HOOKS_AVAILABLE,
        )

    # ── Registration ──────────────────────────────────────────────

    def register(self) -> "GovernanceHooks":
        """Register the four governance hooks with CrewAI.

        Returns
        -------
        GovernanceHooks
            Self, for chaining.

        Raises
        ------
        RuntimeError
            If ``crewai.hooks`` is not available.
        """
        if not _HOOKS_AVAILABLE:
            raise RuntimeError(
                "crewai.hooks is not available. "
                "Upgrade to CrewAI 0.80+ or use the legacy wrap() method."
            )
        if self._registered:
            logger.debug("GovernanceHooks already registered, skipping")
            return self

        # Create governed hook functions and register them
        bt = _before_tool_call(self._make_before_tool_call())
        at = _after_tool_call(self._make_after_tool_call())
        bl = _before_llm_call(self._make_before_llm_call())
        al = _after_llm_call(self._make_after_llm_call())
        self._hook_fns = [bt, at, bl, al]

        self._registered = True
        logger.info("[%s] Governance hooks registered with CrewAI", self._name)
        return self

    def unregister(self) -> None:
        """Deactivate governance hooks.

        .. note::
           CrewAI's global hook registry currently does not expose an
           ``unregister`` API.  This method clears the internal state
           so re-registration is possible but does not remove the
           previously registered functions from CrewAI's registry.
        """
        self._registered = False
        self._hook_fns.clear()
        logger.info("[%s] Governance hooks unregistered", self._name)

    # ── Hook Factories ────────────────────────────────────────────

    def _make_before_tool_call(self):
        """Return the ``before_tool_call`` governance function.

        Returns
        -------
        callable
            A function conforming to CrewAI's ``ToolCallHookContext``
            protocol that returns ``False`` to block or ``None`` to allow.
        """
        kernel = self._kernel
        ctx = self._ctx
        name = self._name

        def governance_before_tool(context) -> "bool | None":
            """Governance gate executed before every tool call.

            Checks tool allowlist/blocklist, scans arguments for blocked
            patterns, and runs Cedar/OPA ``pre_execute`` evaluation.

            Parameters
            ----------
            context : ToolCallHookContext
                CrewAI hook context with ``tool_name``, ``tool_input``,
                ``agent``, ``task``, and ``crew`` attributes.

            Returns
            -------
            bool | None
                ``False`` to block the tool call, ``None`` to allow.
            """
            tool_name = getattr(context, "tool_name", "unknown")
            tool_input = getattr(context, "tool_input", {})
            agent_name = getattr(
                getattr(context, "agent", None), "role",
                getattr(getattr(context, "agent", None), "name", "unknown"),
            )

            logger.debug(
                "[%s] before_tool_call: tool=%s agent=%s",
                name, tool_name, agent_name,
            )

            # Host-side defensive pattern scan on the tool name and the
            # serialised arguments. The AGT manifest bridge only emits a
            # pattern check against ``input.policy_target.value`` (a
            # string), so tool-name and dict-arg pattern matching stays
            # on the host side to preserve the v4 behavioural contract.
            for candidate in (tool_name, str(tool_input)):
                matched = kernel.policy.matches_pattern(candidate)
                if matched:
                    logger.info(
                        "[%s] Policy DENY: blocked pattern '%s' in tool name/args",
                        name, matched[0],
                    )
                    return False

            # ─── AGT pre_tool_call evaluation ────────────────────
            bridge_result = kernel.evaluate_pre_tool_call(
                ctx,
                tool_name=tool_name,
                args=tool_input,
                call_id=getattr(context, "tool_call_id", "call-1"),
            )
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, dict
            ):
                try:
                    context.tool_input = bridge_result.transform.value
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass
            if not bridge_result.allowed:
                logger.info(
                    "[%s] Policy DENY (AGT pre_tool_call): %s",
                    name,
                    bridge_result.reason,
                )
                return False

            # ─── Increment call count ─────────────────────────────
            # The bridge mirrors ``ctx.call_count`` into the snapshot
            # builder via ``max(builder.tool_call_count, ctx.call_count)``
            # on every access, so incrementing here is sufficient. Calling
            # ``record_post_execute(tool_calls=1)`` in addition double-counts
            # the call and trips ``max_tool_calls`` one call early.
            ctx.call_count += 1

            logger.debug(
                "[%s] Tool ALLOW: tool=%s count=%d",
                name, tool_name, ctx.call_count,
            )
            return None  # allow

        return governance_before_tool

    def _make_after_tool_call(self):
        """Return the ``after_tool_call`` governance function.

        Returns
        -------
        callable
            A function that checks tool output for blocked patterns
            and runs ``post_execute`` drift detection.
        """
        kernel = self._kernel
        ctx = self._ctx
        name = self._name

        def governance_after_tool(context) -> None:
            """Governance gate executed after every tool call.

            Scans the tool result for blocked patterns and runs
            drift detection via ``post_execute``.

            Parameters
            ----------
            context : ToolCallHookContext
                CrewAI hook context with ``tool_result`` available.

            Returns
            -------
            None
                Always returns ``None``.  Violations are raised as
                ``PolicyViolationError``.

            Raises
            ------
            PolicyViolationError
                If the tool output contains a blocked pattern.
            """
            tool_name = getattr(context, "tool_name", "unknown")
            tool_result = getattr(context, "tool_result", None)

            if tool_result and isinstance(tool_result, str):
                # AGT output intervention point evaluates the tool result
                post_result = kernel.evaluate_output(ctx, tool_result)
                if not post_result.allowed:
                    logger.info(
                        "[%s] Policy DENY (AGT output) on tool output: %s",
                        name, post_result.reason,
                    )
                    raise PolicyViolationError.from_check_result(
                        post_result.check_result
                    )
                if post_result.transform is not None and isinstance(
                    post_result.transform.value, str
                ):
                    try:
                        context.tool_result = post_result.transform.value
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass

            logger.debug("[%s] after_tool_call OK: tool=%s", name, tool_name)
            return None

        return governance_after_tool

    def _make_before_llm_call(self):
        """Return the ``before_llm_call`` governance function.

        Returns
        -------
        callable
            A function that scans LLM input messages for blocked
            patterns and runs ``pre_execute`` checks.
        """
        kernel = self._kernel
        ctx = self._ctx
        name = self._name

        def governance_before_llm(context) -> "bool | None":
            """Governance gate executed before every LLM call.

            Scans the message list for blocked patterns and runs
            Cedar/OPA ``pre_execute`` checks.

            Parameters
            ----------
            context : LLMCallHookContext
                CrewAI context with ``messages``, ``agent``, ``task``,
                ``iterations`` attributes.

            Returns
            -------
            bool | None
                ``False`` to block the LLM call, ``None`` to allow.
            """
            messages = getattr(context, "messages", None) or []

            # ─── 1. Defensive content-pattern scan on input messages ─
            # Mirrors the v4 behaviour because the AGT input intervention
            # point in the manifest bridge pattern-matches a single
            # ``policy_target.value`` string; multi-message scans stay
            # on the host side.
            for msg in messages:
                content = None
                if isinstance(msg, dict):
                    content = msg.get("content", "")
                elif isinstance(msg, str):
                    content = msg
                else:
                    content = getattr(msg, "content", str(msg))

                if content and isinstance(content, str):
                    matched = kernel.policy.matches_pattern(content)
                    if matched:
                        logger.info(
                            "[%s] Policy DENY: blocked pattern '%s' in LLM input",
                            name, matched[0],
                        )
                        return False

            # ─── 2. AGT input intervention point on combined messages ─
            combined_input = " ".join(
                str(m.get("content", m) if isinstance(m, dict) else m)
                for m in messages
            ) if messages else ""

            if combined_input.strip():
                pre_result = kernel.evaluate_input(ctx, combined_input)
                if not pre_result.allowed:
                    logger.info(
                        "[%s] Policy DENY (AGT input) on LLM input: %s",
                        name, pre_result.reason,
                    )
                    return False
                if pre_result.transform is not None and isinstance(
                    pre_result.transform.value, str
                ):
                    # Rewrite the last user message content per AGT D1.1.
                    for msg in reversed(messages):
                        if isinstance(msg, dict) and isinstance(
                            msg.get("content"), str
                        ):
                            msg["content"] = pre_result.transform.value
                            break
                        if hasattr(msg, "content") and isinstance(
                            getattr(msg, "content"), str
                        ):
                            try:
                                msg.content = pre_result.transform.value
                            except Exception:  # noqa: BLE001 — best-effort rewrite
                                pass
                            break

            return None  # allow

        return governance_before_llm

    def _make_after_llm_call(self):
        """Return the ``after_llm_call`` governance function.

        Returns
        -------
        callable
            A function that scans LLM output for blocked patterns.
        """
        kernel = self._kernel
        ctx = self._ctx
        name = self._name

        def governance_after_llm(context) -> "str | None":
            """Governance gate executed after every LLM call.

            Scans the LLM response for blocked patterns and runs
            ``post_execute`` drift detection.

            Parameters
            ----------
            context : LLMCallHookContext
                CrewAI context with ``response`` available.

            Returns
            -------
            str | None
                ``None`` to keep original response.  Violations are
                raised as ``PolicyViolationError``.

            Raises
            ------
            PolicyViolationError
                If the LLM output contains a blocked pattern.
            """
            response = getattr(context, "response", None)

            if response and isinstance(response, str) and response.strip():
                # AGT output intervention point evaluates the LLM response
                post_result = kernel.evaluate_output(ctx, response.strip())
                if not post_result.allowed:
                    logger.info(
                        "[%s] Policy DENY (AGT output) on LLM output: %s",
                        name, post_result.reason,
                    )
                    raise PolicyViolationError.from_check_result(
                        post_result.check_result
                    )
                if post_result.transform is not None and isinstance(
                    post_result.transform.value, str
                ):
                    # Replace the LLM response per AGT D1.1.
                    try:
                        context.response = post_result.transform.value
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass
                    return post_result.transform.value

            return None  # keep original response

        return governance_after_llm

    # ── Convenience properties ────────────────────────────────────

    @property
    def kernel(self) -> "CrewAIKernel":
        """Return the governing kernel."""
        return self._kernel

    @property
    def context(self):
        """Return the execution context."""
        return self._ctx

    @property
    def is_registered(self) -> bool:
        """Return whether hooks are currently registered."""
        return self._registered

    def __repr__(self) -> str:
        return (
            f"GovernanceHooks(name={self._name!r}, "
            f"registered={self._registered})"
        )


# ═══════════════════════════════════════════════════════════════════
# CrewAIKernel  – main adapter
# ═══════════════════════════════════════════════════════════════════

class CrewAIKernel(BaseIntegration):
    """CrewAI adapter for Agent OS.

    Provides governance for CrewAI crews via two mechanisms:

    **Recommended (native hooks)**:
        Use :meth:`as_hooks` to register global execution hooks that
        intercept every tool and LLM call across all agents.

    **Legacy (deprecated)**:
        Use :meth:`wrap` to create a proxy crew object.

    Parameters
    ----------
    policy : GovernancePolicy, optional
        The governance policy to enforce.
    deep_hooks_enabled : bool
        When ``True`` (default), the legacy :meth:`wrap` method also
        applies step-level, memory, and delegation interception.
    evaluator : Any, optional
        Cedar/OPA policy evaluator for fine-grained access control.

    Examples
    --------
    >>> kernel = CrewAIKernel(policy=GovernancePolicy(allowed_tools=["search"]))
    >>> hooks = kernel.as_hooks()
    >>> # All crew executions now go through governance
    >>> result = my_crew.kickoff({"topic": "AI governance"})
    >>> hooks.unregister()
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        deep_hooks_enabled: bool = True,
        evaluator: Any = None,
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ):
        super().__init__(policy, evaluator=evaluator)
        self.deep_hooks_enabled = deep_hooks_enabled
        self._wrapped_crews: dict[int, Any] = {}
        self._step_log: list[dict[str, Any]] = []
        self._memory_audit_log: list[dict[str, Any]] = []
        self._delegation_log: list[dict[str, Any]] = []
        self._approval_resolver = approval_resolver
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )
        logger.debug(
            "CrewAIKernel initialized with policy=%s deep_hooks_enabled=%s",
            policy, deep_hooks_enabled,
        )

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this kernel."""
        return self._bridge

    def evaluate_input(self, ctx: Any, input_data: Any) -> BridgeResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_output(self, ctx: Any, output_data: Any) -> BridgeResult:
        """Public access to the AGT ``output`` intervention point evaluation."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

    def evaluate_pre_tool_call(
        self,
        ctx: Any,
        *,
        tool_name: str,
        args: Any,
        call_id: str = "call-1",
    ) -> BridgeResult:
        """AGT ``pre_tool_call`` evaluation for a CrewAI tool call."""
        normalised: dict[str, Any]
        if isinstance(args, dict):
            normalised = args
        elif isinstance(args, str):
            normalised = {"arguments": args}
        else:
            normalised = {"value": args}
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=normalised, call_id=call_id
        )

    @staticmethod
    def _to_body(data: Any) -> Any:
        """Normalise a CrewAI payload to a JSON-serialisable body.

        v4 callers passed dicts and CrewAI-specific objects to
        :meth:`pre_execute`; the AGT manifest bridge only pattern-matches
        a string ``policy_target.value``, so the adapter stringifies
        non-string payloads here so the v4 pattern contract still
        holds.
        """
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            return str(data)
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        if hasattr(data, "description"):
            return str(getattr(data, "description"))
        return str(data)

    # ── Native hooks (recommended) ────────────────────────────────

    def as_hooks(self, name: str = "governance") -> GovernanceHooks:
        """Create and register native CrewAI governance hooks.

        This is the **recommended** integration path.  The returned
        :class:`GovernanceHooks` instance registers four global hooks
        (``before_tool_call``, ``after_tool_call``, ``before_llm_call``,
        ``after_llm_call``) that enforce governance on every tool and
        LLM call across all agents in any crew.

        Parameters
        ----------
        name : str
            Human-readable name for the hooks instance (used in logs).

        Returns
        -------
        GovernanceHooks
            The registered hooks instance.

        Raises
        ------
        RuntimeError
            If ``crewai.hooks`` module is not available.

        Examples
        --------
        >>> hooks = kernel.as_hooks("prod-governance")
        >>> result = my_crew.kickoff()
        >>> hooks.unregister()
        """
        hooks = GovernanceHooks(self, name=name)
        hooks.register()
        return hooks

    # ── Legacy proxy (deprecated) ─────────────────────────────────

    def wrap(self, crew: Any) -> Any:
        """Wrap a CrewAI crew with governance.

        .. deprecated::
            Use :meth:`as_hooks` instead.  The proxy-based approach
            mutates tool, memory, and agent objects.  ``wrap()`` will
            be removed in v1.0.

        Intercepts:
        - kickoff() / kickoff_async()
        - Individual agent executions
        - Individual tool calls within agents
        - Task completions
        """
        import warnings
        warnings.warn(
            "CrewAIKernel.wrap() is deprecated. Use kernel.as_hooks() instead, "
            "which leverages CrewAI's native execution hooks. "
            "wrap() will be removed in v1.0.",
            DeprecationWarning,
            stacklevel=2,
        )

        crew_id = getattr(crew, 'id', None) or f"crew-{id(crew)}"
        crew_name = getattr(crew, 'name', crew_id)
        ctx = self.create_context(crew_id)
        logger.info("Wrapping crew with governance: crew_name=%s, crew_id=%s", crew_name, crew_id)

        self._wrapped_crews[id(crew)] = crew

        original = crew
        kernel = self

        class GovernedCrewAICrew:
            """CrewAI crew wrapped with Agent OS governance."""

            def __init__(self):
                self._original = original
                self._ctx = ctx
                self._kernel = kernel
                self._crew_name = crew_name

            def kickoff(self, inputs: dict = None) -> Any:
                """Governed kickoff."""
                logger.info("Crew execution started: crew_name=%s", self._crew_name)
                allowed, reason = self._kernel.pre_execute(self._ctx, inputs)
                if not allowed:
                    logger.warning("Crew execution blocked by policy: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                # Wrap individual agents and their tools
                if hasattr(self._original, 'agents'):
                    for agent in self._original.agents:
                        self._wrap_agent(agent)

                result = self._original.kickoff(inputs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.warning("Crew post-execution validation failed: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                logger.info("Crew execution completed: crew_name=%s", self._crew_name)
                return result

            async def kickoff_async(self, inputs: dict = None) -> Any:
                """Governed async kickoff."""
                logger.info("Async crew execution started: crew_name=%s", self._crew_name)
                allowed, reason = self._kernel.pre_execute(self._ctx, inputs)
                if not allowed:
                    logger.warning("Async crew execution blocked by policy: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                # Wrap individual agents and their tools
                if hasattr(self._original, 'agents'):
                    for agent in self._original.agents:
                        self._wrap_agent(agent)

                result = await self._original.kickoff_async(inputs)

                valid, reason = self._kernel.post_execute(self._ctx, result)
                if not valid:
                    logger.warning("Async crew post-execution validation failed: crew_name=%s, reason=%s", self._crew_name, reason)
                    raise PolicyViolationError(reason)

                logger.info("Async crew execution completed: crew_name=%s", self._crew_name)
                return result

            def _wrap_tool(self, tool, agent_name: str):
                """Wrap a CrewAI tool's _run method with governance interception."""
                interceptor = PolicyInterceptor(self._kernel.policy, self._ctx)
                original_run = getattr(tool, '_run', None)
                if not original_run or getattr(tool, '_governed', False):
                    return

                tool_name = getattr(tool, 'name', type(tool).__name__)
                ctx = self._ctx
                crew_name = self._crew_name

                def governed_run(*args, **kwargs):
                    """Governed wrapper around a CrewAI tool's run method.

                    Intercepts the tool call, runs pre-execution policy checks,
                    records the invocation in the audit log, and delegates
                    to the original _run implementation.

                    Args:
                        *args: Positional arguments forwarded to the original tool.
                        **kwargs: Keyword arguments forwarded to the original tool.

                    Returns:
                        The result from the original tool's run method.

                    Raises:
                        PolicyViolationError: If the tool call violates the active policy.
                    """
                    request = ToolCallRequest(
                        tool_name=tool_name,
                        arguments=kwargs if kwargs else {"args": args},
                        agent_id=agent_name,
                    )
                    result = interceptor.intercept(request)
                    if not result.allowed:
                        logger.warning(
                            "Tool call blocked: crew=%s, agent=%s, tool=%s, reason=%s",
                            crew_name, agent_name, tool_name, result.reason,
                        )
                        raise PolicyViolationError(
                            f"Tool '{tool_name}' blocked: {result.reason}"
                        )
                    ctx.call_count += 1
                    logger.info(
                        "Tool call allowed: crew=%s, agent=%s, tool=%s",
                        crew_name, agent_name, tool_name,
                    )
                    return original_run(*args, **kwargs)

                tool._run = governed_run
                tool._governed = True

            def _wrap_agent(self, agent):
                """Add governance hooks to individual agent and its tools.

                When ``deep_hooks_enabled`` is ``True`` on the kernel, this
                also applies step-level execution interception, memory write
                validation, and delegation detection.
                """
                agent_name = getattr(agent, 'name', str(id(agent)))
                logger.debug("Wrapping individual agent: crew_name=%s, agent=%s", self._crew_name, agent_name)

                # Wrap individual tools for per-call interception
                agent_tools = getattr(agent, 'tools', None) or []
                for tool in agent_tools:
                    self._wrap_tool(tool, agent_name)

                original_execute = getattr(agent, 'execute_task', None)
                if original_execute:
                    crew_name = self._crew_name

                    def governed_execute(task, *args, **kwargs):
                        """Governed wrapper around a CrewAI agent's task execution.

                        Intercepts each task execution call, applies pre-execution
                        policy checks, and delegates to the original execute method.

                        Args:
                            task: The CrewAI Task object to execute.
                            *args: Additional positional arguments.
                            **kwargs: Additional keyword arguments.

                        Returns:
                            The task execution result from the underlying agent.

                        Raises:
                            PolicyViolationError: If the execution violates the active policy.
                        """
                        task_id = getattr(task, 'id', None) or str(id(task))
                        logger.info("Agent task execution started: crew_name=%s, task_id=%s", crew_name, task_id)
                        if self._kernel.policy.require_human_approval:
                            raise PolicyViolationError(
                                f"Task '{task_id}' requires human approval per governance policy"
                            )
                        allowed, reason = self._kernel.pre_execute(self._ctx, task)
                        if not allowed:
                            raise PolicyViolationError(f"Task blocked: {reason}")

                        result = original_execute(task, *args, **kwargs)
                        valid, drift_reason = self._kernel.post_execute(self._ctx, result)
                        if not valid:
                            logger.warning("Post-execute violation: crew_name=%s, task_id=%s, reason=%s", crew_name, task_id, drift_reason)
                        logger.info("Agent task execution completed: crew_name=%s, task_id=%s", crew_name, task_id)
                        return result
                    agent.execute_task = governed_execute

                # Deep hooks at agent level
                if self._kernel.deep_hooks_enabled:
                    self._kernel._intercept_task_steps(agent, agent_name, self._crew_name)
                    self._kernel._intercept_crew_memory(agent, self._ctx, agent_name)
                    self._kernel._detect_crew_delegation(agent, self._ctx, agent_name)

            def __getattr__(self, name):
                return getattr(self._original, name)

        return GovernedCrewAICrew()

    def unwrap(self, governed_crew: Any) -> Any:
        """Get original crew from wrapped version."""
        logger.debug("Unwrapping governed crew")
        return governed_crew._original

    # ── Deep Integration Hooks (legacy) ───────────────────────────

    def _intercept_task_steps(
        self, agent: Any, agent_name: str, crew_name: str
    ) -> None:
        """Hook into individual step execution within a task.

        If the agent exposes a ``step`` or ``_execute_step`` method, it is
        wrapped so that each intermediate step is logged and validated
        against governance policy.

        Args:
            agent: The CrewAI agent being governed.
            agent_name: Human-readable agent name for logging.
            crew_name: Human-readable crew name for logging.
        """
        for step_attr in ("step", "_execute_step"):
            original_step = getattr(agent, step_attr, None)
            if original_step is None or getattr(original_step, "_step_governed", False) is True:
                continue

            kernel = self

            @functools.wraps(original_step)
            def governed_step(*args: Any, _orig=original_step, _attr=step_attr, **kwargs: Any) -> Any:
                """Governed wrapper around a CrewAI task step.

                Intercepts individual step calls within a task, validates
                inputs against the active policy, and records each step
                in the audit trail before delegating to the original method.

                Args:
                    *args: Positional arguments forwarded to the original step.
                    **kwargs: Keyword arguments forwarded to the original step.

                Returns:
                    The result from the original step method.

                Raises:
                    PolicyViolationError: If the step input violates the active policy.
                """
                step_record = {
                    "crew": crew_name,
                    "agent": agent_name,
                    "timestamp": datetime.now().isoformat(),
                    "step_attr": _attr,
                }
                kernel._step_log.append(step_record)
                logger.debug(
                    "Step intercepted: crew=%s agent=%s step=%s",
                    crew_name, agent_name, _attr,
                )

                # Validate step input against policy
                step_input = args[0] if args else kwargs
                matched = kernel.policy.matches_pattern(str(step_input))
                if matched:
                    raise PolicyViolationError(
                        f"Step blocked: pattern '{matched[0]}' detected in step input"
                    )

                return _orig(*args, **kwargs)

            governed_step._step_governed = True
            setattr(agent, step_attr, governed_step)

    def _intercept_crew_memory(
        self, agent: Any, ctx: Any, agent_name: str
    ) -> None:
        """Intercept memory writes for a CrewAI agent's shared memory.

        CrewAI agents may have a ``memory`` or ``shared_memory`` attribute.
        This method wraps the memory's write / save methods with governance
        validation that checks for PII, secrets, and blocked patterns.

        Args:
            agent: The CrewAI agent being governed.
            ctx: Execution context for audit logging.
            agent_name: Human-readable agent name for logging.
        """
        for mem_attr in ("memory", "shared_memory", "long_term_memory"):
            memory = getattr(agent, mem_attr, None)
            if memory is None:
                continue

            for save_method_name in ("save", "save_context", "add"):
                save_fn = getattr(memory, save_method_name, None)
                if save_fn is None or getattr(save_fn, "_mem_governed", False) is True:
                    continue

                kernel = self

                @functools.wraps(save_fn)
                def governed_save(*args: Any, _orig=save_fn, _mname=save_method_name, **kwargs: Any) -> Any:
                    """Governed wrapper around CrewAI memory save operations.

                    Validates content before it is written to crew memory,
                    checking for PII patterns and policy-blocked content.
                    Records every save attempt in the memory audit log.

                    Args:
                        *args: Positional arguments forwarded to the original save.
                        **kwargs: Keyword arguments forwarded to the original save.

                    Returns:
                        The result from the original memory save method.

                    Raises:
                        PolicyViolationError: If the content contains PII or blocked patterns.
                    """
                    combined = str(args) + str(kwargs)

                    # PII / secrets check
                    for pattern in PII_PATTERNS:
                        if pattern.search(combined):
                            raise PolicyViolationError(
                                f"Memory write blocked: sensitive data detected "
                                f"(pattern: {pattern.pattern})"
                            )

                    # Blocked patterns check
                    matched = kernel.policy.matches_pattern(combined)
                    if matched:
                        raise PolicyViolationError(
                            f"Memory write blocked: pattern '{matched[0]}' detected"
                        )

                    result = _orig(*args, **kwargs)
                    kernel._memory_audit_log.append({
                        "agent": agent_name,
                        "method": _mname,
                        "content_summary": combined[:200],
                        "timestamp": datetime.now().isoformat(),
                    })
                    return result

                governed_save._mem_governed = True
                setattr(memory, save_method_name, governed_save)

    def _detect_crew_delegation(
        self, agent: Any, ctx: Any, agent_name: str
    ) -> None:
        """Detect when a CrewAI agent delegates work to another agent.

        Wraps the ``delegate_work`` or ``execute_task`` related delegation
        methods to track and govern delegation chains.

        Args:
            agent: The CrewAI agent being governed.
            ctx: Execution context for audit logging.
            agent_name: Human-readable agent name for logging.
        """
        delegate_fn = getattr(agent, "delegate_work", None)
        if delegate_fn is None or getattr(delegate_fn, "_delegation_governed", False) is True:
            return

        kernel = self
        max_depth = self.policy.max_tool_calls

        @functools.wraps(delegate_fn)
        def governed_delegate(*args: Any, **kwargs: Any) -> Any:
            """Governed wrapper around CrewAI agent delegation.

            Intercepts delegation calls between agents, tracks delegation
            depth, and enforces the maximum delegation limit defined in
            the active policy.

            Args:
                *args: Positional arguments forwarded to the original delegate.
                **kwargs: Keyword arguments forwarded to the original delegate.

            Returns:
                The result from the delegated agent.

            Raises:
                PolicyViolationError: If the delegation depth exceeds the policy limit.
            """
            depth = len(kernel._delegation_log) + 1
            if depth > max_depth:
                raise PolicyViolationError(
                    f"Max delegation depth ({max_depth}) exceeded at depth {depth}"
                )

            record = {
                "delegator": agent_name,
                "depth": depth,
                "args_summary": str(args)[:200],
                "timestamp": datetime.now().isoformat(),
            }
            kernel._delegation_log.append(record)
            logger.info(
                "Crew delegation detected: agent=%s depth=%d",
                agent_name, depth,
            )
            return delegate_fn(*args, **kwargs)

        governed_delegate._delegation_governed = True
        agent.delegate_work = governed_delegate


# ── Convenience function (deprecated) ─────────────────────────────

def wrap(crew: Any, policy: Optional[GovernancePolicy] = None) -> Any:
    """Quick wrapper for CrewAI crews.

    .. deprecated::
        Use ``CrewAIKernel(policy).as_hooks()`` instead.
    """
    import warnings
    warnings.warn(
        "crewai_adapter.wrap() is deprecated. "
        "Use CrewAIKernel(policy).as_hooks() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    logger.debug("Using convenience wrap function for crew")
    return CrewAIKernel(policy).wrap(crew)
