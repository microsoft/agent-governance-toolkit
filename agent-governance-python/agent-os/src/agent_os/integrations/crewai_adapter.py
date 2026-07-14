# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CrewAI integration backed by a required native ACS runtime.

Native execution hooks mediate LLM and tool calls before CrewAI forwards them.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from .base import (
    get_adapter_runtime,
    BaseIntegration,
    GovernanceEventType,
    PolicyViolationError,
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

    The four global hooks mediate tool and model input and output through the
    kernel's native runtime. Only one hook set should be active per process.
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

            trusted_skill_sources = kernel.trusted_sources_from_attrs(context)

            kernel.emit_skill_audit_event(
                GovernanceEventType.POLICY_CHECK,
                agent_id=agent_name,
                action="crewai.before_tool_call",
                trusted_sources=trusted_skill_sources,
                default_origin="crewai",
                context_before=tool_input,
                tool_name=tool_name,
            )

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

            trusted_skill_sources = kernel.trusted_sources_from_attrs(context)

            if tool_result and isinstance(tool_result, str):
                kernel.emit_skill_audit_event(
                    GovernanceEventType.POLICY_CHECK,
                    agent_id=ctx.agent_id,
                    action="crewai.after_tool_call",
                    trusted_sources=trusted_skill_sources,
                    default_origin="crewai",
                    context_after=tool_result,
                    tool_name=tool_name,
                )

                # AGT output intervention point evaluates the tool result
                post_result = kernel.evaluate_output(ctx, tool_result)
                if not post_result.allowed:
                    logger.info(
                        "[%s] Policy DENY (AGT output) on tool output: %s",
                        name, post_result.reason,
                    )
                    raise post_result.to_policy_violation(PolicyViolationError)
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

            # ─── 2. AGT input intervention point on combined messages ─
            combined_input = " ".join(
                str(m.get("content", m) if isinstance(m, dict) else m)
                for m in messages
            ) if messages else ""

            trusted_skill_sources = kernel.trusted_sources_from_attrs(context)

            if combined_input.strip():
                kernel.emit_skill_audit_event(
                    GovernanceEventType.POLICY_CHECK,
                    agent_id=ctx.agent_id,
                    action="crewai.before_llm_call",
                    trusted_sources=trusted_skill_sources,
                    default_origin="crewai",
                    context_before=combined_input,
                )

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

            trusted_skill_sources = kernel.trusted_sources_from_attrs(context)

            if response and isinstance(response, str) and response.strip():
                kernel.emit_skill_audit_event(
                    GovernanceEventType.POLICY_CHECK,
                    agent_id=ctx.agent_id,
                    action="crewai.after_llm_call",
                    trusted_sources=trusted_skill_sources,
                    default_origin="crewai",
                    context_after=response.strip(),
                )

                # AGT output intervention point evaluates the LLM response
                post_result = kernel.evaluate_output(ctx, response.strip())
                if not post_result.allowed:
                    logger.info(
                        "[%s] Policy DENY (AGT output) on LLM output: %s",
                        name, post_result.reason,
                    )
                    raise post_result.to_policy_violation(PolicyViolationError)
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
    """CrewAI adapter using native hooks and a required ACS runtime."""

    def __init__(self, *, runtime: Any):
        super().__init__(runtime=runtime)
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)
        logger.debug("CrewAIKernel initialized")

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(self, ctx: Any, input_data: Any) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_output(self, ctx: Any, output_data: Any) -> AdapterResult:
        """Public access to the AGT ``output`` intervention point evaluation."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

    def evaluate_pre_tool_call(
        self,
        ctx: Any,
        *,
        tool_name: str,
        args: Any,
        call_id: str = "call-1",
    ) -> AdapterResult:
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
        """Normalise a CrewAI payload to a JSON-serialisable body."""
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
