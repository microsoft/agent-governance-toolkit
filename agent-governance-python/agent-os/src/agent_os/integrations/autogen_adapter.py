# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AutoGen integration backed by a required native ACS runtime.

The intervention handler mediates messages and function calls before AutoGen
forwards them. Runtime-owned transforms and approvals are preserved.
"""

import functools
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from .base import (
    get_adapter_runtime,
    PII_PATTERNS,
    BaseIntegration,
    AdapterExecutionState,
    GovernanceEventType,
    PolicyViolationError,
)

logger = logging.getLogger("agent_os.autogen")

# ── Graceful import of AutoGen native intervention handlers ───────
# AutoGen v0.4+ provides DefaultInterventionHandler with on_send,
# on_publish, on_response hooks.  When unavailable (older AutoGen or
# not installed), we fall back to the legacy govern() approach.

try:
    from autogen_core import DropMessage
    from autogen_core import intervention as _autogen_intervention  # noqa: F401 — feature detection
    _INTERVENTION_AVAILABLE = True
except ImportError:
    _INTERVENTION_AVAILABLE = False

# Also try to import FunctionCall for type detection
try:
    from autogen_core import FunctionCall
    _FUNCTION_CALL_AVAILABLE = True
except ImportError:
    _FUNCTION_CALL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════
# GovernanceInterventionHandler — native AutoGen intervention
# ═══════════════════════════════════════════════════════════════════

class GovernanceInterventionHandler:
    """Native AutoGen intervention handler for Agent OS governance.

    It mediates direct messages, broadcasts, tool calls, and responses through
    the kernel's native runtime.
    """

    def __init__(self, kernel: "AutoGenKernel", name: str = "governance"):
        self._kernel = kernel
        self._name = name
        self._ctx = kernel.create_context(f"autogen-handler-{name}")
        logger.debug(
            "GovernanceInterventionHandler created: name=%s, "
            "intervention_available=%s",
            name,
            _INTERVENTION_AVAILABLE,
        )

    # ── on_send: intercept direct messages ────────────────────────

    async def on_send(
        self,
        message: Any,
        *,
        message_context: Any = None,
        recipient: Any = None,
    ) -> Any:
        """Intercept direct messages between agents.

        Checks for:
        1. Tool call governance (``FunctionCall`` messages) — allowlist,
           blocked-pattern scan on name and arguments.
        2. Content governance — blocked-pattern scan on message text.
        3. Cedar/OPA ``pre_execute`` gate.

        Parameters
        ----------
        message : Any
            The message being sent. Can be a ``FunctionCall``, string,
            dict, or framework message object.
        message_context : MessageContext, optional
            AutoGen message context (sender info, topic, etc.).
        recipient : AgentId, optional
            The target agent for this message.

        Returns
        -------
        Any
            The original message to allow, or ``DropMessage`` to block.
        """
        kernel = self._kernel
        ctx = self._ctx
        name = self._name

        # ─── 1. FunctionCall governance via AGT pre_tool_call ────
        if _FUNCTION_CALL_AVAILABLE and isinstance(message, FunctionCall):
            tool_name = getattr(message, "name", "unknown")
            tool_args = getattr(message, "arguments", "")

            trusted_skill_sources = kernel.trusted_sources_from_attrs(message)

            emitted = kernel.emit_skill_audit_event(
                GovernanceEventType.POLICY_CHECK,
                agent_id=ctx.agent_id,
                action="autogen.on_send.function_call",
                trusted_sources=trusted_skill_sources,
                default_origin="autogen",
                context_before=tool_args,
                tool_name=tool_name,
            )
            kernel._function_call_log.append({
                "agent_id": ctx.agent_id,
                "function_name": tool_name,
                "args_summary": str(tool_args)[:200],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "skill_name": emitted.get("skill_name"),
                "skill_origin": emitted.get("skill_origin"),
                "provenance_source_trust": emitted.get("provenance_source_trust"),
                "context_hash_before": emitted.get("context_hash_before"),
                "context_hash_after": emitted.get("context_hash_after"),
            })

            logger.debug(
                "[%s] on_send: FunctionCall tool=%s", name, tool_name,
            )

            bridge_result = kernel.evaluate_pre_tool_call(
                ctx,
                tool_name=tool_name,
                args=tool_args,
                call_id=getattr(message, "id", "call-1"),
            )
            if bridge_result.transform is not None:
                # Rewrite the FunctionCall arguments per AGT D1.1 before
                # forwarding the message to the recipient.
                replacement = bridge_result.transformed_value
                if isinstance(replacement, dict) and "arguments" in replacement:
                    try:
                        message.arguments = replacement["arguments"]
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass
                elif isinstance(replacement, str):
                    try:
                        message.arguments = replacement
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass
            if not bridge_result.allowed:
                logger.info(
                    "[%s] Policy DENY (AGT pre_tool_call): %s",
                    name,
                    bridge_result.reason,
                )
                return DropMessage

            # Increment call count. The bridge mirrors ``ctx.call_count``
            # into the snapshot builder on every access, so calling
            # ``record_post_execute(tool_calls=1)`` as well would double-count
            # the call and trip ``max_tool_calls`` one call early.
            ctx.call_count += 1

            logger.debug(
                "[%s] Tool ALLOW: tool=%s count=%d",
                name, tool_name, ctx.call_count,
            )
            return message

        # ─── 2. General message content governance via AGT input ───
        content = self._extract_content(message)
        if content:
            bridge_result = kernel.evaluate_input(ctx, content)
            if bridge_result.transform is not None and isinstance(
                bridge_result.transformed_value, str
            ):
                try:
                    self._apply_content(message, bridge_result.transformed_value)
                except Exception:  # noqa: BLE001 — best-effort rewrite
                    pass
            if not bridge_result.allowed:
                logger.info(
                    "[%s] Policy DENY (AGT input): %s",
                    name,
                    bridge_result.reason,
                )
                return DropMessage

            # PII check on outbound messages (retained as a defensive
            # secondary guard; the AGT manifest can override via the
            # input intervention point binding).
            for pii_pattern in PII_PATTERNS:
                if pii_pattern.search(content):
                    logger.info(
                        "[%s] Policy DENY: PII detected in message "
                        "(pattern: %s)",
                        name, pii_pattern.pattern,
                    )
                    return DropMessage

        return message

    # ── on_publish: intercept broadcast messages ──────────────────

    async def on_publish(
        self,
        message: Any,
        *,
        message_context: Any = None,
    ) -> Any:
        """Intercept broadcast/published messages.

        Scans published messages for blocked patterns and PII before
        they reach subscribers.

        Parameters
        ----------
        message : Any
            The message being published.
        message_context : MessageContext, optional
            AutoGen message context.

        Returns
        -------
        Any
            The original message to allow, or ``DropMessage`` to block.
        """
        name = self._name
        kernel = self._kernel

        content = self._extract_content(message)
        if content:
            result = kernel.evaluate_input(self._ctx, content)
            if result.transform is not None and isinstance(result.transformed_value, str):
                self._apply_content(message, result.transformed_value)
                content = result.transformed_value
            if not result.allowed:
                logger.info("[%s] Policy DENY (publish): %s", name, result.reason)
                return DropMessage
            for pii_pattern in PII_PATTERNS:
                if pii_pattern.search(content):
                    logger.info("[%s] Policy DENY (publish): PII detected", name)
                    return DropMessage

        return message

    # ── on_response: intercept agent responses ────────────────────

    async def on_response(
        self,
        message: Any,
        *,
        message_context: Any = None,
        sender: Any = None,
    ) -> Any:
        """Intercept agent responses for output governance.

        Scans responses for blocked patterns and runs ``post_execute``
        drift detection.

        Parameters
        ----------
        message : Any
            The response message.
        message_context : MessageContext, optional
            AutoGen message context.
        sender : AgentId, optional
            The agent that generated this response.

        Returns
        -------
        Any
            The original message to allow, or ``DropMessage`` to block.
        """
        kernel = self._kernel
        ctx = self._ctx
        name = self._name

        content = self._extract_content(message)
        if content:
            # Drift detection / checkpointing via base post_execute
            valid, reason = kernel.post_execute(ctx, content)
            if not valid:
                logger.info(
                    "[%s] Policy DENY (post_execute) on response: %s",
                    name, reason,
                )
                return DropMessage

        return message

    # ── Helper methods ────────────────────────────────────────────

    @staticmethod
    def _extract_content(message: Any) -> str:
        """Extract text content from various message types.

        Parameters
        ----------
        message : Any
            A message that may be a string, dict, or object with a
            ``content`` attribute.

        Returns
        -------
        str
            The extracted text content, or empty string if none found.
        """
        if isinstance(message, str):
            return message
        if isinstance(message, dict):
            return str(message.get("content", ""))
        content = getattr(message, "content", None)
        if content is not None:
            return str(content)
        return ""

    @staticmethod
    def _apply_content(message: Any, new_content: str) -> None:
        """Rewrite a message's content in place per AGT D1.1 transform.

        Mirrors :meth:`_extract_content`. Strings are immutable so the
        AutoGen runtime keeps the original reference; for dicts and
        objects with a ``content`` attribute the new value is written
        through. Best-effort: opaque message types fall through
        silently.
        """
        if isinstance(message, dict):
            message["content"] = new_content
            return
        if hasattr(message, "content"):
            try:
                message.content = new_content
            except Exception:  # noqa: BLE001 — best-effort rewrite
                pass

    # ── Convenience properties ────────────────────────────────────

    @property
    def kernel(self) -> "AutoGenKernel":
        """Return the governing kernel."""
        return self._kernel

    @property
    def context(self):
        """Return the execution context."""
        return self._ctx

    def __repr__(self) -> str:
        return (
            f"GovernanceInterventionHandler(name={self._name!r})"
        )


# ═══════════════════════════════════════════════════════════════════
# AutoGenKernel — main adapter
# ═══════════════════════════════════════════════════════════════════

class AutoGenKernel(BaseIntegration):
    """AutoGen adapter using native intervention handlers and ACS."""

    def __init__(
        self,
        timeout_seconds: float = 300.0,
        on_error: Optional[Callable[[Exception, str], Any]] = None,
        deep_hooks_enabled: bool = True,
        *,
        runtime: Any,
    ):
        """Initialise host controls and the required native runtime."""
        super().__init__(runtime=runtime)
        self.timeout_seconds = timeout_seconds
        self.on_error = on_error
        self.deep_hooks_enabled = deep_hooks_enabled
        self._governed_agents: dict[str, Any] = {}
        self._original_methods: dict[str, dict[str, Any]] = {}
        self._stopped: dict[str, bool] = {}
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._function_call_log: list[dict[str, Any]] = []
        self._groupchat_message_log: list[dict[str, Any]] = []
        self._state_change_log: list[dict[str, Any]] = []
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(self, ctx: Any, input_data: Any) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_pre_tool_call(
        self,
        ctx: Any,
        *,
        tool_name: str,
        args: Any,
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for an AutoGen FunctionCall."""
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
        """Normalise an AutoGen payload to a JSON-serialisable body."""
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            return str(data)
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        return str(data)

    # ── Native intervention handler (recommended) ─────────────────

    def as_handler(
        self, name: str = "governance"
    ) -> "GovernanceInterventionHandler":
        """Create a native AutoGen intervention handler.

        This is the **recommended** integration path.  The returned
        handler intercepts all message traffic in the runtime:

        * ``on_send``    — tool call governance, content filtering
        * ``on_publish`` — broadcast message governance
        * ``on_response``— output content filtering, drift detection

        Parameters
        ----------
        name : str
            Human-readable name for logging.

        Returns
        -------
        GovernanceInterventionHandler
            The handler instance, ready to be passed to
            ``SingleThreadedAgentRuntime(intervention_handlers=[...])``.

        Raises
        ------
        RuntimeError
            If ``autogen_core`` is not installed.

        Examples
        --------
        >>> handler = kernel.as_handler("prod-governance")
        >>> runtime = SingleThreadedAgentRuntime(
        ...     intervention_handlers=[handler],
        ... )
        """
        if not _INTERVENTION_AVAILABLE:
            raise RuntimeError(
                "autogen_core is not available. "
                "Upgrade to AutoGen 0.4+ or use the legacy govern() method."
            )
        return GovernanceInterventionHandler(self, name=name)

    # ── Legacy monkey-patching (deprecated) ───────────────────────

    def wrap(self, agent: Any) -> Any:
        """Wrap a single AutoGen agent with governance.

        .. deprecated::
            Use :meth:`as_handler` instead.

        Convenience method that delegates to :meth:`govern` for a single
        agent.

        Args:
            agent: An AutoGen agent (``AssistantAgent``, ``UserProxyAgent``,
                etc.).

        Returns:
            The same agent object with its key methods monkey-patched for
            governance.
        """
        import warnings
        warnings.warn(
            "AutoGenKernel.wrap() is deprecated. Use kernel.as_handler() "
            "instead, which leverages AutoGen's native InterventionHandler. "
            "wrap() will be removed in v1.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.govern(agent)[0]

    def govern(self, *agents: Any) -> list[Any]:
        """Add governance to one or more AutoGen agents.

        .. deprecated::
            Use :meth:`as_handler` instead.  The monkey-patch approach
            mutates agent methods in-place.  ``govern()`` will be
            removed in v1.0.

        Monkey-patches ``initiate_chat``, ``generate_reply``, and
        ``receive`` on each agent so that every message exchange is
        validated against the active policy.

        The original methods are stored internally so they can be restored
        later via :meth:`unwrap`.

        Args:
            *agents: AutoGen agents to govern.

        Returns:
            The same agent objects (in-place patched) as a list.

        """
        import warnings
        warnings.warn(
            "AutoGenKernel.govern() is deprecated. Use kernel.as_handler() "
            "instead, which leverages AutoGen's native InterventionHandler. "
            "govern() will be removed in v1.0.",
            DeprecationWarning,
            stacklevel=2,
        )

        governed = []

        for agent in agents:
            agent_id = getattr(agent, 'name', f"autogen-{id(agent)}")
            ctx = self.create_context(agent_id)

            # Store reference
            self._governed_agents[agent_id] = agent
            self._stopped[agent_id] = False

            # Store original methods before wrapping
            self._original_methods[agent_id] = {}
            for method_name in ('initiate_chat', 'generate_reply', 'receive'):
                if hasattr(agent, method_name):
                    self._original_methods[agent_id][method_name] = getattr(agent, method_name)

            # Wrap key methods
            self._wrap_initiate_chat(agent, ctx, agent_id)
            self._wrap_generate_reply(agent, ctx, agent_id)
            self._wrap_receive(agent, ctx, agent_id)

            # Apply deep hooks
            if self.deep_hooks_enabled:
                try:
                    self._intercept_function_calls(agent, ctx, agent_id)
                except Exception as exc:
                    logger.warning("Function call interception failed for %s: %s", agent_id, exc)
                try:
                    self._intercept_groupchat(agent, ctx, agent_id)
                except Exception as exc:
                    logger.warning("GroupChat interception failed for %s: %s", agent_id, exc)
                try:
                    self._intercept_state_changes(agent, ctx, agent_id)
                except Exception as exc:
                    logger.warning("State change interception failed for %s: %s", agent_id, exc)

            governed.append(agent)

        return governed

    def _wrap_initiate_chat(self, agent: Any, ctx: AdapterExecutionState, agent_id: str):
        """Wrap ``initiate_chat`` with pre-/post-execution governance.

        Args:
            agent: The AutoGen agent to patch.
            ctx: Execution context for this agent.
            agent_id: Unique identifier for audit logging.
        """
        if not hasattr(agent, 'initiate_chat'):
            return

        original = agent.initiate_chat
        kernel = self

        def governed_initiate_chat(recipient, message=None, **kwargs):
            if kernel._stopped.get(agent_id):
                raise PolicyViolationError(f"Agent '{agent_id}' is stopped (SIGSTOP)")

            try:
                allowed, reason = kernel.pre_execute(ctx, {"recipient": str(recipient), "message": message})
                if not allowed:
                    logger.info("Policy DENY on initiate_chat for %s: %s", agent_id, reason)
                    raise PolicyViolationError(reason)
            except PolicyViolationError:
                raise
            except Exception as exc:
                logger.error("Governance check failed for %s: %s", agent_id, exc)
                kernel._last_error = str(exc)
                if kernel.on_error:
                    kernel.on_error(exc, agent_id)
                    return None
                raise

            try:
                result = original(recipient, message=message, **kwargs)
            except Exception as exc:
                logger.error("initiate_chat failed for %s: %s", agent_id, exc)
                kernel._last_error = str(exc)
                if kernel.on_error:
                    kernel.on_error(exc, agent_id)
                    return None
                raise

            kernel.post_execute(ctx, result)
            return result

        agent.initiate_chat = governed_initiate_chat

    def _wrap_generate_reply(self, agent: Any, ctx: AdapterExecutionState, agent_id: str):
        """Wrap ``generate_reply`` with message interception and governance.

        Unlike ``initiate_chat``, violations in ``generate_reply`` return a
        ``[BLOCKED: ...]`` string rather than raising an exception, so that
        multi-agent conversations can continue with the violation visible
        in the message stream.

        Args:
            agent: The AutoGen agent to patch.
            ctx: Execution context for this agent.
            agent_id: Unique identifier for audit logging.
        """
        if not hasattr(agent, 'generate_reply'):
            return

        original = agent.generate_reply
        kernel = self

        def governed_generate_reply(messages=None, sender=None, **kwargs):
            if kernel._stopped.get(agent_id):
                return f"[BLOCKED: Agent '{agent_id}' is stopped (SIGSTOP)]"

            try:
                allowed, reason = kernel.pre_execute(ctx, {"messages": messages, "sender": str(sender)})
                if not allowed:
                    logger.info("Policy DENY on generate_reply for %s: %s", agent_id, reason)
                    return f"[BLOCKED: {reason}]"
            except Exception as exc:
                logger.error("Governance check failed for %s: %s", agent_id, exc)
                kernel._last_error = str(exc)
                if kernel.on_error:
                    kernel.on_error(exc, agent_id)
                return "[ERROR: governance check failed]"

            try:
                result = original(messages=messages, sender=sender, **kwargs)
            except Exception as exc:
                logger.error("generate_reply failed for %s: %s", agent_id, exc)
                kernel._last_error = str(exc)
                if kernel.on_error:
                    kernel.on_error(exc, agent_id)
                return f"[ERROR: {exc}]"

            valid, reason = kernel.post_execute(ctx, result)
            if not valid:
                return f"[BLOCKED: {reason}]"

            return result

        agent.generate_reply = governed_generate_reply

    def _wrap_receive(self, agent: Any, ctx: AdapterExecutionState, agent_id: str):
        """Wrap ``receive`` with inbound message governance.

        Intercepts messages arriving at this agent and validates them
        against the active policy before forwarding to the original
        ``receive`` implementation.

        Args:
            agent: The AutoGen agent to patch.
            ctx: Execution context for this agent.
            agent_id: Unique identifier for audit logging.
        """
        if not hasattr(agent, 'receive'):
            return

        original = agent.receive
        kernel = self

        def governed_receive(message, sender, **kwargs):
            if kernel._stopped.get(agent_id):
                raise PolicyViolationError(f"Agent '{agent_id}' is stopped (SIGSTOP)")

            try:
                allowed, reason = kernel.pre_execute(ctx, {"message": message, "sender": str(sender)})
                if not allowed:
                    logger.info("Policy DENY on receive for %s: %s", agent_id, reason)
                    raise PolicyViolationError(reason)
            except PolicyViolationError:
                raise
            except Exception as exc:
                logger.error("Governance check failed on receive for %s: %s", agent_id, exc)
                kernel._last_error = str(exc)
                if kernel.on_error:
                    kernel.on_error(exc, agent_id)
                    return None
                raise

            try:
                result = original(message, sender, **kwargs)
            except Exception as exc:
                logger.error("receive failed for %s: %s", agent_id, exc)
                kernel._last_error = str(exc)
                if kernel.on_error:
                    kernel.on_error(exc, agent_id)
                    return None
                raise

            kernel.post_execute(ctx, result)
            return result

        agent.receive = governed_receive

    # ── Deep Integration Hooks (legacy) ───────────────────────────

    def _intercept_function_calls(
        self, agent: Any, ctx: AdapterExecutionState, agent_id: str
    ) -> None:
        """Wrap the function_map on an AutoGen AssistantAgent.

        AutoGen agents store callable functions in a ``function_map`` dict.
        This method wraps each function so that every invocation is
        validated against the governance policy before execution.

        Blocked functions are prevented from running and a
        ``PolicyViolationError`` is raised.

        Args:
            agent: The AutoGen agent to instrument.
            ctx: Execution context for governance checks.
            agent_id: Unique identifier for audit logging.
        """
        function_map = getattr(agent, "function_map", None)
        if not function_map or not isinstance(function_map, dict):
            return

        kernel = self

        for func_name, func in list(function_map.items()):
            if getattr(func, "_fn_governed", False) is True:
                continue

            @functools.wraps(func)
            def governed_function(
                *args: Any,
                _orig=func,
                _name=func_name,
                **kwargs: Any,
            ) -> Any:
                """Governed wrapper around an AutoGen function_map entry."""
                result = kernel.evaluate_pre_tool_call(
                    ctx, tool_name=_name, args={"args": args, "kwargs": kwargs}
                )
                if not result.allowed:
                    raise result.to_policy_violation(PolicyViolationError)

                # Record the call
                record = {
                    "agent_id": agent_id,
                    "function_name": _name,
                    "args_summary": str(args)[:200],
                    "timestamp": datetime.now().isoformat(),
                }
                kernel._function_call_log.append(record)
                logger.info("Function call governed: agent=%s function=%s", agent_id, _name)

                return _orig(*args, **kwargs)

            governed_function._fn_governed = True
            function_map[func_name] = governed_function

    def _intercept_groupchat(
        self, agent: Any, ctx: AdapterExecutionState, agent_id: str
    ) -> None:
        """Hook into GroupChat's select_speaker and message routing.

        If the agent is a GroupChat manager (has a ``groupchat`` attribute),
        this method wraps ``select_speaker`` and ``_process_message`` to
        validate each speaker selection and track conversation patterns.

        Args:
            agent: The AutoGen agent (potentially a GroupChatManager).
            ctx: Execution context for governance checks.
            agent_id: Unique identifier for audit logging.
        """
        groupchat = getattr(agent, "groupchat", None)
        if groupchat is None:
            return

        kernel = self

        # Wrap select_speaker
        original_select = getattr(groupchat, "select_speaker", None)
        if original_select and getattr(original_select, "_gc_governed", False) is not True:

            @functools.wraps(original_select)
            def governed_select_speaker(*args: Any, **kwargs: Any) -> Any:
                result = original_select(*args, **kwargs)
                speaker_name = getattr(result, "name", str(result))

                record = {
                    "groupchat_manager": agent_id,
                    "selected_speaker": speaker_name,
                    "timestamp": datetime.now().isoformat(),
                }
                kernel._groupchat_message_log.append(record)

                evaluation = kernel.evaluate_input(ctx, speaker_name)
                if not evaluation.allowed:
                    raise evaluation.to_policy_violation(PolicyViolationError)

                logger.debug(
                    "GroupChat speaker selected: manager=%s speaker=%s",
                    agent_id, speaker_name,
                )
                return result

            governed_select_speaker._gc_governed = True
            groupchat.select_speaker = governed_select_speaker

        # Wrap message sending/routing if available
        for route_attr in ("send", "_broadcast"):
            original_route = getattr(groupchat, route_attr, None)
            if original_route and getattr(original_route, "_gc_governed", False) is not True:

                @functools.wraps(original_route)
                def governed_route(
                    *args: Any, _orig=original_route, _attr=route_attr, **kwargs: Any
                ) -> Any:
                    message_str = str(args[0]) if args else str(kwargs)
                    evaluation = kernel.evaluate_input(ctx, message_str)
                    if not evaluation.allowed:
                        raise evaluation.to_policy_violation(PolicyViolationError)

                    kernel._groupchat_message_log.append({
                        "groupchat_manager": agent_id,
                        "route_method": _attr,
                        "message_summary": message_str[:200],
                        "timestamp": datetime.now().isoformat(),
                    })
                    return _orig(*args, **kwargs)

                governed_route._gc_governed = True
                setattr(groupchat, route_attr, governed_route)

    def _intercept_state_changes(
        self, agent: Any, ctx: AdapterExecutionState, agent_id: str
    ) -> None:
        """Track agent state changes for governance audit.

        Wraps ``update_system_message`` and ``reset`` (if present) to
        monitor and validate state mutations.  State changes that contain
        PII or blocked patterns are rejected.

        Args:
            agent: The AutoGen agent to instrument.
            ctx: Execution context for governance checks.
            agent_id: Unique identifier for audit logging.
        """
        kernel = self

        # Wrap update_system_message
        original_update = getattr(agent, "update_system_message", None)
        if original_update and getattr(original_update, "_state_governed", False) is not True:

            @functools.wraps(original_update)
            def governed_update(*args: Any, **kwargs: Any) -> Any:
                content = str(args[0]) if args else str(kwargs)

                # PII check
                for pattern in PII_PATTERNS:
                    if pattern.search(content):
                        raise PolicyViolationError(
                            f"State update blocked for '{agent_id}': "
                            f"sensitive data detected (pattern: {pattern.pattern})"
                        )

                evaluation = kernel.evaluate_input(ctx, content)
                if not evaluation.allowed:
                    raise evaluation.to_policy_violation(PolicyViolationError)

                kernel._state_change_log.append({
                    "agent_id": agent_id,
                    "action": "update_system_message",
                    "content_summary": content[:200],
                    "timestamp": datetime.now().isoformat(),
                })
                return original_update(*args, **kwargs)

            governed_update._state_governed = True
            agent.update_system_message = governed_update

        # Wrap reset
        original_reset = getattr(agent, "reset", None)
        if original_reset and getattr(original_reset, "_state_governed", False) is not True:

            @functools.wraps(original_reset)
            def governed_reset(*args: Any, **kwargs: Any) -> Any:
                kernel._state_change_log.append({
                    "agent_id": agent_id,
                    "action": "reset",
                    "timestamp": datetime.now().isoformat(),
                })
                logger.info("Agent state reset: agent=%s", agent_id)
                return original_reset(*args, **kwargs)

            governed_reset._state_governed = True
            agent.reset = governed_reset

    def unwrap(self, governed_agent: Any) -> Any:
        """Restore original methods on a governed AutoGen agent.

        Removes all monkey-patches applied by :meth:`govern` and clears
        the agent from internal tracking.

        Args:
            governed_agent: A previously governed AutoGen agent.

        Returns:
            The agent with its original, un-governed methods restored.
        """
        agent_id = getattr(governed_agent, 'name', f"autogen-{id(governed_agent)}")
        originals = self._original_methods.get(agent_id, {})

        for method_name, original_method in originals.items():
            setattr(governed_agent, method_name, original_method)

        self._governed_agents.pop(agent_id, None)
        self._original_methods.pop(agent_id, None)
        self._stopped.pop(agent_id, None)

        return governed_agent

    def signal(self, agent_id: str, signal: str):
        """Send a POSIX-style signal to a governed agent.

        Supported signals:

        * ``SIGSTOP`` — pause the agent; all intercepted methods will
          raise ``PolicyViolationError`` or return a blocked message.
        * ``SIGCONT`` — resume a previously stopped agent.
        * ``SIGKILL`` — permanently remove governance (calls
          :meth:`unwrap`).

        Args:
            agent_id: Identifier of the target agent.
            signal: One of ``"SIGSTOP"``, ``"SIGCONT"``, or ``"SIGKILL"``.
        """
        if signal == "SIGSTOP":
            self._stopped[agent_id] = True
        elif signal == "SIGCONT":
            self._stopped[agent_id] = False
        elif signal == "SIGKILL":
            if agent_id in self._governed_agents:
                agent = self._governed_agents[agent_id]
                self.unwrap(agent)

        super().signal(agent_id, signal)

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime = time.monotonic() - self._start_time
        status = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "autogen",
            "backend_connected": bool(self._governed_agents),
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }
