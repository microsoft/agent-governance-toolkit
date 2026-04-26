# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AutoGen Integration

Wraps Microsoft AutoGen agents with Agent OS governance.

Usage:
    from agent_os.integrations import AutoGenKernel

    kernel = AutoGenKernel()
    kernel.govern(agent1, agent2, agent3)

    # Now all conversations are governed
    agent1.initiate_chat(agent2, message="...")
"""

import functools
import logging
import re
import time
from datetime import datetime
from typing import Any, Callable, Optional

from .base import BaseIntegration, ExecutionContext, GovernancePolicy, PolicyViolationError

logger = logging.getLogger("agent_os.autogen")

# Patterns used to detect potential PII / secrets in state changes
_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),           # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE),
]


class AutoGenKernel(BaseIntegration):
    """
    AutoGen adapter for Agent OS.

    Supports:
    - AssistantAgent
    - UserProxyAgent
    - GroupChat
    - Conversation flows
    - Deep hooks: function call pipeline interception, GroupChat message
      routing, and agent state tracking (when ``deep_hooks_enabled`` is True).
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        timeout_seconds: float = 300.0,
        on_error: Optional[Callable[[Exception, str], Any]] = None,
        deep_hooks_enabled: bool = True,
    ):
        """Initialise the AutoGen governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used.
            timeout_seconds: Default timeout in seconds (default 300).
            on_error: Optional callback invoked on errors with ``(exception,
                agent_id)`` arguments.  When ``None``, errors propagate
                normally.
            deep_hooks_enabled: When ``True`` (default), apply deep
                integration hooks — function call pipeline interception,
                GroupChat message routing, and state change tracking.
        """
        super().__init__(policy)
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

    def wrap(self, agent: Any) -> Any:
        """Wrap a single AutoGen agent with governance.

        Convenience method that delegates to :meth:`govern` for a single
        agent.

        Args:
            agent: An AutoGen agent (``AssistantAgent``, ``UserProxyAgent``,
                etc.).

        Returns:
            The same agent object with its key methods monkey-patched for
            governance.
        """
        return self.govern(agent)[0]

    def govern(self, *agents: Any) -> list[Any]:
        """Add governance to one or more AutoGen agents.

        Monkey-patches ``initiate_chat``, ``generate_reply``, and
        ``receive`` on each agent so that every message exchange is
        validated against the active policy.

        The original methods are stored internally so they can be restored
        later via :meth:`unwrap`.

        Args:
            *agents: AutoGen agents to govern.

        Returns:
            The same agent objects (in-place patched) as a list.

        Example:
            >>> kernel = AutoGenKernel(policy=GovernancePolicy(
            ...     blocked_patterns=["password"]
            ... ))
            >>> kernel.govern(assistant, user_proxy)
            >>> assistant.initiate_chat(user_proxy, message="hello")
        """
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

    def _wrap_initiate_chat(self, agent: Any, ctx: ExecutionContext, agent_id: str):
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

    def _wrap_generate_reply(self, agent: Any, ctx: ExecutionContext, agent_id: str):
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

    def _wrap_receive(self, agent: Any, ctx: ExecutionContext, agent_id: str):
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

    # ── Deep Integration Hooks ────────────────────────────────────

    def _intercept_function_calls(
        self, agent: Any, ctx: ExecutionContext, agent_id: str
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
                # Check allowed tools
                if kernel.policy.allowed_tools and _name not in kernel.policy.allowed_tools:
                    raise PolicyViolationError(
                        f"Function '{_name}' not in allowed list: {kernel.policy.allowed_tools}"
                    )

                # Check blocked patterns on function name + arguments
                combined = _name + str(args) + str(kwargs)
                matched = kernel.policy.matches_pattern(combined)
                if matched:
                    raise PolicyViolationError(
                        f"Function '{_name}' blocked: pattern '{matched[0]}' detected"
                    )

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
        self, agent: Any, ctx: ExecutionContext, agent_id: str
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

                # Validate speaker selection against blocked patterns
                matched = kernel.policy.matches_pattern(speaker_name)
                if matched:
                    raise PolicyViolationError(
                        f"Speaker '{speaker_name}' blocked: "
                        f"pattern '{matched[0]}' detected"
                    )

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
                    matched = kernel.policy.matches_pattern(message_str)
                    if matched:
                        raise PolicyViolationError(
                            f"GroupChat message blocked: pattern '{matched[0]}' detected"
                        )

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
        self, agent: Any, ctx: ExecutionContext, agent_id: str
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
                for pattern in _PII_PATTERNS:
                    if pattern.search(content):
                        raise PolicyViolationError(
                            f"State update blocked for '{agent_id}': "
                            f"sensitive data detected (pattern: {pattern.pattern})"
                        )

                # Blocked patterns check
                matched = kernel.policy.matches_pattern(content)
                if matched:
                    raise PolicyViolationError(
                        f"State update blocked for '{agent_id}': "
                        f"pattern '{matched[0]}' detected"
                    )

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


# Convenience function
def govern(
    *agents: Any,
    policy: Optional[GovernancePolicy] = None,
    timeout_seconds: float = 300.0,
    on_error: Optional[Callable[[Exception, str], Any]] = None,
) -> list[Any]:
    """Convenience function to add governance to AutoGen agents.

    Args:
        *agents: AutoGen agents to govern.
        policy: Optional governance policy (uses defaults when ``None``).
        timeout_seconds: Default timeout in seconds (default 300).
        on_error: Optional error callback ``(exception, agent_id)``.

    Returns:
        The governed agents as a list.

    Example:
        >>> from agent_os.integrations.autogen_adapter import govern
        >>> governed_agents = govern(assistant, user_proxy)
    """
    return AutoGenKernel(
        policy, timeout_seconds=timeout_seconds, on_error=on_error
    ).govern(*agents)
