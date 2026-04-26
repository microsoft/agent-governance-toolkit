# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mistral AI Integration

Wraps Mistral's Chat API with Agent OS governance.

Usage:
    from agent_os.integrations.mistral_adapter import MistralKernel

    kernel = MistralKernel(policy=GovernancePolicy(
        max_tokens=4096,
        allowed_tools=["web_search"],
        blocked_patterns=["password"],
    ))

    governed = kernel.wrap(client)
    response = governed.chat(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": "Hello"}],
    )

Features:
- Pre-execution policy checks on message content
- Tool call interception and validation
- Token limit enforcement
- Content filtering via blocked patterns
- Audit logging for all calls
- Health check endpoint
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .base import BaseIntegration, ExecutionContext, GovernancePolicy

logger = logging.getLogger("agent_os.mistral")

try:
    import mistralai  # noqa: F401

    _HAS_MISTRAL = True
except ImportError:
    _HAS_MISTRAL = False


def _check_mistral_available() -> None:
    """Raise a helpful error when the ``mistralai`` package is missing."""
    if not _HAS_MISTRAL:
        raise ImportError(
            "The 'mistralai' package is required for MistralKernel. "
            "Install it with: pip install mistralai"
        )


@dataclass
class MistralContext(ExecutionContext):
    """Execution context for Mistral AI interactions.

    Attributes:
        model: The model used for this session.
        chat_ids: Recorded chat completion response IDs.
        function_calls: History of function/tool calls returned by Mistral.
        prompt_tokens: Cumulative prompt tokens consumed.
        completion_tokens: Cumulative completion tokens consumed.
    """

    model: str = ""
    chat_ids: list[str] = field(default_factory=list)
    function_calls: list[dict[str, Any]] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0


class PolicyViolationError(Exception):
    """Raised when a Mistral request violates governance policy."""

    pass


class MistralKernel(BaseIntegration):
    """Mistral AI adapter for Agent OS.

    Provides governance for the Mistral Chat API including policy
    enforcement, tool-call validation, token tracking, and audit logging.

    Example:
        >>> kernel = MistralKernel(policy=GovernancePolicy(max_tokens=8192))
        >>> governed = kernel.wrap(MistralClient())
        >>> response = governed.chat(
        ...     model="mistral-large-latest",
        ...     messages=[{"role": "user", "content": "Hello"}],
        ... )
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
    ) -> None:
        """Initialise the Mistral governance kernel.

        Args:
            policy: Governance policy to enforce. Uses default when ``None``.
        """
        super().__init__(policy)
        self._wrapped_clients: dict[int, Any] = {}
        self._start_time = time.monotonic()
        self._last_error: str | None = None

    def wrap(self, client: Any) -> GovernedMistralClient:
        """Wrap a Mistral client with governance.

        Args:
            client: A ``MistralClient`` or ``Mistral`` client instance.

        Returns:
            A ``GovernedMistralClient`` that enforces policy on all
            ``chat()`` calls.
        """
        _check_mistral_available()
        client_id = id(client)
        ctx = MistralContext(
            agent_id=f"mistral-{client_id}",
            session_id=f"mis-{int(time.time())}",
            policy=self.policy,
        )
        self.contexts[ctx.agent_id] = ctx
        self._wrapped_clients[client_id] = client

        return GovernedMistralClient(
            client=client,
            kernel=self,
            ctx=ctx,
        )

    def unwrap(self, governed_agent: Any) -> Any:
        """Retrieve the original unwrapped Mistral client.

        Args:
            governed_agent: A ``GovernedMistralClient`` or any object.

        Returns:
            The original Mistral client if applicable, otherwise
            *governed_agent* as-is.
        """
        if isinstance(governed_agent, GovernedMistralClient):
            return governed_agent._client
        return governed_agent

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime = time.monotonic() - self._start_time
        has_clients = bool(self._wrapped_clients)
        status = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "mistral",
            "backend_connected": has_clients,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


class GovernedMistralClient:
    """Mistral client wrapped with Agent OS governance.

    Intercepts ``chat()`` calls for policy enforcement while proxying
    all other attributes to the underlying client.
    """

    def __init__(
        self,
        client: Any,
        kernel: MistralKernel,
        ctx: MistralContext,
    ) -> None:
        self._client = client
        self._kernel = kernel
        self._ctx = ctx

    def chat(self, **kwargs: Any) -> Any:
        """Execute a governed chat completion.

        Validates message content against blocked patterns, enforces
        tool-call allowlists, checks token limits after completion,
        and records an audit trail.

        Args:
            **kwargs: Forwarded to ``client.chat()`` (includes ``model``,
                ``messages``, ``tools``, etc.).

        Returns:
            The Mistral chat completion response.

        Raises:
            PolicyViolationError: If a governance policy is violated.
        """
        # --- pre-execution checks ---
        messages = kwargs.get("messages", [])
        for msg in messages:
            content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
            allowed, reason = self._kernel.pre_execute(self._ctx, content)
            if not allowed:
                raise PolicyViolationError(f"Message blocked: {reason}")

        # Validate tools against policy
        tools = kwargs.get("tools")
        if tools:
            self._validate_tools(tools)

        # Enforce max_tokens cap from policy
        requested_max = kwargs.get("max_tokens", 0)
        if requested_max and requested_max > self._kernel.policy.max_tokens:
            raise PolicyViolationError(
                f"Requested max_tokens ({requested_max}) exceeds policy limit "
                f"({self._kernel.policy.max_tokens})"
            )

        # Audit log
        logger.info(
            "Mistral chat | agent=%s model=%s",
            self._ctx.agent_id,
            kwargs.get("model", "unknown"),
        )

        # --- execute ---
        try:
            response = self._client.chat(**kwargs)
        except Exception as exc:
            self._kernel._last_error = str(exc)
            raise

        # --- post-execution checks ---
        response_id = getattr(response, "id", f"chatcmpl-{int(time.time())}")
        self._ctx.chat_ids.append(response_id)

        # Track tokens
        usage = getattr(response, "usage", None)
        if usage:
            self._ctx.prompt_tokens += getattr(usage, "prompt_tokens", 0)
            self._ctx.completion_tokens += getattr(usage, "completion_tokens", 0)

            total = self._ctx.prompt_tokens + self._ctx.completion_tokens
            if total > self._kernel.policy.max_tokens:
                raise PolicyViolationError(
                    f"Token limit exceeded: {total} > "
                    f"{self._kernel.policy.max_tokens}"
                )

        # Check for tool calls in response choices
        choices = getattr(response, "choices", [])
        for choice in choices:
            message = getattr(choice, "message", None)
            if message is None:
                continue
            tool_calls = getattr(message, "tool_calls", None)
            if not tool_calls:
                continue
            for tc in tool_calls:
                fn = getattr(tc, "function", None)
                fn_name = getattr(fn, "name", "") if fn else ""
                call_info = {
                    "id": getattr(tc, "id", ""),
                    "name": fn_name,
                    "arguments": getattr(fn, "arguments", "") if fn else "",
                    "timestamp": datetime.now().isoformat(),
                }
                self._ctx.function_calls.append(call_info)
                self._ctx.tool_calls.append(call_info)

                if len(self._ctx.tool_calls) > self._kernel.policy.max_tool_calls:
                    raise PolicyViolationError(
                        f"Tool call limit exceeded: "
                        f"{len(self._ctx.tool_calls)} > "
                        f"{self._kernel.policy.max_tool_calls}"
                    )

                if self._kernel.policy.allowed_tools:
                    if fn_name not in self._kernel.policy.allowed_tools:
                        raise PolicyViolationError(
                            f"Tool not allowed: {fn_name}"
                        )

        # Post-execute bookkeeping
        self._kernel.post_execute(self._ctx, response)

        return response

    def get_context(self) -> MistralContext:
        """Return the execution context with the full audit trail.

        Returns:
            The ``MistralContext`` for this governed client.
        """
        return self._ctx

    def get_token_usage(self) -> dict[str, Any]:
        """Return cumulative token usage statistics.

        Returns:
            A dict with ``prompt_tokens``, ``completion_tokens``,
            ``total_tokens``, and ``limit``.
        """
        return {
            "prompt_tokens": self._ctx.prompt_tokens,
            "completion_tokens": self._ctx.completion_tokens,
            "total_tokens": self._ctx.prompt_tokens + self._ctx.completion_tokens,
            "limit": self._kernel.policy.max_tokens,
        }

    def _validate_tools(self, tools: list[Any]) -> None:
        """Validate tool definitions against policy allowlist.

        Args:
            tools: List of tool definitions from the request.

        Raises:
            PolicyViolationError: If a tool is not in the allowed list.
        """
        if not self._kernel.policy.allowed_tools:
            return
        for tool in tools:
            if isinstance(tool, dict):
                fn = tool.get("function", {})
                name = fn.get("name", "") if isinstance(fn, dict) else ""
            else:
                fn = getattr(tool, "function", None)
                name = getattr(fn, "name", "") if fn else ""
            if name and name not in self._kernel.policy.allowed_tools:
                raise PolicyViolationError(f"Tool not allowed: {name}")

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying Mistral client."""
        return getattr(self._client, name)


def wrap_client(
    client: Any,
    policy: GovernancePolicy | None = None,
) -> GovernedMistralClient:
    """Quick wrapper for Mistral clients.

    Args:
        client: A Mistral client instance.
        policy: Optional governance policy.

    Returns:
        A governed client.

    Example:
        >>> from agent_os.integrations.mistral_adapter import wrap_client
        >>> governed = wrap_client(my_client)
        >>> response = governed.chat(model="mistral-large-latest", ...)
    """
    return MistralKernel(policy=policy).wrap(client)
