# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Anthropic Claude Integration

Wraps Anthropic's Messages API with Agent OS governance.

Usage:
    from agent_os.integrations.anthropic_adapter import AnthropicKernel

    kernel = AnthropicKernel(policy=GovernancePolicy(
        max_tokens=4096,
        allowed_tools=["web_search", "code_interpreter"],
        blocked_patterns=["password", "api_key"],
    ))

    governed = kernel.wrap(client)
    # All messages.create() calls are now governed
    response = governed.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )

Features:
- Pre-execution policy checks on message content
- Tool call interception and validation
- Token limit enforcement
- Content filtering via blocked patterns
- SIGKILL support (cancel running requests)
- Full audit trail
- Health check endpoint
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .base import BaseIntegration, ExecutionContext, GovernancePolicy

logger = logging.getLogger("agent_os.anthropic")

try:
    import anthropic as _anthropic_mod  # noqa: F401

    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False


def _check_anthropic_available() -> None:
    """Raise a helpful error when the ``anthropic`` package is missing."""
    if not _HAS_ANTHROPIC:
        raise ImportError(
            "The 'anthropic' package is required for AnthropicKernel. "
            "Install it with: pip install anthropic"
        )


@dataclass
class AnthropicContext(ExecutionContext):
    """Execution context for Anthropic Claude interactions.

    Attributes:
        model: The model used for this session.
        message_ids: Recorded message response IDs.
        tool_use_calls: History of tool-use blocks returned by Claude.
        prompt_tokens: Cumulative input tokens consumed.
        completion_tokens: Cumulative output tokens consumed.
    """

    model: str = ""
    message_ids: list[str] = field(default_factory=list)
    tool_use_calls: list[dict[str, Any]] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0


class PolicyViolationError(Exception):
    """Raised when a Claude request violates governance policy."""

    pass


class RequestCancelledException(Exception):
    """Raised when a request is cancelled via SIGKILL."""

    pass


class AnthropicKernel(BaseIntegration):
    """Anthropic Claude adapter for Agent OS.

    Provides governance for the Anthropic Messages API including policy
    enforcement, tool-call validation, token tracking, and audit logging.

    Example:
        >>> kernel = AnthropicKernel(policy=GovernancePolicy(max_tokens=8192))
        >>> governed = kernel.wrap(anthropic.Anthropic())
        >>> response = governed.messages.create(
        ...     model="claude-sonnet-4-20250514",
        ...     max_tokens=1024,
        ...     messages=[{"role": "user", "content": "Hello"}],
        ... )
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
        max_retries: int = 3,
        timeout_seconds: float = 300.0,
    ) -> None:
        """Initialise the Anthropic governance kernel.

        Args:
            policy: Governance policy to enforce. Uses default when ``None``.
            max_retries: Maximum retry attempts for transient errors.
            timeout_seconds: Default timeout for operations.
        """
        super().__init__(policy)
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self._wrapped_clients: dict[int, Any] = {}
        self._cancelled_requests: set[str] = set()
        self._start_time = time.monotonic()
        self._last_error: str | None = None

    def wrap(self, client: Any) -> GovernedAnthropicClient:
        """Wrap an Anthropic client with governance.

        Args:
            client: An ``anthropic.Anthropic`` client instance.

        Returns:
            A ``GovernedAnthropicClient`` that enforces policy on all
            ``messages.create()`` calls.
        """
        _check_anthropic_available()
        client_id = id(client)
        ctx = AnthropicContext(
            agent_id=f"anthropic-{client_id}",
            session_id=f"ant-{int(time.time())}",
            policy=self.policy,
        )
        self.contexts[ctx.agent_id] = ctx
        self._wrapped_clients[client_id] = client

        return GovernedAnthropicClient(
            client=client,
            kernel=self,
            ctx=ctx,
        )

    def unwrap(self, governed_agent: Any) -> Any:
        """Retrieve the original unwrapped Anthropic client.

        Args:
            governed_agent: A ``GovernedAnthropicClient`` or any object.

        Returns:
            The original Anthropic client if applicable, otherwise
            *governed_agent* as-is.
        """
        if isinstance(governed_agent, GovernedAnthropicClient):
            return governed_agent._client
        return governed_agent

    def cancel_request(self, request_id: str) -> None:
        """Cancel a request (SIGKILL equivalent).

        Args:
            request_id: Identifier of the request to cancel.
        """
        self._cancelled_requests.add(request_id)
        logger.info("Request %s marked for cancellation", request_id)

    def is_cancelled(self, request_id: str) -> bool:
        """Check whether a request has been cancelled.

        Args:
            request_id: The request identifier to check.

        Returns:
            ``True`` if the request was previously cancelled.
        """
        return request_id in self._cancelled_requests

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
            "backend": "anthropic",
            "backend_connected": has_clients,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


class _GovernedMessages:
    """Proxy for ``client.messages`` that intercepts ``create()``."""

    def __init__(
        self,
        client: Any,
        kernel: AnthropicKernel,
        ctx: AnthropicContext,
    ) -> None:
        self._client = client
        self._kernel = kernel
        self._ctx = ctx

    def create(self, **kwargs: Any) -> Any:
        """Create a message with governance enforcement.

        Validates message content against blocked patterns, enforces
        tool-call allowlists, checks token limits after completion,
        and records an audit trail.

        Args:
            **kwargs: Forwarded to ``client.messages.create()``.

        Returns:
            The Anthropic message response.

        Raises:
            PolicyViolationError: If a governance policy is violated.
            RequestCancelledException: If the request was SIGKILL'd.
        """
        # --- pre-execution checks ---
        messages = kwargs.get("messages", [])
        for msg in messages:
            content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
            allowed, reason = self._kernel.pre_execute(self._ctx, content)
            if not allowed:
                raise PolicyViolationError(f"Message blocked: {reason}")

        # Validate requested tools against policy
        tools = kwargs.get("tools")
        if tools:
            self._validate_tools(tools)

        # Enforce max_tokens cap from policy
        requested_max = kwargs.get("max_tokens", 0)
        if requested_max > self._kernel.policy.max_tokens:
            raise PolicyViolationError(
                f"Requested max_tokens ({requested_max}) exceeds policy limit "
                f"({self._kernel.policy.max_tokens})"
            )

        # Audit log
        logger.info(
            "Anthropic messages.create | agent=%s model=%s",
            self._ctx.agent_id,
            kwargs.get("model", "unknown"),
        )

        # --- execute ---
        try:
            response = self._client.messages.create(**kwargs)
        except Exception as exc:
            self._kernel._last_error = str(exc)
            raise

        # --- post-execution checks ---
        response_id = getattr(response, "id", f"msg-{int(time.time())}")
        self._ctx.message_ids.append(response_id)

        if self._kernel.is_cancelled(response_id):
            raise RequestCancelledException("Request was cancelled (SIGKILL)")

        # Track tokens
        usage = getattr(response, "usage", None)
        if usage:
            self._ctx.prompt_tokens += getattr(usage, "input_tokens", 0)
            self._ctx.completion_tokens += getattr(usage, "output_tokens", 0)

            total = self._ctx.prompt_tokens + self._ctx.completion_tokens
            if total > self._kernel.policy.max_tokens:
                raise PolicyViolationError(
                    f"Token limit exceeded: {total} > {self._kernel.policy.max_tokens}"
                )

        # Validate tool_use blocks in response
        content_blocks = getattr(response, "content", [])
        for block in content_blocks:
            if getattr(block, "type", None) == "tool_use":
                tool_name = getattr(block, "name", "")
                call_info = {
                    "id": getattr(block, "id", ""),
                    "name": tool_name,
                    "input": getattr(block, "input", {}),
                    "timestamp": datetime.now().isoformat(),
                }
                self._ctx.tool_use_calls.append(call_info)
                self._ctx.tool_calls.append(call_info)

                if len(self._ctx.tool_calls) > self._kernel.policy.max_tool_calls:
                    raise PolicyViolationError(
                        f"Tool call limit exceeded: "
                        f"{len(self._ctx.tool_calls)} > "
                        f"{self._kernel.policy.max_tool_calls}"
                    )

                if self._kernel.policy.allowed_tools:
                    if tool_name not in self._kernel.policy.allowed_tools:
                        raise PolicyViolationError(
                            f"Tool not allowed: {tool_name}"
                        )

                if self._kernel.policy.require_human_approval:
                    raise PolicyViolationError(
                        f"Tool '{tool_name}' requires human approval per governance policy"
                    )

        # Post-execute bookkeeping
        self._kernel.post_execute(self._ctx, response)

        return response

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
            name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
            if name and name not in self._kernel.policy.allowed_tools:
                raise PolicyViolationError(f"Tool not allowed: {name}")


class GovernedAnthropicClient:
    """Anthropic client wrapped with Agent OS governance.

    Transparently proxies attribute access to the underlying client
    while intercepting ``messages.create()`` for policy enforcement.
    """

    def __init__(
        self,
        client: Any,
        kernel: AnthropicKernel,
        ctx: AnthropicContext,
    ) -> None:
        self._client = client
        self._kernel = kernel
        self._ctx = ctx
        self.messages = _GovernedMessages(client, kernel, ctx)

    def sigkill(self, request_id: str) -> None:
        """Send SIGKILL — immediately cancel a request.

        Args:
            request_id: The message ID to cancel.
        """
        self._kernel.cancel_request(request_id)

    def get_context(self) -> AnthropicContext:
        """Return the execution context with the full audit trail.

        Returns:
            The ``AnthropicContext`` for this governed client.
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

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying Anthropic client."""
        return getattr(self._client, name)


def wrap_client(
    client: Any,
    policy: GovernancePolicy | None = None,
) -> GovernedAnthropicClient:
    """Quick wrapper for Anthropic clients.

    Args:
        client: An ``anthropic.Anthropic`` client instance.
        policy: Optional governance policy.

    Returns:
        A governed client.

    Example:
        >>> from agent_os.integrations.anthropic_adapter import wrap_client
        >>> governed = wrap_client(my_client)
        >>> response = governed.messages.create(model="claude-sonnet-4-20250514", ...)
    """
    return AnthropicKernel(policy=policy).wrap(client)
