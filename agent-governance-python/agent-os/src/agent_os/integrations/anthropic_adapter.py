# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Anthropic Messages integration backed by a required native ACS runtime.

Input, tool, and output intervention points are mediated before content is
forwarded to or disclosed by the Anthropic client.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError
from .base import AdapterExecutionState, BaseIntegration, get_adapter_runtime

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
class AnthropicContext(AdapterExecutionState):
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


class RequestCancelledException(Exception):
    """Raised when a request is cancelled via SIGKILL."""

    pass


class AnthropicKernel(BaseIntegration):
    """Govern Anthropic Messages API calls with a native runtime."""

    def __init__(
        self,
        max_retries: int = 3,
        timeout_seconds: float = 300.0,
        *,
        runtime: Any,
    ) -> None:
        """Initialise retry controls and the required native runtime."""
        super().__init__(runtime=runtime)
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self._wrapped_clients: dict[int, Any] = {}
        self._cancelled_requests: set[str] = set()
        self._start_time = time.monotonic()
        self._last_error: str | None = None
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
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for an Anthropic tool-use block."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

    @staticmethod
    def _to_body(data: Any) -> Any:
        """Normalise an Anthropic payload to a JSON-serialisable body."""
        if isinstance(data, (str, dict)):
            return data
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        return str(data)

    def as_message_hook(self, *, name: str = "anthropic-governance") -> "GovernanceMessageHook":
        """Create a ``GovernanceMessageHook`` for non-invasive integration.

        The hook governs ``messages.create()`` calls without wrapping or
        proxying the Anthropic client.  This is the **recommended**
        integration pattern.

        Args:
            name: Human-readable identifier for audit logging.

        Returns:
            A ``GovernanceMessageHook`` instance.

        Example::

            kernel = AnthropicKernel(policy=policy)
            hook = kernel.as_message_hook()
            response = hook.create(client, model="claude-sonnet-4-20250514", ...)
        """
        return GovernanceMessageHook(self, name=name)

    def wrap(self, client: Any) -> "GovernedAnthropicClient":
        """Wrap an Anthropic client with governance.

        .. deprecated::
            Use :meth:`as_message_hook` instead for a non-invasive
            integration that does not proxy the client object.

        Args:
            client: An ``anthropic.Anthropic`` client instance.

        Returns:
            A ``GovernedAnthropicClient`` that enforces policy on all
            ``messages.create()`` calls.
        """
        import warnings
        warnings.warn(
            "AnthropicKernel.wrap() is deprecated. Use as_message_hook() "
            "for a non-invasive governance pattern that doesn't proxy the client.",
            DeprecationWarning,
            stacklevel=2,
        )
        _check_anthropic_available()
        client_id = id(client)
        ctx = AnthropicContext(
            agent_id=f"anthropic-{client_id}",
            session_id=f"ant-{int(time.time())}",
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
        # --- pre-execution checks via AGT input intervention point ---
        messages = kwargs.get("messages", [])
        for idx, msg in enumerate(messages):
            content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
            if not isinstance(content, str):
                content = str(content)
            bridge_result = self._kernel.evaluate_input(self._ctx, content)
            if not bridge_result.allowed:
                raise bridge_result.to_policy_violation(PolicyViolationError)
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, str
            ):
                if isinstance(msg, dict):
                    msg["content"] = bridge_result.transform.value
                    messages[idx] = msg

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
            self._ctx.total_tokens = total

        # Validate tool_use blocks via AGT pre_tool_call intervention point
        content_blocks = getattr(response, "content", [])
        for block in content_blocks:
            if getattr(block, "type", None) == "tool_use":
                tool_name = getattr(block, "name", "")
                tool_input = getattr(block, "input", {}) or {}
                call_info = {
                    "id": getattr(block, "id", ""),
                    "name": tool_name,
                    "input": tool_input,
                    "timestamp": datetime.now().isoformat(),
                }
                self._ctx.tool_use_calls.append(call_info)
                self._ctx.tool_calls.append(call_info)
                self._ctx.call_count = len(self._ctx.tool_calls)

                tool_result = self._kernel.evaluate_pre_tool_call(
                    self._ctx,
                    tool_name=tool_name,
                    args=tool_input if isinstance(tool_input, dict) else {"value": tool_input},
                    call_id=getattr(block, "id", "call-1"),
                )
                if not tool_result.allowed:
                    raise tool_result.to_policy_violation(PolicyViolationError)
                if tool_result.transform is not None and isinstance(
                    tool_result.transform.value, dict
                ):
                    try:
                        block.input = tool_result.transform.value
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass

        # Post-execute bookkeeping
        self._kernel.post_execute(self._ctx, response)

        return response

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
            A dict with cumulative prompt, completion, and total token counts.
        """
        return {
            "prompt_tokens": self._ctx.prompt_tokens,
            "completion_tokens": self._ctx.completion_tokens,
            "total_tokens": self._ctx.prompt_tokens + self._ctx.completion_tokens,
        }

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying Anthropic client."""
        return getattr(self._client, name)


# ═══════════════════════════════════════════════════════════════════
# Native Hook: GovernanceMessageHook
# ═══════════════════════════════════════════════════════════════════
#
# Anthropic's Python SDK does not expose a formal middleware/plugin
# system.  However, the recommended integration pattern is a
# composable "message hook" that wraps messages.create() calls
# with governance checks — without creating a proxy client object.
#
# ═══════════════════════════════════════════════════════════════════


class GovernanceMessageHook:
    """Stateless governance hook for Anthropic ``messages.create()`` calls.

    Unlike ``GovernedAnthropicClient``, this does **not** wrap or proxy the
    client object.  Instead, it provides a ``create()`` method that governs
    a single ``messages.create()`` invocation on any client you pass in.

    This is the recommended integration pattern for Anthropic because the
    SDK does not expose a native plugin/middleware system.

    """

    def __init__(self, kernel: AnthropicKernel, *, name: str = "anthropic-governance") -> None:
        self._kernel = kernel
        self._name = name
        self._ctx = AnthropicContext(
            agent_id=name,
            session_id=f"ant-hook-{int(time.time())}",
        )
        kernel.contexts[name] = self._ctx

    @property
    def kernel(self) -> AnthropicKernel:
        """Return the governing kernel."""
        return self._kernel

    @property
    def context(self) -> AnthropicContext:
        """Return the execution context."""
        return self._ctx

    def create(self, client: Any, **kwargs: Any) -> Any:
        """Govern a single ``messages.create()`` call.

        Validates message content via the AGT ``input`` intervention
        point, evaluates each tool-use block returned by Claude through
        the AGT ``pre_tool_call`` intervention point, applies
        transform-verdict rewrites per AGT-DELTA D1.1, and routes
        escalate verdicts through the configured approval resolver per
        AGT-DELTA D1.4.

        Args:
            client: An ``anthropic.Anthropic`` client instance.
            **kwargs: Forwarded to ``client.messages.create()``.

        Returns:
            The Anthropic message response.

        Raises:
            PolicyViolationError: If a governance policy is violated.
        """
        # --- pre-execution checks via AGT input intervention point ---
        messages = kwargs.get("messages", [])
        for idx, msg in enumerate(messages):
            content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
            if not isinstance(content, str):
                content = str(content)
            bridge_result = self._kernel.evaluate_input(self._ctx, content)
            if not bridge_result.allowed:
                raise bridge_result.to_policy_violation(PolicyViolationError)
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, str
            ):
                if isinstance(msg, dict):
                    msg["content"] = bridge_result.transform.value
                    messages[idx] = msg

        # Audit log
        logger.info(
            "Anthropic hook.create | agent=%s model=%s",
            self._name,
            kwargs.get("model", "unknown"),
        )

        # --- execute ---
        response = client.messages.create(**kwargs)

        # --- post-execution checks ---
        response_id = getattr(response, "id", f"msg-{int(time.time())}")
        self._ctx.message_ids.append(response_id)

        # Track tokens
        usage = getattr(response, "usage", None)
        if usage:
            self._ctx.prompt_tokens += getattr(usage, "input_tokens", 0)
            self._ctx.completion_tokens += getattr(usage, "output_tokens", 0)

            total = self._ctx.prompt_tokens + self._ctx.completion_tokens
            self._ctx.total_tokens = total

        # Validate tool_use blocks in response via AGT pre_tool_call
        content_blocks = getattr(response, "content", [])
        for block in content_blocks:
            if getattr(block, "type", None) == "tool_use":
                tool_name = getattr(block, "name", "")
                tool_input = getattr(block, "input", {}) or {}
                self._ctx.tool_use_calls.append({
                    "id": getattr(block, "id", ""),
                    "name": tool_name,
                    "input": tool_input,
                    "timestamp": datetime.now().isoformat(),
                })
                self._ctx.tool_calls.append({"name": tool_name})
                self._ctx.call_count = len(self._ctx.tool_calls)

                tool_result = self._kernel.evaluate_pre_tool_call(
                    self._ctx,
                    tool_name=tool_name,
                    args=tool_input if isinstance(tool_input, dict) else {"value": tool_input},
                    call_id=getattr(block, "id", "call-1"),
                )
                if not tool_result.allowed:
                    raise tool_result.to_policy_violation(PolicyViolationError)
                if tool_result.transform is not None and isinstance(
                    tool_result.transform.value, dict
                ):
                    # Rewrite the tool-use block's input per AGT D1.1
                    # so any subsequent host-side tool executor sees
                    # the sanitised arguments.
                    try:
                        block.input = tool_result.transform.value
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass

        # Record host completion after output mediation.
        self._kernel.post_execute(self._ctx, response)

        return response

    def __repr__(self) -> str:
        return f"GovernanceMessageHook(name={self._name!r})"


def wrap_client(
    client: Any,
    *,
    runtime: Any,
) -> GovernedAnthropicClient:
    """Quick wrapper for Anthropic clients.

    .. deprecated::
        Use ``AnthropicKernel.as_message_hook()`` instead for a
        non-invasive integration that does not proxy the client.

    Args:
        client: An ``anthropic.Anthropic`` client instance.
        runtime: Native runtime used for every intervention point.

    Returns:
        A governed client.

    Example:
        >>> from agent_os.integrations.anthropic_adapter import wrap_client
        >>> governed = wrap_client(my_client)
        >>> response = governed.messages.create(model="claude-sonnet-4-20250514", ...)
    """
    import warnings
    warnings.warn(
        "wrap_client() is deprecated. Use AnthropicKernel(runtime=...).as_message_hook() "
        "for a non-invasive governance pattern that doesn't proxy the client.",
        DeprecationWarning,
        stacklevel=2,
    )
    return AnthropicKernel(runtime=runtime).wrap(client)
