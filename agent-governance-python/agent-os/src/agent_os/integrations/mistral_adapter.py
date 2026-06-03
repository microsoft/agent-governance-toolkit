# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mistral AI Integration

Wraps Mistral's Chat API with Agent OS governance.

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
outbound message content or tool arguments before the Mistral client
sees them; ``escalate`` verdicts route through the configured approval
resolver per AGT-DELTA D1.4.

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
- Pre-execution policy checks via the AGT 5.0 ACS runtime
- Tool call interception and validation at the AGT pre_tool_call hook
- Transform-verdict rewriting of outbound message content and tool args
- Escalate-verdict approval routing via the configured resolver
- Token limit enforcement
- Audit logging for all calls
- Health check endpoint
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from ..exceptions import PolicyViolationError as _CanonicalPolicyViolationError
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


class PolicyViolationError(_CanonicalPolicyViolationError):
    """Raised when a Mistral request violates governance policy.

    Subclass of :class:`agent_os.exceptions.PolicyViolationError` so the
    canonical ``from_check_result`` constructor is available while
    preserving the legacy ``agent_os.integrations.mistral_adapter.PolicyViolationError``
    import path for v4 callers.
    """

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
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Initialise the Mistral governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used. The policy is translated to
                an AGT manifest and an :class:`agt.policies.runtime.AgtRuntime`
                is constructed over it at init time.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature matches
                :data:`agt.policies.runtime.ApprovalCallback`. When
                ``None`` an escalate verdict fails closed to ``deny``.
            _runtime: Test seam — inject a pre-built :class:`AgtRuntime`
                so scenario tests can wire a scripted policy dispatcher
                without OPA on PATH. Not part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public surface.
        """
        super().__init__(policy)
        self._wrapped_clients: dict[int, Any] = {}
        self._start_time = time.monotonic()
        self._last_error: str | None = None
        self._approval_resolver = approval_resolver
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this kernel."""
        return self._bridge

    def evaluate_input(
        self, ctx: ExecutionContext, input_data: Any
    ) -> BridgeResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        body: Any
        if isinstance(input_data, (str, dict)):
            body = input_data
        elif hasattr(input_data, "content"):
            body = str(getattr(input_data, "content"))
        else:
            body = str(input_data)
        return self._bridge.evaluate_input(ctx, body=body)

    def evaluate_pre_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> BridgeResult:
        """AGT ``pre_tool_call`` evaluation for a Mistral tool-call response."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

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

        Validates message content against the configured AGT manifest at
        the ``input`` intervention point. Tool calls returned by Mistral
        are validated at the ``pre_tool_call`` intervention point.
        ``transform`` verdicts (AGT-DELTA D1.1) rewrite the outbound
        message content or tool arguments; ``deny`` verdicts raise
        :class:`PolicyViolationError`; ``escalate`` verdicts that the
        approval resolver refuses are surfaced as ``deny``.

        Args:
            **kwargs: Forwarded to ``client.chat()`` (includes ``model``,
                ``messages``, ``tools``, etc.).

        Returns:
            The Mistral chat completion response.

        Raises:
            PolicyViolationError: If a governance policy is violated.
        """
        # --- pre-execution checks via AGT input intervention point ---
        messages = kwargs.get("messages", [])
        for idx, msg in enumerate(messages):
            if isinstance(msg, dict):
                content = msg.get("content", "")
            else:
                content = str(msg)
            if not isinstance(content, str):
                content = str(content)
            bridge_result = self._kernel.evaluate_input(self._ctx, content)
            if not bridge_result.allowed:
                raise PolicyViolationError.from_check_result(
                    bridge_result.check_result
                )
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, str
            ):
                if isinstance(msg, dict):
                    msg["content"] = bridge_result.transform.value
                    messages[idx] = msg

        # Validate tools against policy (host-side allowlist guard — the
        # AGT manifest bridge emits no ``pre_tool_call`` binding for tool
        # definitions submitted with the request).
        tools = kwargs.get("tools")
        if tools:
            self._validate_tools(tools)

        # Enforce max_tokens cap from policy. This is the per-request
        # parameter the Mistral API exposes (request-level, not snapshot
        # budget) so it stays at the host-side guard.
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
            self._ctx.total_tokens = total
            if total > self._kernel.policy.max_tokens:
                raise PolicyViolationError(
                    f"Token limit exceeded: {total} > "
                    f"{self._kernel.policy.max_tokens}"
                )

        # Check for tool calls in response choices via AGT pre_tool_call
        # intervention point.
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
                raw_args = getattr(fn, "arguments", "") if fn else ""
                call_info = {
                    "id": getattr(tc, "id", ""),
                    "name": fn_name,
                    "arguments": raw_args,
                    "timestamp": datetime.now().isoformat(),
                }
                self._ctx.function_calls.append(call_info)
                self._ctx.tool_calls.append(call_info)
                self._ctx.call_count = len(self._ctx.tool_calls)

                # Parse Mistral's JSON-string arguments for the snapshot.
                parsed_args: dict[str, Any]
                if isinstance(raw_args, dict):
                    parsed_args = raw_args
                elif isinstance(raw_args, str) and raw_args:
                    try:
                        import json as _json

                        parsed_args = _json.loads(raw_args)
                        if not isinstance(parsed_args, dict):
                            parsed_args = {"_value": parsed_args}
                    except (TypeError, ValueError):
                        parsed_args = {"_raw": raw_args}
                else:
                    parsed_args = {}

                tool_result = self._kernel.evaluate_pre_tool_call(
                    self._ctx,
                    tool_name=fn_name or "",
                    args=parsed_args,
                    call_id=getattr(tc, "id", "call-1") or "call-1",
                )
                if not tool_result.allowed:
                    raise PolicyViolationError.from_check_result(
                        tool_result.check_result
                    )
                if tool_result.transform is not None and isinstance(
                    tool_result.transform.value, dict
                ):
                    # Rewrite the Mistral tool-call arguments per AGT D1.1.
                    try:
                        import json as _json

                        if fn is not None:
                            fn.arguments = _json.dumps(tool_result.transform.value)
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass

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
