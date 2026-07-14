# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LangChain AgentMiddleware integration backed by a native ACS runtime.

Model and tool calls are mediated before handlers run. Outputs are mediated
before they are returned to LangChain.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .base import BaseIntegration, GovernanceEventType, get_adapter_runtime
from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError

logger = logging.getLogger("agent_os.langchain")


# ── Graceful import of LangChain AgentMiddleware ──────────────────────
try:
    from langchain.agents.middleware import AgentMiddleware as _SDKMiddleware  # type: ignore[import-untyped]

    _HAS_MIDDLEWARE = True
except ImportError:
    _SDKMiddleware = None
    _HAS_MIDDLEWARE = False


class LangChainKernel(BaseIntegration):
    """Provide native LangChain model and tool middleware."""

    def __init__(self, *, runtime: Any):
        super().__init__(runtime=runtime)
        self._start_time = time.monotonic()
        self._last_error: Optional[str] = None
        self._tool_invocations: list[dict[str, Any]] = []
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
        """AGT ``pre_tool_call`` evaluation for a LangChain tool invocation."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

    def evaluate_output(self, ctx: Any, output_data: Any) -> AdapterResult:
        """AGT ``output`` evaluation for buffered LangChain output."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

    @staticmethod
    def _to_body(data: Any) -> Any:
        """Normalise a LangChain input payload to a JSON-serialisable body."""
        if isinstance(data, (str, dict)):
            return data
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        if isinstance(data, list):
            return str(data)
        return str(data)

    # ── Deep Integration Hooks ────────────────────────────────────

    def _record_tool_invocation(
        self,
        tool_name: str,
        args: Any,
        kwargs: Any,
        *,
        skill_fields: dict[str, str | None] | None = None,
    ) -> None:
        """Append a tool invocation record to the audit log."""
        record = {
            "tool_name": tool_name,
            "args": str(args),
            "kwargs": str(kwargs),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(skill_fields or self.build_skill_audit_fields()),
        }
        self._tool_invocations.append(record)
        logger.info("Tool invocation: %s", record)

    # ── Memory Write Interception ─────────────────────────────────

    def as_middleware(self, name: str = "governance") -> "GovernanceMiddleware":
        """Return middleware backed by this kernel."""
        return GovernanceMiddleware(kernel=self, name=name)

    # ================================================================
    # Deprecated wrap()-Based API  (BACKWARD COMPAT)
    # ================================================================

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
            "backend": "langchain",
            "backend_connected": True,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


# =====================================================================
# GovernanceMiddleware  (native AgentMiddleware)
# =====================================================================

# Build the base class dynamically so the module stays importable even
# when ``langchain`` is not installed.
_MiddlewareBase: type = _SDKMiddleware if _HAS_MIDDLEWARE else object


class GovernanceMiddleware(_MiddlewareBase):
    """LangChain middleware that mediates model and tool calls through ACS."""

    def __init__(
        self,
        kernel: "LangChainKernel",
        name: str = "governance",
    ):
        """Initialise the governance middleware.

        Args:
            kernel: The :class:`LangChainKernel` that supplies the active
                governance policy and Cedar/OPA evaluator.
            name: Label used in log messages and audit records.
        """
        self._kernel = kernel
        self._name = name
        self._ctx = kernel.create_context(f"langchain-middleware-{name}")
        logger.info("GovernanceMiddleware '%s' initialised", name)

    # ── wrap_tool_call ────────────────────────────────────────────
    #
    # Intercepts every tool execution.  Has full access to the tool
    # name and arguments before execution, and the result after.
    # Can BLOCK by raising PolicyViolationError.

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        """Governance gate around each tool execution.

        Performs the following checks **before** the tool runs:

        1. Tool allowlist / blocklist enforcement.
        2. Blocked-pattern scan on tool arguments.
        3. Cedar/OPA ``pre_execute`` gate (when an evaluator is
           configured on the kernel).

        After the tool completes, a ``post_execute`` check validates
        the output against the governance policy.

        Args:
            request: LangChain ``ToolCallRequest`` with ``tool_call``
                dict containing ``name``, ``args``, and ``id``.
            handler: Callable that executes the actual tool.

        Returns:
            The tool's result (``ToolMessage`` or ``Command``).

        Raises:
            PolicyViolationError: If the tool call violates the
                governance policy.
        """
        tool_call = getattr(request, "tool_call", {})
        tool_name = tool_call.get("name", "<unknown>") if isinstance(tool_call, dict) else str(tool_call)
        tool_args = tool_call.get("args", {}) if isinstance(tool_call, dict) else {}

        logger.debug(
            "[%s] wrap_tool_call: tool=%s args=%s",
            self._name,
            tool_name,
            tool_args,
        )

        trusted_skill_sources = self._kernel.trusted_sources(
            *self._kernel.trusted_sources_from_attrs(request),
            self._kernel.trusted_skill_metadata_from_mapping(
                getattr(request, "skill_metadata", None)
            ),
        )

        skill_fields = self._kernel.build_skill_audit_fields(
            trusted_sources=trusted_skill_sources,
            default_origin="langchain",
            context_before=tool_args,
        )
        self._kernel.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=self._ctx.agent_id,
            action="langchain.wrap_tool_call",
            trusted_sources=trusted_skill_sources,
            default_origin="langchain",
            context_before=tool_args,
            tool_name=tool_name,
        )

        # ─── 2. AGT pre_tool_call evaluation ──────────────────────
        bridge_result = self._kernel.evaluate_pre_tool_call(
            self._ctx,
            tool_name=tool_name,
            args=tool_args if isinstance(tool_args, dict) else {"value": tool_args},
            call_id=tool_call.get("id", "call-1") if isinstance(tool_call, dict) else "call-1",
        )
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ) and isinstance(tool_call, dict):
            tool_args = bridge_result.transform.value
            tool_call["args"] = tool_args
        if not bridge_result.allowed:
            logger.info(
                "[%s] Policy DENY (AGT pre_tool_call) on tool '%s': %s",
                self._name,
                tool_name,
                bridge_result.reason,
            )
            raise bridge_result.to_policy_violation(PolicyViolationError)
        logger.info("[%s] Policy ALLOW on tool '%s'", self._name, tool_name)

        # ─── 3. Record invocation ─────────────────────────────────
        self._kernel._record_tool_invocation(
            tool_name,
            (tool_args,),
            {},
            skill_fields=skill_fields,
        )

        # ─── 4. Execute the tool ──────────────────────────────────
        try:
            result = handler(request)
        except Exception as exc:
            logger.error(
                "[%s] Tool '%s' raised: %s", self._name, tool_name, exc
            )
            self._kernel._last_error = str(exc)
            raise

        # ─── 5. Post-execution validation via AGT output hook ─────
        result_str = str(getattr(result, "content", result))

        post_result = self._kernel._bridge.evaluate_output(self._ctx, content=result_str)
        if not post_result.allowed:
            logger.info(
                "[%s] Policy DENY (AGT output) on tool '%s' result: %s",
                self._name,
                tool_name,
                post_result.reason,
            )
            raise post_result.to_policy_violation(PolicyViolationError)
        if post_result.transform is not None and isinstance(
            post_result.transform.value, str
        ):
            # Rewrite the tool result content so downstream consumers see
            # the AGT-redacted text per AGT-DELTA D1.1.
            if hasattr(result, "content"):
                try:
                    result.content = post_result.transform.value
                except Exception:  # noqa: BLE001 — best-effort rewrite on opaque message
                    pass

        self._ctx.call_count += 1
        return result

    # ── wrap_model_call ───────────────────────────────────────────
    #
    # Intercepts every model (LLM/chat) call.  Can modify the request
    # (tools, system prompt) or block entirely.  This is a *new*
    # capability not possible via the proxy-based wrap() approach.

    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        """Governance gate around each model invocation.

        Performs the following checks **before** the model call:

        1. Content-filter scan on input messages for blocked patterns.
        2. Cedar/OPA ``pre_execute`` gate on the model input.

        After the model responds, a ``post_execute`` check validates
        the output for blocked patterns.

        This hook also enables **model-level governance** — a capability
        that the proxy-based ``wrap()`` approach cannot achieve:

        * System prompt integrity validation.
        * Dynamic tool filtering (remove dangerous tools before the
          model sees them).
        * Prompt injection detection on input messages.

        Args:
            request: LangChain ``ModelRequest`` with ``messages``,
                ``tools``, and ``system_message`` attributes.
            handler: Callable that executes the model call.

        Returns:
            The model's response.

        Raises:
            PolicyViolationError: If the model input or output
                violates the governance policy.
        """
        # Extract input text for content filtering
        messages = getattr(request, "messages", None) or []
        input_text = ""
        for msg in messages:
            content = getattr(msg, "content", str(msg))
            if isinstance(content, str):
                input_text += " " + content
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        input_text += " " + block.get("text", "")

        logger.debug(
            "[%s] wrap_model_call: input_len=%d",
            self._name,
            len(input_text),
        )

        trusted_skill_sources = self._kernel.trusted_sources(
            *self._kernel.trusted_sources_from_attrs(request),
            self._kernel.trusted_skill_metadata_from_mapping(
                getattr(request, "skill_metadata", None)
            ),
        )

        self._kernel.emit_skill_audit_event(
            GovernanceEventType.POLICY_CHECK,
            agent_id=self._ctx.agent_id,
            action="langchain.wrap_model_call",
            trusted_sources=trusted_skill_sources,
            default_origin="langchain",
            context_before=input_text.strip() if input_text.strip() else None,
        )

        # ─── 1. Content filter on input ───────────────────────────
        # ─── 1. AGT input intervention point ──────────────────────
        if input_text.strip():
            pre_result = self._kernel.evaluate_input(
                self._ctx, input_text.strip()
            )
            if not pre_result.allowed:
                logger.info(
                    "[%s] Policy DENY (AGT input) on model input: %s",
                    self._name,
                    pre_result.reason,
                )
                raise pre_result.to_policy_violation(PolicyViolationError)
            if pre_result.transform is not None and isinstance(
                pre_result.transform.value, str
            ):
                # Rewrite the most recent user message content per AGT D1.1.
                for msg in reversed(messages):
                    if hasattr(msg, "content") and isinstance(
                        getattr(msg, "content"), str
                    ):
                        try:
                            msg.content = pre_result.transform.value
                        except Exception:  # noqa: BLE001 — best-effort rewrite
                            pass
                        break
            logger.info("[%s] Policy ALLOW on model input", self._name)

        # ─── 2. Execute the model call ────────────────────────────
        try:
            response = handler(request)
        except Exception as exc:
            logger.error("[%s] Model call failed: %s", self._name, exc)
            self._kernel._last_error = str(exc)
            raise

        # ─── 3. AGT output intervention point ─────────────────────
        response_msg = getattr(response, "message", response)
        output_text = getattr(response_msg, "content", str(response_msg))
        if isinstance(output_text, str) and output_text.strip():
            post_result = self._kernel._bridge.evaluate_output(
                self._ctx, content=output_text.strip()
            )
            if not post_result.allowed:
                logger.info(
                    "[%s] Policy DENY (AGT output) on model output: %s",
                    self._name,
                    post_result.reason,
                )
                raise post_result.to_policy_violation(PolicyViolationError)
            if post_result.transform is not None and isinstance(
                post_result.transform.value, str
            ):
                if hasattr(response_msg, "content"):
                    try:
                        response_msg.content = post_result.transform.value
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass

        return response

    # ── Convenience properties ────────────────────────────────────

    @property
    def kernel(self) -> "LangChainKernel":
        """Return the governing kernel."""
        return self._kernel

    @property
    def context(self) -> Any:
        """Return the execution context."""
        return self._ctx

    def __repr__(self) -> str:
        return (
            f"GovernanceMiddleware(name={self._name!r})"
        )
