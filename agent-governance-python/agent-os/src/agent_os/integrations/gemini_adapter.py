# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Google Gemini integration backed by a required native ACS runtime.

Prompts, tool calls, and outputs are mediated before Gemini receives or
discloses them.
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

logger = logging.getLogger("agent_os.gemini")

try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        import google.generativeai as _genai_mod  # noqa: F401

    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False


def _check_genai_available() -> None:
    """Raise a helpful error when the ``google-generativeai`` package is missing."""
    if not _HAS_GENAI:
        raise ImportError(
            "The 'google-generativeai' package is required for GeminiKernel. "
            "Install it with: pip install google-generativeai"
        )


@dataclass
class GeminiContext(AdapterExecutionState):
    """Execution context for Google Gemini interactions.

    Attributes:
        model_name: The Gemini model used for this session.
        generation_ids: Recorded generation response identifiers.
        function_calls: History of function calls returned by Gemini.
        prompt_tokens: Cumulative prompt tokens consumed.
        completion_tokens: Cumulative candidate tokens consumed.
    """

    model_name: str = ""
    generation_ids: list[str] = field(default_factory=list)
    function_calls: list[dict[str, Any]] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0


class GeminiKernel(BaseIntegration):
    """Govern Gemini generation and tool calls with a native runtime."""

    def __init__(
        self,
        *,
        runtime: Any,
    ) -> None:
        """Initialise the kernel with the required native runtime."""
        super().__init__(runtime=runtime)
        self._wrapped_models: dict[int, Any] = {}
        self._start_time = time.monotonic()
        self._last_error: str | None = None
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(self, ctx: AdapterExecutionState, input_data: Any) -> AdapterResult:
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
        ctx: AdapterExecutionState,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> AdapterResult:
        """AGT ``pre_tool_call`` evaluation for a Gemini function call."""
        return self._bridge.evaluate_pre_tool_call(
            ctx, tool_name=tool_name, args=args, call_id=call_id
        )

    def wrap(self, model: Any) -> GovernedGeminiModel:
        """Wrap a Gemini GenerativeModel with governance.

        Args:
            model: A ``google.generativeai.GenerativeModel`` instance.

        Returns:
            A ``GovernedGeminiModel`` that enforces policy on all
            ``generate_content()`` calls.
        """
        _check_genai_available()
        model_id = id(model)
        model_name = getattr(model, "model_name", "unknown")
        ctx = GeminiContext(
            agent_id=f"gemini-{model_id}",
            session_id=f"gem-{int(time.time())}",
            model_name=model_name,
        )
        self.contexts[ctx.agent_id] = ctx
        self._wrapped_models[model_id] = model

        return GovernedGeminiModel(
            model=model,
            kernel=self,
            ctx=ctx,
        )

    def unwrap(self, governed_agent: Any) -> Any:
        """Retrieve the original unwrapped Gemini model.

        Args:
            governed_agent: A ``GovernedGeminiModel`` or any object.

        Returns:
            The original GenerativeModel if applicable, otherwise
            *governed_agent* as-is.
        """
        if isinstance(governed_agent, GovernedGeminiModel):
            return governed_agent._model
        return governed_agent

    def health_check(self) -> dict[str, Any]:
        """Return adapter health status.

        Returns:
            A dict with ``status``, ``backend``, ``last_error``, and
            ``uptime_seconds`` keys.
        """
        uptime = time.monotonic() - self._start_time
        has_models = bool(self._wrapped_models)
        status = "degraded" if self._last_error else "healthy"
        return {
            "status": status,
            "backend": "gemini",
            "backend_connected": has_models,
            "last_error": self._last_error,
            "uptime_seconds": round(uptime, 2),
        }


class GovernedGeminiModel:
    """Gemini GenerativeModel wrapped with Agent OS governance.

    Intercepts ``generate_content()`` for policy enforcement while
    proxying all other attributes to the underlying model.
    """

    def __init__(
        self,
        model: Any,
        kernel: GeminiKernel,
        ctx: GeminiContext,
    ) -> None:
        self._model = model
        self._kernel = kernel
        self._ctx = ctx

    def generate_content(self, contents: Any, **kwargs: Any) -> Any:
        """Generate content with governance enforcement.

        Validates prompt content against the configured AGT manifest at
        the ``input`` intervention point, validates each function-call
        block returned by the model at the ``pre_tool_call`` intervention
        point, enforces token limits, and records an audit trail.

        Args:
            contents: The prompt content (string, list, or Content object).
            **kwargs: Forwarded to ``model.generate_content()``.

        Returns:
            The Gemini generation response.

        Raises:
            PolicyViolationError: If a governance policy is violated.
        """
        # --- pre-execution checks via AGT input intervention point ---
        content_str = str(contents)
        bridge_result = self._kernel.evaluate_input(self._ctx, content_str)
        if not bridge_result.allowed:
            raise bridge_result.to_policy_violation(PolicyViolationError)
        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, str
        ):
            contents = bridge_result.transform.value

        # Validate tools against policy
        tools = kwargs.get("tools")
        if tools:
            self._validate_tools(tools)

        # Audit log
        logger.info(
            "Gemini generate_content | agent=%s model=%s",
            self._ctx.agent_id,
            self._ctx.model_name,
        )

        # --- execute ---
        try:
            response = self._kernel._wrapped_models.get(
                id(self._model), self._model
            ).generate_content(contents, **kwargs)
        except Exception as exc:
            self._kernel._last_error = str(exc)
            raise

        # --- post-execution checks ---
        gen_id = f"gen-{int(time.time())}-{self._ctx.call_count}"
        self._ctx.generation_ids.append(gen_id)

        # Track tokens from usage_metadata
        usage = getattr(response, "usage_metadata", None)
        if usage:
            self._ctx.prompt_tokens += getattr(usage, "prompt_token_count", 0)
            self._ctx.completion_tokens += getattr(
                usage, "candidates_token_count", 0
            )

            total = self._ctx.prompt_tokens + self._ctx.completion_tokens
            self._ctx.total_tokens = total

        # Check for function calls in candidates via AGT pre_tool_call
        candidates = getattr(response, "candidates", [])
        for candidate in candidates:
            content = getattr(candidate, "content", None)
            if content is None:
                continue
            parts = getattr(content, "parts", [])
            for part in parts:
                fn_call = getattr(part, "function_call", None)
                if fn_call is None:
                    continue
                fn_name = getattr(fn_call, "name", "")
                fn_args = dict(getattr(fn_call, "args", {}))
                call_info = {
                    "name": fn_name,
                    "args": fn_args,
                    "timestamp": datetime.now().isoformat(),
                }
                self._ctx.function_calls.append(call_info)
                self._ctx.tool_calls.append(call_info)
                current_call_count = len(self._ctx.tool_calls)
                self._ctx.call_count = max(0, current_call_count - 1)
                try:
                    tool_result = self._kernel.evaluate_pre_tool_call(
                        self._ctx,
                        tool_name=fn_name,
                        args=fn_args,
                        call_id=f"call-{current_call_count}",
                    )
                finally:
                    self._ctx.call_count = current_call_count
                if not tool_result.allowed:
                    raise tool_result.to_policy_violation(PolicyViolationError)
                if tool_result.transform is not None and isinstance(
                    tool_result.transform.value, dict
                ):
                    try:
                        fn_call.args = tool_result.transform.value
                    except Exception:  # noqa: BLE001 — best-effort rewrite
                        pass
                self._kernel.bridge.record_post_execute(self._ctx, tool_calls=1)

        # Post-execute bookkeeping
        self._kernel.post_execute(self._ctx, response)

        return response

    def get_context(self) -> GeminiContext:
        """Return the execution context with the full audit trail.

        Returns:
            The ``GeminiContext`` for this governed model.
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

    def _validate_tools(self, tools: Any) -> None:
        """Tool authorization is enforced at the native tool intervention."""
        del tools

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying Gemini model."""
        return getattr(self._model, name)


def wrap_model(
    model: Any,
    *,
    runtime: Any,
) -> GovernedGeminiModel:
    """Quick wrapper for Gemini GenerativeModel.

    Args:
        model: A ``google.generativeai.GenerativeModel`` instance.
        runtime: Native runtime used for every intervention point.

    Returns:
        A governed model.

    Example:
        >>> from agent_os.integrations.gemini_adapter import wrap_model
        >>> governed = wrap_model(my_model)
        >>> response = governed.generate_content("Hello")
    """
    return GeminiKernel(runtime=runtime).wrap(model)
