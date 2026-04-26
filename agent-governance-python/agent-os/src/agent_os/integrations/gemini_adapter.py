# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Google Gemini Integration

Wraps Google's Generative AI SDK with Agent OS governance.

Usage:
    from agent_os.integrations.gemini_adapter import GeminiKernel
    import google.generativeai as genai

    kernel = GeminiKernel(policy=GovernancePolicy(
        max_tokens=4096,
        allowed_tools=["web_search"],
        blocked_patterns=["password"],
    ))

    model = genai.GenerativeModel("gemini-pro")
    governed = kernel.wrap(model)
    response = governed.generate_content("Hello")

Features:
- Pre-execution policy checks on prompts
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
class GeminiContext(ExecutionContext):
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


class PolicyViolationError(Exception):
    """Raised when a Gemini request violates governance policy."""

    pass


class GeminiKernel(BaseIntegration):
    """Google Gemini adapter for Agent OS.

    Provides governance for ``GenerativeModel.generate_content()`` calls
    including policy enforcement, tool-call validation, token tracking,
    and audit logging.

    Example:
        >>> kernel = GeminiKernel(policy=GovernancePolicy(max_tokens=8192))
        >>> governed = kernel.wrap(genai.GenerativeModel("gemini-pro"))
        >>> response = governed.generate_content("Explain quantum computing")
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
    ) -> None:
        """Initialise the Gemini governance kernel.

        Args:
            policy: Governance policy to enforce. Uses default when ``None``.
        """
        super().__init__(policy)
        self._wrapped_models: dict[int, Any] = {}
        self._start_time = time.monotonic()
        self._last_error: str | None = None

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
            policy=self.policy,
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

        Validates prompt content against blocked patterns, enforces
        tool-call allowlists, checks token limits, and records an
        audit trail.

        Args:
            contents: The prompt content (string, list, or Content object).
            **kwargs: Forwarded to ``model.generate_content()``.

        Returns:
            The Gemini generation response.

        Raises:
            PolicyViolationError: If a governance policy is violated.
        """
        # --- pre-execution checks ---
        content_str = str(contents)
        allowed, reason = self._kernel.pre_execute(self._ctx, content_str)
        if not allowed:
            raise PolicyViolationError(f"Content blocked: {reason}")

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
            if total > self._kernel.policy.max_tokens:
                raise PolicyViolationError(
                    f"Token limit exceeded: {total} > "
                    f"{self._kernel.policy.max_tokens}"
                )

        # Check for function calls in candidates
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
                call_info = {
                    "name": fn_name,
                    "args": dict(getattr(fn_call, "args", {})),
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

                if self._kernel.policy.require_human_approval:
                    raise PolicyViolationError(
                        f"Tool '{fn_name}' requires human approval per governance policy"
                    )

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
            A dict with ``prompt_tokens``, ``completion_tokens``,
            ``total_tokens``, and ``limit``.
        """
        return {
            "prompt_tokens": self._ctx.prompt_tokens,
            "completion_tokens": self._ctx.completion_tokens,
            "total_tokens": self._ctx.prompt_tokens + self._ctx.completion_tokens,
            "limit": self._kernel.policy.max_tokens,
        }

    def _validate_tools(self, tools: Any) -> None:
        """Validate tool definitions against policy allowlist.

        Args:
            tools: Tool definitions from the request.

        Raises:
            PolicyViolationError: If a tool is not in the allowed list.
        """
        if not self._kernel.policy.allowed_tools:
            return
        tool_list = tools if isinstance(tools, list) else [tools]
        for tool in tool_list:
            declarations = getattr(tool, "function_declarations", None)
            if declarations:
                for decl in declarations:
                    name = getattr(decl, "name", "") if not isinstance(decl, dict) else decl.get("name", "")
                    if name and name not in self._kernel.policy.allowed_tools:
                        raise PolicyViolationError(f"Tool not allowed: {name}")

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying Gemini model."""
        return getattr(self._model, name)


def wrap_model(
    model: Any,
    policy: GovernancePolicy | None = None,
) -> GovernedGeminiModel:
    """Quick wrapper for Gemini GenerativeModel.

    Args:
        model: A ``google.generativeai.GenerativeModel`` instance.
        policy: Optional governance policy.

    Returns:
        A governed model.

    Example:
        >>> from agent_os.integrations.gemini_adapter import wrap_model
        >>> governed = wrap_model(my_model)
        >>> response = governed.generate_content("Hello")
    """
    return GeminiKernel(policy=policy).wrap(model)
