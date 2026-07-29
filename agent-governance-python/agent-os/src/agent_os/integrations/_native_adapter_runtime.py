# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native adapter-facing orchestration over ``AdapterRuntimeSession``."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_LOGGER = logging.getLogger(__name__)


class _ContextLike(Protocol):
    agent_id: str
    session_id: str
    call_count: int
    total_tokens: int


class AdapterResult(Protocol):
    evaluation: Any
    transform: Any | None

    @property
    def transformed_value(self) -> Any:
        """Return the materialized policy target after transformation."""

    @property
    def allowed(self) -> bool:
        """Return whether the adapter may continue."""

    @property
    def permits_unchanged(self) -> bool:
        """Return whether the caller may proceed with the value it has."""

    @property
    def point_not_configured(self) -> bool:
        """Return whether the manifest configures this intervention point."""

    @property
    def verdict(self) -> str:
        """Return the native policy verdict."""

    @property
    def reason(self) -> str:
        """Return the normalized reason code."""

    @property
    def input_identity(self) -> str | None:
        """Return the identity of the evaluated input."""

    @property
    def enforced_identity(self) -> str | None:
        """Return the identity of the enforced action."""

    def to_legacy_tuple(self) -> tuple[bool, str]:
        """Return the temporary tuple compatibility shape."""

    @property
    def public_message(self) -> str:
        """Return the sanitized public policy message."""

    def to_policy_violation(self, error_type: Any) -> Exception:
        """Create the canonical policy exception for this result."""


class AdapterRuntime(Protocol):
    runtime: Any

    def evaluate_input(self, *args: Any, **kwargs: Any) -> AdapterResult:
        """Evaluate an input intervention point."""

    def evaluate_pre_tool_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate before a tool call."""

    def evaluate_post_tool_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate after a tool call."""

    def evaluate_pre_model_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate before a model call."""

    def evaluate_post_model_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate after a model call."""

    def evaluate_output(self, *args: Any, **kwargs: Any) -> AdapterResult:
        """Evaluate an output intervention point."""

    def record_post_execute(self, *args: Any, **kwargs: Any) -> None:
        """Record host usage after execution."""


# The engine answers a request naming a point the manifest does not configure
# with this reason. Failing closed is right for a request that names an
# unknown point, but an adapter does not name points on the host's behalf: it
# evaluates output after every call whether or not the manifest asked for
# output governance. See ``permit_if_unconfigured``.
POINT_NOT_CONFIGURED = "runtime_error:intervention_point_unknown"


@dataclass(frozen=True)
class NativeAdapterResult:
    """Adapter decision backed by the native ``PolicyEvaluation`` contract."""

    evaluation: Any
    permit_if_unconfigured: bool = False
    """Whether an unconfigured intervention point permits instead of denying.

    Set only where the adapter evaluates on its own initiative rather than
    because the host asked. It is set for ``output`` and deliberately not for
    ``input`` or ``pre_tool_call``, which stay fail-closed: a manifest that
    omits those omits governance of an action that is about to happen, and
    that must be loud.
    """

    @property
    def point_not_configured(self) -> bool:
        """Whether the manifest leaves this intervention point unconfigured."""
        return self.reason == POINT_NOT_CONFIGURED

    @property
    def allowed(self) -> bool:
        if self.permit_if_unconfigured and self.point_not_configured:
            return True
        return bool(self.evaluation.is_allowed())

    @property
    def verdict(self) -> str:
        return str(self.evaluation.verdict)

    @property
    def reason(self) -> str:
        reason = str(self.evaluation.reason_code or "")
        return reason.removeprefix("policy:")

    @property
    def input_identity(self) -> str | None:
        return self.evaluation.input_identity

    @property
    def enforced_identity(self) -> str | None:
        return self.evaluation.enforced_identity

    @property
    def transform(self) -> Any | None:
        return self.evaluation.transform

    @property
    def permits_unchanged(self) -> bool:
        """Whether the caller may proceed with the value it already has.

        ``allowed`` is true for ``transform``, but a transform carries a
        replacement the caller is expected to apply. A site that cannot apply
        one must gate on this instead, or it runs the original value while the
        policy believed it had been rewritten, and a redaction policy silently
        does not redact.
        """
        return self.allowed and self.transform is None

    @property
    def transformed_value(self) -> Any:
        transform = self.transform
        if transform is None:
            return None
        applied_value = getattr(transform, "applied_value", None)
        return applied_value if applied_value is not None else transform.value

    @property
    def public_message(self) -> str:
        return str(self.evaluation.public_error_message())

    def to_policy_violation(self, error_type: Any) -> Exception:
        return error_type.from_evaluation_result(self.evaluation)

    def to_legacy_tuple(self) -> tuple[bool, str]:
        return self.allowed, self.reason


class NativeAdapterRuntime:
    """Shared native runtime/session seam for framework adapters."""

    def __init__(self, runtime: Any) -> None:
        if runtime is None:
            raise TypeError("NativeAdapterRuntime requires AgtRuntime")
        self._runtime = runtime
        self._sessions: dict[str, Any] = {}
        self._unconfigured_logged: set[str] = set()

    @property
    def runtime(self) -> Any:
        return self._runtime

    def _session_for(self, ctx: _ContextLike) -> Any:
        from agt.policies.session import AdapterRuntimeSession

        key = ctx.session_id or ctx.agent_id
        session = self._sessions.get(key)
        if session is None:
            session = AdapterRuntimeSession(
                self._runtime,
                agent_id=ctx.agent_id,
                session_id=ctx.session_id or f"{ctx.agent_id}-session",
            )
            self._sessions[key] = session
        session.synchronize_counters(
            tool_call_count=int(ctx.call_count),
            token_count=int(ctx.total_tokens),
        )
        return session

    def record_post_execute(
        self,
        ctx: _ContextLike,
        *,
        tokens: int = 0,
        tool_calls: int = 0,
    ) -> None:
        """Record tokens while avoiding a second native attempted-call charge."""
        del tool_calls
        self._session_for(ctx).record_usage(tokens=int(tokens))

    def evaluate_input(
        self,
        ctx: _ContextLike,
        *,
        body: Any,
        source: str = "user",
        headers: dict[str, str] | None = None,
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate_input(
            body=body if isinstance(body, str | dict) else str(body),
            source=source,
            headers=headers,
        )
        return NativeAdapterResult(evaluation)

    def evaluate_pre_tool_call(
        self,
        ctx: _ContextLike,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        call_id: str = "call-1",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate_pre_tool_call(
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )
        return NativeAdapterResult(evaluation)

    def evaluate_post_tool_call(
        self,
        ctx: _ContextLike,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str = "call-1",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate_post_tool_call(
            tool_name=tool_name,
            args=args,
            result=result,
            error=error,
            duration_ms=duration_ms,
            call_id=call_id,
        )
        return self._post_hoc_result(evaluation, "post_tool_call")

    def evaluate_pre_model_call(
        self,
        ctx: _ContextLike,
        *,
        model_name: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate_pre_model_call(
            model_name=model_name,
            messages=messages,
            tools=tools,
            request_id=request_id,
            model_vendor=model_vendor,
        )
        return NativeAdapterResult(evaluation)

    def evaluate_post_model_call(
        self,
        ctx: _ContextLike,
        *,
        model_name: str,
        response: dict[str, Any],
        usage: dict[str, int] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate_post_model_call(
            model_name=model_name,
            response=response,
            usage=usage,
            request_id=request_id,
            model_vendor=model_vendor,
        )
        return self._post_hoc_result(evaluation, "post_model_call")

    def evaluate_output(
        self,
        ctx: _ContextLike,
        *,
        content: Any,
        message_chain: list[dict[str, Any]] | None = None,
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate_output(
            content=content if isinstance(content, str | dict) else str(content),
            message_chain=message_chain,
        )
        return self._post_hoc_result(evaluation, "output")

    def _post_hoc_result(self, evaluation: Any, point: str) -> NativeAdapterResult:
        """Wrap a verdict for a point evaluated after the action happened.

        A post-hoc point cannot prevent anything: the tool ran, the model
        answered. Refusing an unconfigured one therefore protects nothing and
        only breaks the caller, so it permits and says so. The pre-points keep
        denying, because there the action has not happened yet.
        """
        result = NativeAdapterResult(evaluation, permit_if_unconfigured=True)
        if result.point_not_configured and point not in self._unconfigured_logged:
            self._unconfigured_logged.add(point)
            _LOGGER.warning(
                "manifest configures no '%s' intervention point; it is a "
                "post-hoc point, so the value is forwarded without policy "
                "evaluation (reason=%s). Bind '%s' in the manifest to "
                "enforce it.",
                point,
                POINT_NOT_CONFIGURED,
                point,
            )
        return result

__all__ = [
    "AdapterResult",
    "AdapterRuntime",
    "NativeAdapterResult",
    "NativeAdapterRuntime",
]
