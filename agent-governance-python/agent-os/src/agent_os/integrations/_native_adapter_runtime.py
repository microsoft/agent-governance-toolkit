# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native adapter-facing orchestration over ``AdapterRuntimeSession``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


class _ContextLike(Protocol):
    agent_id: str
    session_id: str
    call_count: int
    total_tokens: int


class AdapterResult(Protocol):
    evaluation: Any
    transform: Any | None

    @property
    def allowed(self) -> bool: ...

    @property
    def verdict(self) -> str: ...

    @property
    def reason(self) -> str: ...

    @property
    def input_identity(self) -> str | None: ...

    @property
    def enforced_identity(self) -> str | None: ...

    def to_legacy_tuple(self) -> tuple[bool, str]: ...

    @property
    def public_message(self) -> str: ...

    def to_policy_violation(self, error_type: Any) -> Exception: ...


class AdapterRuntime(Protocol):
    runtime: Any

    def evaluate_input(self, *args: Any, **kwargs: Any) -> AdapterResult: ...

    def evaluate_pre_tool_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult: ...

    def evaluate_post_tool_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult: ...

    def evaluate_pre_model_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult: ...

    def evaluate_post_model_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult: ...

    def evaluate_output(self, *args: Any, **kwargs: Any) -> AdapterResult: ...

    def record_post_execute(self, *args: Any, **kwargs: Any) -> None: ...


@dataclass(frozen=True)
class NativeAdapterResult:
    """Adapter decision backed by the native ``PolicyEvaluation`` contract."""

    evaluation: Any

    @property
    def allowed(self) -> bool:
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
        return NativeAdapterResult(evaluation)

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
        return NativeAdapterResult(evaluation)

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
        return NativeAdapterResult(evaluation)

__all__ = [
    "AdapterResult",
    "AdapterRuntime",
    "NativeAdapterResult",
    "NativeAdapterRuntime",
]
