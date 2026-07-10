# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Session-scoped host orchestration over a stateless :class:`AgtRuntime`."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from .manifest import AdapterManifestContract, AgtManifest
from .result import PolicyEvaluation
from .snapshot import SnapshotBuilder


class _RuntimeLike(Protocol):
    manifest: AgtManifest | None

    def evaluate(
        self, intervention_point: str, snapshot: Mapping[str, Any]
    ) -> PolicyEvaluation: ...

    def close(self) -> None: ...


class AdapterRuntimeSession:
    """Own one session's snapshots and budget counters.

    The runtime remains stateless and may be shared across sessions when its
    host dispatchers and approval callback are thread-safe. This object is the
    sole owner of session counters. Tool-call budget is charged after every
    attempted ``pre_tool_call`` evaluation, including denied or failed
    attempts, so the next evaluation sees the consumed attempt.
    """

    def __init__(
        self,
        runtime: _RuntimeLike,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        builder: SnapshotBuilder | None = None,
        contract: AdapterManifestContract | None = None,
        owns_runtime: bool = False,
    ) -> None:
        if builder is None:
            if not agent_id or not session_id:
                raise ValueError(
                    "agent_id and session_id are required when builder is omitted"
                )
            builder = SnapshotBuilder(agent_id=agent_id, session_id=session_id)
        elif agent_id is not None or session_id is not None:
            raise ValueError("pass builder or agent_id/session_id, not both")

        if contract is not None:
            if runtime.manifest is None:
                raise ValueError(
                    "adapter preflight requires a runtime created by "
                    "AgtRuntime.from_manifest"
                )
            runtime.manifest.validate_for(contract)

        self._runtime = runtime
        self._builder = builder
        self._contract = contract
        self._owns_runtime = owns_runtime
        self._lock = threading.RLock()
        self._closed = False

    @property
    def runtime(self) -> _RuntimeLike:
        return self._runtime

    @property
    def builder(self) -> SnapshotBuilder:
        return self._builder

    @property
    def contract(self) -> AdapterManifestContract | None:
        return self._contract

    def synchronize_counters(
        self,
        *,
        tool_call_count: int | None = None,
        token_count: int | None = None,
        elapsed_seconds: float | None = None,
        cost_usd: float | None = None,
    ) -> None:
        """Raise local counters to host-observed values without moving backward."""
        with self._lock:
            self._ensure_open()
            if tool_call_count is not None:
                _validate_non_negative_int("tool_call_count", tool_call_count)
                self._builder.tool_call_count = max(
                    self._builder.tool_call_count, tool_call_count
                )
            if token_count is not None:
                _validate_non_negative_int("token_count", token_count)
                self._builder.token_count = max(
                    self._builder.token_count, token_count
                )
            if elapsed_seconds is not None:
                _validate_non_negative_number("elapsed_seconds", elapsed_seconds)
                self._builder.elapsed_seconds = max(
                    self._builder.elapsed_seconds, float(elapsed_seconds)
                )
            if cost_usd is not None:
                _validate_non_negative_number("cost_usd", cost_usd)
                self._builder.cost_usd = max(
                    self._builder.cost_usd, float(cost_usd)
                )

    def record_usage(
        self,
        *,
        tokens: int = 0,
        tool_calls: int = 0,
        elapsed_seconds: float = 0.0,
        cost_usd: float = 0.0,
    ) -> None:
        """Record host-observed usage that was not charged by an IP helper."""
        _validate_non_negative_int("tokens", tokens)
        _validate_non_negative_int("tool_calls", tool_calls)
        _validate_non_negative_number("elapsed_seconds", elapsed_seconds)
        _validate_non_negative_number("cost_usd", cost_usd)
        with self._lock:
            self._ensure_open()
            if tool_calls:
                self._builder.record_tool_call(tool_calls)
            if tokens:
                self._builder.record_tokens(tokens)
            if elapsed_seconds:
                self._builder.record_elapsed(elapsed_seconds)
            if cost_usd:
                self._builder.record_cost(cost_usd)

    def evaluate_snapshot(
        self, intervention_point: str, snapshot: Mapping[str, Any]
    ) -> PolicyEvaluation:
        """Evaluate a custom snapshot through the native result contract."""
        with self._lock:
            self._ensure_open()
        return self._runtime.evaluate(intervention_point, snapshot)

    def evaluate_agent_startup(
        self,
        *,
        capabilities: Iterable[str] = (),
        model_name: str = "",
        model_vendor: str = "test",
        tools_registered: Iterable[str] = (),
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.agent_startup(
                capabilities=capabilities,
                model_name=model_name,
                model_vendor=model_vendor,
                tools_registered=tools_registered,
            )
        return self._runtime.evaluate("agent_startup", snapshot)

    def evaluate_input(
        self,
        *,
        body: str | dict[str, Any],
        source: str = "user",
        headers: dict[str, str] | None = None,
        source_labels: Iterable[str] = (),
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.input(
                body=body,
                source=source,
                headers=headers,
                source_labels=source_labels,
            )
        return self._runtime.evaluate("input", snapshot)

    def evaluate_pre_model_call(
        self,
        *,
        model_name: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
        model_params: dict[str, Any] | None = None,
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.pre_model_call(
                model_name=model_name,
                messages=messages,
                tools=tools,
                request_id=request_id,
                model_vendor=model_vendor,
                model_params=model_params,
            )
        return self._runtime.evaluate("pre_model_call", snapshot)

    def evaluate_post_model_call(
        self,
        *,
        model_name: str,
        response: dict[str, Any],
        usage: dict[str, int] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
        charge_usage: bool = True,
    ) -> PolicyEvaluation:
        tokens_to_charge = _usage_tokens(usage) if charge_usage else 0
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.post_model_call(
                model_name=model_name,
                response=response,
                usage=usage,
                request_id=request_id,
                model_vendor=model_vendor,
            )
        try:
            return self._runtime.evaluate("post_model_call", snapshot)
        finally:
            if tokens_to_charge:
                with self._lock:
                    if not self._closed:
                        self._builder.record_tokens(tokens_to_charge)

    def evaluate_pre_tool_call(
        self,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        call_id: str = "call-1",
        content_hash: str | None = None,
        count_attempt: bool = True,
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.pre_tool_call(
                tool_name=tool_name,
                args=dict(args),
                call_id=call_id,
                content_hash=content_hash,
            )
            if count_attempt:
                self._builder.record_tool_call()
        return self._runtime.evaluate("pre_tool_call", snapshot)

    def evaluate_post_tool_call(
        self,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str = "call-1",
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.post_tool_call(
                tool_name=tool_name,
                args=dict(args),
                result=result,
                error=error,
                duration_ms=duration_ms,
                call_id=call_id,
            )
        return self._runtime.evaluate("post_tool_call", snapshot)

    def evaluate_output(
        self,
        *,
        content: str | dict[str, Any],
        message_chain: list[dict[str, Any]] | None = None,
        result_labels: Iterable[str] = (),
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.output(
                content=content,
                message_chain=message_chain,
                result_labels=result_labels,
            )
        return self._runtime.evaluate("output", snapshot)

    def evaluate_agent_shutdown(
        self,
        *,
        tool_calls: int | None = None,
        tokens: int | None = None,
        errors: int = 0,
        duration_seconds: float | None = None,
    ) -> PolicyEvaluation:
        with self._lock:
            self._ensure_open()
            snapshot = self._builder.agent_shutdown(
                tool_calls=tool_calls,
                tokens=tokens,
                errors=errors,
                duration_seconds=duration_seconds,
            )
        return self._runtime.evaluate("agent_shutdown", snapshot)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._owns_runtime:
                self._runtime.close()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("AdapterRuntimeSession is closed")


def _usage_tokens(usage: Mapping[str, int] | None) -> int:
    if not usage:
        return 0
    if "total_tokens" in usage:
        value = usage["total_tokens"]
        _validate_non_negative_int("total_tokens", value)
        return value
    if "input_tokens" in usage or "output_tokens" in usage:
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        _validate_non_negative_int("input_tokens", input_tokens)
        _validate_non_negative_int("output_tokens", output_tokens)
        return input_tokens + output_tokens
    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)
    _validate_non_negative_int("prompt_tokens", prompt_tokens)
    _validate_non_negative_int("completion_tokens", completion_tokens)
    return prompt_tokens + completion_tokens


def _validate_non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _validate_non_negative_number(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{name} must be a non-negative number")


__all__ = ["AdapterRuntimeSession"]
