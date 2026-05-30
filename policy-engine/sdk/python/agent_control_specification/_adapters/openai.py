from __future__ import annotations

from collections.abc import AsyncIterable, Awaitable, Callable, Iterable, Mapping
from typing import Any, TypeVar

from .._orchestration import AgentControl
from .._types import EnforcementMode, JsonValue
from ._errors import AdapterUnsupportedError
from ._generic import run_model_call
from ._sse import MAX_STREAM_BYTES, assemble_sse_stream, synthesize_sse_stream
from ._shared import (
    Execute,
    _has_path,
    _merge_snapshot,
    _maybe_await,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _require_callable,
    _resolve_control_and_target,
)

AgentT = TypeVar("AgentT")


def guard_openai_client(
    control_or_client: AgentControl | AgentT,
    client: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard common OpenAI-style async client create methods by duck typing."""

    resolved_control, resolved_client = _resolve_control_and_target(
        control_or_client,
        client,
        control=control,
        target_name="OpenAI-style client",
        adapter_name="guard_openai_client",
    )
    overrides: dict[str, Any] = {}
    if _has_path(resolved_client, ("chat", "completions", "create")):
        completions = resolved_client.chat.completions
        create = completions.create
        completions_proxy = _ObjectProxy(
            completions,
            overrides={
                "create": _guard_call_request_method(
                    resolved_control,
                    create,
                    snapshot=snapshot,
                    mode=mode,
                    streaming_chat_completion=True,
                )
            },
        )
        chat_proxy = _ObjectProxy(resolved_client.chat, overrides={"completions": completions_proxy})
        overrides["chat"] = chat_proxy

    if _has_path(resolved_client, ("responses", "create")):
        responses = resolved_client.responses
        create = responses.create
        overrides["responses"] = _ObjectProxy(
            responses,
            overrides={
                "create": _guard_call_request_method(
                    resolved_control,
                    create,
                    snapshot=snapshot,
                    mode=mode,
                    streaming_unsupported_message=(
                        "OpenAI responses streaming is not guarded because it is not "
                        "a chat-completion SSE shape."
                    ),
                )
            },
        )

    if not overrides:
        raise AdapterUnsupportedError(
            "OpenAI-style adapter requires chat.completions.create or responses.create."
        )
    return _ObjectProxy(resolved_client, overrides=overrides)  # type: ignore[return-value]


def guard_openai_agents_runner(
    control_or_runner: AgentControl | AgentT,
    runner: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard an OpenAI Agents SDK Runner-style async ``run`` method."""

    resolved_control, resolved_runner = _resolve_control_and_target(
        control_or_runner,
        runner,
        control=control,
        target_name="OpenAI Agents Runner-style object",
        adapter_name="guard_openai_agents_runner",
    )
    run = _require_callable(resolved_runner, "run", "OpenAI Agents Runner-style object")
    blocked = {
        name: (
            f"{name} is not guarded by this adapter; use async run() or "
            "AgentControl.run() so input/output controls are enforced."
        )
        for name in ("run_sync", "run_streamed")
        if hasattr(resolved_runner, name)
    }
    return _ObjectProxy(
        resolved_runner,
        overrides={
            "run": _guard_openai_agents_runner_run_method(
                resolved_control,
                run,
                snapshot=snapshot,
                mode=mode,
            )
        },
        blocked=blocked,
    )  # type: ignore[return-value]


def _guard_call_request_method(
    control: AgentControl,
    method: Execute,
    *,
    snapshot: Mapping[str, JsonValue] | None,
    mode: EnforcementMode | str,
    streaming_chat_completion: bool = False,
    streaming_unsupported_message: str | None = None,
) -> Callable[..., Awaitable[JsonValue]]:
    default_snapshot = dict(snapshot or {})

    async def guarded(*args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        model_request = _pack_call_request(args, kwargs)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)
        if _requests_stream(model_request):
            if not streaming_chat_completion:
                raise AdapterUnsupportedError(
                    streaming_unsupported_message
                    or "Streaming is not guarded for this adapter surface."
                )
            return await _guard_raw_sse_chat_completion(
                control,
                method,
                model_request,
                snapshot=merged_snapshot,
                mode=mode,
            )

        async def execute_effective(effective_request: JsonValue) -> JsonValue:
            return await _maybe_await(_invoke_with_call_request(method, effective_request))

        result = await run_model_call(
            control,
            model_request,
            execute_effective,
            snapshot=merged_snapshot,
            mode=mode,
        )
        return result.value

    return guarded


async def _guard_raw_sse_chat_completion(
    control: AgentControl,
    method: Execute,
    model_request: JsonValue,
    *,
    snapshot: Mapping[str, JsonValue],
    mode: EnforcementMode | str,
) -> bytes:
    captured: dict[str, Any] = {}

    async def execute_effective(effective_request: JsonValue) -> JsonValue:
        raw_stream = await _maybe_await(_invoke_with_call_request(method, effective_request))
        raw_sse = await _collect_raw_sse_bytes(raw_stream)
        assembled = assemble_sse_stream(raw_sse)
        captured["raw_sse"] = raw_sse
        captured["assembled"] = assembled
        return assembled

    result = await run_model_call(
        control,
        model_request,
        execute_effective,
        snapshot=snapshot,
        mode=mode,
    )
    post_result = result.post_model_call_result
    applies = (
        EnforcementMode(mode) == EnforcementMode.ENFORCE
        and post_result.verdict.decision.applies_transform
    )
    if not applies or post_result.transformed_policy_target is None:
        return captured["raw_sse"]
    return synthesize_sse_stream(result.value, captured["assembled"])


async def _collect_raw_sse_bytes(stream: Any) -> bytes:
    if isinstance(stream, bytes | bytearray):
        raw = bytes(stream)
        _require_raw_sse_limit(len(raw))
        return raw
    if isinstance(stream, str):
        raw = stream.encode("utf-8")
        _require_raw_sse_limit(len(raw))
        return raw
    if isinstance(stream, AsyncIterable):
        chunks: list[bytes] = []
        total = 0
        async for chunk in stream:
            piece = _raw_sse_piece(chunk)
            total += len(piece)
            _require_raw_sse_limit(total)
            chunks.append(piece)
        return b"".join(chunks)
    if isinstance(stream, Iterable) and not isinstance(stream, Mapping):
        chunks = []
        total = 0
        for chunk in stream:
            piece = _raw_sse_piece(chunk)
            total += len(piece)
            _require_raw_sse_limit(total)
            chunks.append(piece)
        return b"".join(chunks)
    raise AdapterUnsupportedError(
        "OpenAI chat streaming guard requires raw SSE bytes from the client surface."
    )


def _raw_sse_piece(chunk: Any) -> bytes:
    if isinstance(chunk, bytes | bytearray):
        return bytes(chunk)
    if isinstance(chunk, str):
        return chunk.encode("utf-8")
    raise AdapterUnsupportedError(
        "OpenAI chat streaming guard requires every SSE chunk to be bytes or text."
    )


def _require_raw_sse_limit(size: int) -> None:
    if size > MAX_STREAM_BYTES:
        raise AdapterUnsupportedError("Streaming response exceeded the buffering byte limit.")


def _requests_stream(request: JsonValue) -> bool:
    if not isinstance(request, Mapping):
        return False
    if request.get("stream") is True:
        return True
    kwargs = request.get("kwargs")
    if isinstance(kwargs, Mapping) and kwargs.get("stream") is True:
        return True
    args = request.get("args")
    return bool(
        isinstance(args, list | tuple)
        and args
        and isinstance(args[0], Mapping)
        and args[0].get("stream") is True
    )


def _guard_openai_agents_runner_run_method(
    control: AgentControl,
    method: Execute,
    *,
    snapshot: Mapping[str, JsonValue] | None,
    mode: EnforcementMode | str,
) -> Callable[..., Awaitable[JsonValue]]:
    default_snapshot = dict(snapshot or {})

    async def guarded(agent: Any, *args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        policy_target, execute_effective = _runner_policy_target_and_executor(method, agent, args, kwargs)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)
        result = await control.run(
            policy_target,
            execute_effective,
            snapshot=merged_snapshot,
            mode=mode,
        )
        return result.value

    return guarded


def _runner_policy_target_and_executor(
    method: Execute,
    agent: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> tuple[JsonValue, Callable[[JsonValue], Awaitable[JsonValue]]]:
    if args:
        policy_target = args[0]
        rest = args[1:]

        async def execute_effective(effective_policy_target: JsonValue) -> JsonValue:
            return await _maybe_await(method(agent, effective_policy_target, *rest, **kwargs))

        return policy_target, execute_effective

    if "input" in kwargs:
        policy_target = kwargs["input"]

        async def execute_effective(effective_policy_target: JsonValue) -> JsonValue:
            effective_kwargs = dict(kwargs)
            effective_kwargs["input"] = effective_policy_target
            return await _maybe_await(method(agent, **effective_kwargs))

        return policy_target, execute_effective

    raise AdapterUnsupportedError(
        "OpenAI Agents Runner-style run() requires an agent plus a positional input "
        "or input keyword."
    )


def _pack_call_request(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> JsonValue:
    if args:
        return {"args": list(args), "kwargs": dict(kwargs)}
    return dict(kwargs)


def _invoke_with_call_request(method: Execute, request: JsonValue) -> JsonValue | Awaitable[JsonValue]:
    if isinstance(request, Mapping):
        if "args" in request or "kwargs" in request:
            raw_args = request.get("args", [])
            raw_kwargs = request.get("kwargs", {})
            if not isinstance(raw_args, list | tuple) or not isinstance(raw_kwargs, Mapping):
                raise AdapterUnsupportedError(
                    "Transformed call-request envelope must contain list args and mapping kwargs."
                )
            return method(*raw_args, **dict(raw_kwargs))
        return method(**dict(request))
    return method(request)
