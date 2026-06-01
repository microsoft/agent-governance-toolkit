from __future__ import annotations

import copy
import json
from dataclasses import is_dataclass, replace as dataclass_replace
from collections.abc import AsyncIterable, Awaitable, Callable, Iterable, Mapping
from typing import Any, TypeVar

from .._orchestration import AgentControl
from .._types import EnforcementMode, InterventionPoint, JsonValue
from ._errors import AdapterUnsupportedError
from ._generic import run_model_call
from ._sse import MAX_STREAM_BYTES, assemble_sse_stream, synthesize_sse_stream
from ._shared import (
    Execute,
    _has_path,
    _jsonable,
    _merge_snapshot,
    _maybe_await,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _require_callable,
    _resolve_control_and_target,
    _transformed_or,
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

        captured: dict[str, Any] = {}

        async def execute_effective(effective_request: JsonValue) -> JsonValue:
            raw_response = await _maybe_await(_invoke_with_call_request(method, effective_request))
            captured["raw_response"] = raw_response
            return _jsonable(raw_response)

        result = await run_model_call(
            control,
            model_request,
            execute_effective,
            snapshot=merged_snapshot,
            mode=mode,
        )
        raw_response = captured.get("raw_response")
        if raw_response is None:
            return result.value
        if not _post_model_effect_applied(result.post_model_call_result, mode):
            return raw_response
        response_value = _response_value_for_policy_target(
            raw_response,
            result.value,
            result.post_model_call_result,
        )
        return _restore_response_shape(raw_response, response_value)

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
    if not applies or (
        post_result.transformed_policy_target is None
        and not post_result.transformed_policy_target_applied
    ):
        return captured["raw_sse"]
    response_value = _response_value_for_policy_target(
        captured["assembled"],
        result.value,
        post_result,
    )
    return synthesize_sse_stream(response_value, captured["assembled"])


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
        structured = False
        async for chunk in stream:
            piece, is_structured = _raw_sse_piece(chunk)
            structured = _update_structured_mode(structured, is_structured, bool(chunks))
            total += len(piece)
            _require_raw_sse_limit(total)
            chunks.append(piece)
        if structured:
            chunks.append(_sse_frame("[DONE]"))
        return b"".join(chunks)
    if isinstance(stream, Iterable) and not isinstance(stream, Mapping):
        chunks = []
        total = 0
        structured = False
        for chunk in stream:
            piece, is_structured = _raw_sse_piece(chunk)
            structured = _update_structured_mode(structured, is_structured, bool(chunks))
            total += len(piece)
            _require_raw_sse_limit(total)
            chunks.append(piece)
        if structured:
            chunks.append(_sse_frame("[DONE]"))
        return b"".join(chunks)
    raise AdapterUnsupportedError(
        "OpenAI chat streaming guard requires raw SSE bytes from the client surface."
    )


def _raw_sse_piece(chunk: Any) -> tuple[bytes, bool]:
    if isinstance(chunk, bytes | bytearray):
        return bytes(chunk), False
    if isinstance(chunk, str):
        return chunk.encode("utf-8"), False
    value = _jsonable(chunk)
    if isinstance(value, Mapping):
        return _sse_frame(json.dumps(value, separators=(",", ":"), ensure_ascii=False)), True
    raise AdapterUnsupportedError(
        "OpenAI chat streaming guard requires every chunk to be bytes, text, or a JSON object."
    )


def _update_structured_mode(structured: bool, is_structured: bool, has_previous: bool) -> bool:
    if has_previous and structured != is_structured:
        raise AdapterUnsupportedError("OpenAI chat streaming guard cannot mix raw SSE and object chunks.")
    return structured or is_structured


def _sse_frame(data: str) -> bytes:
    return f"data: {data}\n\n".encode("utf-8")


def _require_raw_sse_limit(size: int) -> None:
    if size > MAX_STREAM_BYTES:
        raise AdapterUnsupportedError("Streaming response exceeded the buffering byte limit.")


def _post_model_effect_applied(result: Any, mode: EnforcementMode | str) -> bool:
    return _effect_applied(result, mode)


def _effect_applied(result: Any, mode: EnforcementMode | str) -> bool:
    return (
        EnforcementMode(mode) == EnforcementMode.ENFORCE
        and result.verdict.decision.applies_effects
        and (result.transformed_policy_target_applied or result.transformed_policy_target is not None)
    )


def _restore_response_shape(original: Any, value: JsonValue) -> JsonValue:
    if isinstance(original, Mapping) or not isinstance(value, Mapping):
        return value
    for factory_name in ("model_validate", "parse_obj"):
        factory = getattr(original.__class__, factory_name, None)
        if callable(factory):
            try:
                return factory(value)
            except Exception:  # noqa: BLE001
                pass
    try:
        return original.__class__(**value)
    except Exception:  # noqa: BLE001
        return value


def _response_value_for_policy_target(
    original: Any,
    transformed: JsonValue,
    result: Any,
) -> JsonValue:
    response = _jsonable(original)
    path = _policy_target_path(result)
    relative = _model_response_relative_path(path)
    if relative is None:
        return transformed
    if not relative:
        return transformed
    if _set_relative_json_path(response, relative, transformed):
        return response
    return transformed


def _policy_target_path(result: Any) -> str | None:
    policy_input = getattr(result, "policy_input", None)
    if not isinstance(policy_input, Mapping):
        return None
    policy_target = policy_input.get("policy_target")
    if not isinstance(policy_target, Mapping):
        return None
    path = policy_target.get("path")
    return path if isinstance(path, str) else None


def _model_response_relative_path(path: str | None) -> str | None:
    if path is None:
        return None
    for prefix in ("$.model_response", "$snap.model_response"):
        if path == prefix:
            return ""
        if path.startswith(prefix + ".") or path.startswith(prefix + "["):
            return path[len(prefix):]
    return None


def _set_relative_json_path(root: JsonValue, path: str, value: JsonValue) -> bool:
    segments = _relative_path_segments(path)
    if not segments:
        return False
    current = root
    for segment in segments[:-1]:
        match segment:
            case str():
                if not isinstance(current, Mapping):
                    return False
                if segment not in current:
                    return False
                current = current[segment]
            case int():
                if not isinstance(current, list) or segment < 0 or segment >= len(current):
                    return False
                current = current[segment]
            case _:
                return False

    last = segments[-1]
    if isinstance(last, str) and isinstance(current, dict) and last in current:
        current[last] = value
        return True
    if isinstance(last, int) and isinstance(current, list) and 0 <= last < len(current):
        current[last] = value
        return True
    return False


def _relative_path_segments(path: str) -> list[str | int]:
    segments: list[str | int] = []
    index = 0
    while index < len(path):
        if path[index] == ".":
            index += 1
            start = index
            while index < len(path) and path[index] not in ".[":
                index += 1
            if start == index:
                return []
            segments.append(path[start:index])
        elif path[index] == "[":
            end = path.find("]", index)
            if end == -1:
                return []
            try:
                segments.append(int(path[index + 1:end]))
            except ValueError:
                return []
            index = end + 1
        else:
            return []
    return segments


def _runner_output_value(output: Any) -> JsonValue:
    if hasattr(output, "final_output"):
        return getattr(output, "final_output")
    return output


def _restore_runner_output(
    original: Any,
    value: JsonValue,
    result: Any,
    mode: EnforcementMode | str,
) -> JsonValue:
    if not hasattr(original, "final_output"):
        return value
    if not _effect_applied(result, mode):
        return original

    model_copy = getattr(original, "model_copy", None)
    if callable(model_copy):
        try:
            return model_copy(update={"final_output": value})
        except Exception:  # noqa: BLE001
            pass

    if is_dataclass(original):
        try:
            return dataclass_replace(original, final_output=value)
        except Exception:  # noqa: BLE001
            pass

    try:
        cloned = copy.copy(original)
        setattr(cloned, "final_output", value)
        return cloned
    except Exception:  # noqa: BLE001
        pass

    try:
        setattr(original, "final_output", value)
        return original
    except Exception:  # noqa: BLE001
        return value


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
        enforcement_mode = EnforcementMode(mode)

        input_result = await control.evaluate_intervention_point(
            InterventionPoint.INPUT,
            {**merged_snapshot, "input": policy_target},
            enforcement_mode,
        )
        await control.enforce(InterventionPoint.INPUT, input_result, enforcement_mode)
        effective_input = _transformed_or(input_result, policy_target, enforcement_mode)

        raw_output = await execute_effective(effective_input)
        output_value = _runner_output_value(raw_output)
        output_result = await control.evaluate_intervention_point(
            InterventionPoint.OUTPUT,
            {**merged_snapshot, "input": effective_input, "output": output_value},
            enforcement_mode,
        )
        await control.enforce(InterventionPoint.OUTPUT, output_result, enforcement_mode)
        effective_output = _transformed_or(output_result, output_value, enforcement_mode)
        return _restore_runner_output(raw_output, effective_output, output_result, enforcement_mode)

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
