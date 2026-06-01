from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import import_module
from typing import Any

from .._orchestration import AgentControl
from .._types import (
    AgentControlBlocked,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    JsonValue,
)
from ._errors import AdapterUnsupportedError
from ._generic import run_model_call
from ._shared import (
    Execute,
    _body_bytes,
    _capture_asgi_send,
    _decode_json_body,
    _encode_json_body,
    _jsonable,
    _maybe_await,
    _read_asgi_body,
    _resolve_control_and_target,
    _response_json_from_asgi_messages,
    _scope_with_content_length,
    _send_json_asgi_response,
    _single_body_receive,
)
from ._sse import assemble_sse_stream, synthesize_sse_stream


# Optional LiteLLM guardrail base. The SDK remains importable without the
# proxy extra, while a real proxy deployment gets LiteLLM metadata support.
try:  # pragma: no cover - exercised when litellm is installed
    from litellm.integrations.custom_guardrail import (
        CustomGuardrail as _LiteLLMCustomGuardrail,
    )
    from litellm.types.guardrails import (
        GuardrailEventHooks as _LiteLLMGuardrailEventHooks,
    )
except ImportError:  # pragma: no cover - default dependency-free test path
    _LiteLLMCustomGuardrail = object
    _LiteLLMGuardrailEventHooks = None

_EVENT_STREAM_MEDIA_TYPE = b"text/event-stream"


class LiteLLMProxyMiddleware:
    """ASGI-ish LiteLLM proxy middleware with no LiteLLM dependency."""

    DEFAULT_PATHS = (
        "/chat/completions",
        "/completions",
        "/embeddings",
        "/messages",
        "/responses",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/messages",
        "/v1/responses",
    )

    # Streaming is only assembled for chat-completions; other schemas
    # fail closed rather than risk a wrong reconstruction.
    STREAMING_PATHS = ("/chat/completions", "/v1/chat/completions")

    def __init__(
        self,
        control: AgentControl,
        app: Any,
        *,
        snapshot: Mapping[str, JsonValue] | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        paths: tuple[str, ...] | None = None,
    ) -> None:
        self.control = control
        self.app = app
        self.snapshot = dict(snapshot or {})
        self.mode = mode
        self.paths = tuple(paths or self.DEFAULT_PATHS)

    async def __call__(self, scope: Mapping[str, Any], receive: Execute, send: Execute) -> None:
        if not _is_guarded_litellm_scope(scope, self.paths):
            await _maybe_await(self.app(scope, receive, send))
            return

        raw_body = await _read_asgi_body(receive)
        model_request = _decode_json_body(raw_body, "LiteLLM proxy request")
        ambient = self._ambient_snapshot(scope)

        if isinstance(model_request, Mapping) and model_request.get("stream") is True:
            await self._guard_streaming(scope, model_request, ambient, send)
            return

        await self._guard_json(scope, model_request, ambient, send)

    def _ambient_snapshot(self, scope: Mapping[str, Any]) -> dict[str, JsonValue]:
        return {
            **self.snapshot,
            "transport": {
                "adapter": "litellm_proxy",
                "method": str(scope.get("method", "")).upper(),
                "path": scope.get("path"),
            },
        }

    async def _guard_json(
        self,
        scope: Mapping[str, Any],
        model_request: JsonValue,
        ambient: Mapping[str, JsonValue],
        send: Execute,
    ) -> None:
        captured_messages: list[dict[str, Any]] = []

        async def execute_effective(effective_request: JsonValue) -> JsonValue:
            body = _encode_json_body(effective_request)
            replay_scope = _scope_with_content_length(scope, len(body))
            captured_messages.clear()
            await _maybe_await(
                self.app(
                    replay_scope,
                    _single_body_receive(body),
                    _capture_asgi_send(captured_messages),
                )
            )
            return _response_json_from_asgi_messages(captured_messages)

        result = await run_model_call(
            self.control,
            model_request,
            execute_effective,
            snapshot=ambient,
            mode=self.mode,
        )
        await _send_json_asgi_response(send, captured_messages, result.value)

    async def _guard_streaming(
        self,
        scope: Mapping[str, Any],
        model_request: JsonValue,
        ambient: Mapping[str, JsonValue],
        send: Execute,
    ) -> None:
        if scope.get("path") not in self.STREAMING_PATHS:
            raise AdapterUnsupportedError(
                "Streaming responses are only guarded on chat-completions paths; "
                "disable stream or wrap the model call explicitly with guard_model_call()."
            )

        captured: dict[str, Any] = {}

        async def execute_effective(effective_request: JsonValue) -> JsonValue:
            body = _encode_json_body(effective_request)
            replay_scope = _scope_with_content_length(scope, len(body))
            messages: list[dict[str, Any]] = []
            await _maybe_await(
                self.app(replay_scope, _single_body_receive(body), _capture_asgi_send(messages))
            )
            start = _require_event_stream(messages)
            raw_sse = b"".join(
                _body_bytes(message)
                for message in messages
                if message.get("type") == "http.response.body"
            )
            assembled = assemble_sse_stream(raw_sse)
            captured["start"] = start
            captured["raw_sse"] = raw_sse
            captured["assembled"] = assembled
            return assembled

        result = await run_model_call(
            self.control,
            model_request,
            execute_effective,
            snapshot=ambient,
            mode=self.mode,
        )

        post_result = result.post_model_call_result
        applies = (
            EnforcementMode(self.mode) == EnforcementMode.ENFORCE
            and post_result.verdict.decision.applies_transform
        )
        if not applies or (
            post_result.transformed_policy_target is None
            and not post_result.transformed_policy_target_applied
        ):
            await _send_sse(send, captured["start"], captured["raw_sse"])
        else:
            body = synthesize_sse_stream(result.value, captured["assembled"])
            await _send_sse(send, _event_stream_start(captured["start"]), body)


def guard_litellm_proxy(
    control_or_app: AgentControl | Any | None = None,
    app: Any = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    paths: tuple[str, ...] | None = None,
) -> LiteLLMProxyMiddleware:
    """Return ASGI middleware for LiteLLM proxy JSON calls.

    This adapter targets the LiteLLM proxy server app. Install proxy support with
    ``pip install 'litellm[proxy]'``. Pass ``litellm.proxy.proxy_server.app``
    explicitly, or omit the app to load it lazily. LiteLLM proxy rejects
    client-supplied ``api_base`` and credentials unless its proxy settings allow
    client-side credentials.
    """

    if isinstance(control_or_app, AgentControl) and app is None:
        app = _load_litellm_proxy_app()
    elif control_or_app is None and control is not None and app is None:
        control_or_app = _load_litellm_proxy_app()

    resolved_control, resolved_app = _resolve_control_and_target(
        control_or_app,
        app,
        control=control,
        target_name="ASGI app callable",
        adapter_name="guard_litellm_proxy",
    )
    if not callable(resolved_app):
        raise AdapterUnsupportedError(
            "guard_litellm_proxy() requires an ASGI app callable."
        )
    return LiteLLMProxyMiddleware(
        resolved_control,
        resolved_app,
        snapshot=snapshot,
        mode=mode,
        paths=paths,
    )


def _load_litellm_proxy_app() -> Any:
    try:
        proxy_server = import_module("litellm.proxy.proxy_server")
    except ImportError as exc:
        raise ImportError(
            "guard_litellm_proxy requires the LiteLLM proxy server. "
            "Install it with: pip install 'litellm[proxy]'"
        ) from exc
    return getattr(proxy_server, "app", None)


def _is_guarded_litellm_scope(scope: Mapping[str, Any], paths: tuple[str, ...]) -> bool:
    return (
        scope.get("type") == "http"
        and str(scope.get("method", "")).upper() == "POST"
        and scope.get("path") in paths
    )


def _require_event_stream(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Fail closed unless the upstream returned a 2xx event-stream response."""

    start = next(
        (message for message in messages if message.get("type") == "http.response.start"),
        None,
    )
    if start is None:
        raise AdapterUnsupportedError("Streaming upstream sent no response start.")
    status = start.get("status", 200)
    if not isinstance(status, int) or not 200 <= status < 300:
        raise AdapterUnsupportedError("Streaming upstream returned a non-success status.")
    media_type = b"".join(
        value if isinstance(value, bytes) else str(value).encode("latin-1")
        for name, value in start.get("headers", [])
        if (name if isinstance(name, bytes) else str(name).encode("latin-1")).lower()
        == b"content-type"
    )
    if _EVENT_STREAM_MEDIA_TYPE not in media_type:
        raise AdapterUnsupportedError("Streaming upstream response was not text/event-stream.")
    return start


def _event_stream_start(start: Mapping[str, Any]) -> dict[str, Any]:
    """A fresh SSE response start without stale content-length/encoding."""

    return {
        "type": "http.response.start",
        "status": start.get("status", 200),
        "headers": [
            (b"content-type", _EVENT_STREAM_MEDIA_TYPE),
            (b"cache-control", b"no-cache"),
        ],
    }


async def _send_sse(send: Execute, start: Mapping[str, Any], body: bytes) -> None:
    await _maybe_await(send(dict(start)))
    await _maybe_await(send({"type": "http.response.body", "body": body, "more_body": False}))


class AgentControlLiteLLMGuardrail(_LiteLLMCustomGuardrail):
    """LiteLLM Proxy guardrail hook backed by an ACS manifest or control."""

    def __init__(
        self,
        control: AgentControl | None = None,
        *,
        manifest_path: str | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        snapshot: Mapping[str, JsonValue] | None = None,
        guardrail_name: str = "agent_control_specification",
        session_cache_size: int = 512,
        session_ttl_seconds: float = 1800.0,
        streaming: str = "buffer",
        reject_unknown_tool_results: bool = True,
        **kwargs: Any,
    ) -> None:
        if control is None and manifest_path is None:
            raise ValueError("AgentControlLiteLLMGuardrail requires control= or manifest_path=.")
        if control is not None and manifest_path is not None:
            raise ValueError("Pass either control= or manifest_path=, not both.")
        if streaming not in {"buffer", "fail_closed", "evaluate_only"}:
            raise ValueError("streaming must be 'buffer', 'fail_closed', or 'evaluate_only'.")
        if _LiteLLMGuardrailEventHooks is not None:
            kwargs.setdefault(
                "supported_event_hooks",
                [_LiteLLMGuardrailEventHooks.pre_call, _LiteLLMGuardrailEventHooks.post_call],
            )
        if _LiteLLMCustomGuardrail is object:
            super().__init__()
        else:
            super().__init__(guardrail_name=guardrail_name, **kwargs)
        self.control = control
        self.manifest_path = manifest_path
        self.mode = EnforcementMode(mode)
        self.snapshot = dict(snapshot or {})
        self.guardrail_name = guardrail_name
        self.streaming = streaming
        self.reject_unknown_tool_results = reject_unknown_tool_results
        self._sessions = _LiteLLMSessionCache(session_cache_size, session_ttl_seconds)

    def _control(self) -> AgentControl:
        if self.control is None:
            if self.manifest_path is None:
                raise RuntimeError("AgentControlLiteLLMGuardrail has no manifest path.")
            self.control = AgentControl.from_path(self.manifest_path)
        return self.control

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: Any,
    ) -> dict:
        if not isinstance(data, dict):
            return data
        mode = self.mode
        messages = data.get("messages")
        if not isinstance(messages, list) or not messages:
            return await self._evaluate_pre_model(data, mode)
        sid = _litellm_session_id(data)
        async with self._sessions.locked(sid) as session:
            trailing_role = _message_role(messages[-1])
            if trailing_role == "user":
                await self._evaluate_input(data, messages, mode)
            elif trailing_role == "tool":
                await self._evaluate_trailing_tool_results(session, data, messages, mode)
            elif trailing_role == "assistant" and self.reject_unknown_tool_results:
                _raise_litellm_block("acs_litellm_terminal_assistant", "LiteLLM request ended with an assistant message that ACS cannot map to input or post_tool_call.")
            return await self._evaluate_pre_model(data, mode)

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        return await self._post_call_success(data, response, self.mode)

    async def _post_call_success(self, data: dict, response: Any, mode: EnforcementMode) -> Any:
        sid = _litellm_session_id(data if isinstance(data, dict) else {})
        async with self._sessions.locked(sid) as session:
            response = await self._evaluate_post_model(data, response, mode)
            tool_calls = _response_tool_calls(response)
            if tool_calls:
                await self._evaluate_tool_calls(session, data, response, tool_calls, mode)
                return response
            return await self._evaluate_output(data, response, mode)

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ) -> Any:
        if self.streaming == "fail_closed" and self.mode == EnforcementMode.ENFORCE:
            _raise_litellm_block("acs_litellm_streaming_unsupported", "ACS LiteLLM streaming is configured to fail closed.")
        chunks = []
        async for chunk in response:
            chunks.append(chunk)
        if self.streaming == "evaluate_only":
            await self._post_call_success(request_data, _assemble_litellm_chunks(chunks), EnforcementMode.EVALUATE_ONLY)
            for chunk in chunks:
                yield chunk
            return
        assembled = _assemble_litellm_chunks(chunks)
        original_assembled = _jsonable(assembled)
        transformed = await self._post_call_success(request_data, assembled, self.mode)
        if _jsonable(transformed) == original_assembled:
            for chunk in chunks:
                yield chunk
            return
        yield _stream_replacement_chunk(transformed, chunks[0] if chunks else {})

    async def async_post_call_failure_hook(
        self,
        request_data: dict,
        original_exception: Exception,
        user_api_key_dict: Any,
        traceback_str: str | None = None,
    ) -> None:
        self._sessions.drop(_litellm_session_id(request_data if isinstance(request_data, dict) else {}))

    async def _evaluate_input(self, data: dict, messages: list[Any], mode: EnforcementMode) -> None:
        content = _message_content(messages[-1])
        result = await self._evaluate(InterventionPoint.INPUT, {**self._ambient(data), "input": content}, mode)
        if _has_transform(result, mode):
            _set_message_content(messages[-1], result.transformed_policy_target)

    async def _evaluate_pre_model(self, data: dict, mode: EnforcementMode) -> dict:
        result = await self._evaluate(InterventionPoint.PRE_MODEL_CALL, {**self._ambient(data), "model_request": _jsonable(data)}, mode)
        if _has_transform(result, mode) and isinstance(result.transformed_policy_target, dict):
            data.clear()
            data.update(result.transformed_policy_target)
        return data

    async def _evaluate_post_model(self, data: Any, response: Any, mode: EnforcementMode) -> Any:
        result = await self._evaluate(
            InterventionPoint.POST_MODEL_CALL,
            {**self._ambient(data), "model_request": _jsonable(data), "model_response": _jsonable(response)},
            mode,
        )
        if _has_transform(result, mode):
            return result.transformed_policy_target
        return response

    async def _evaluate_tool_calls(
        self,
        session: "_LiteLLMSessionState",
        data: Any,
        response: Any,
        tool_calls: list[Any],
        mode: EnforcementMode,
    ) -> None:
        next_pending: dict[str, str] = {}
        for call in tool_calls:
            call_id = _tool_call_id(call)
            name = _tool_call_name(call)
            args = _tool_call_args(call)
            if not name:
                _raise_litellm_block("acs_litellm_tool_name_missing", "LiteLLM tool call did not include a function name.")
            result = await self._evaluate(
                InterventionPoint.PRE_TOOL_CALL,
                {**self._ambient(data), "model_response": _jsonable(response), "tool_call": _acs_tool_call(name, args, call_id)},
                mode,
            )
            effective_args = args
            if _has_transform(result, mode):
                effective_args = result.transformed_policy_target
                _set_tool_call_args(call, effective_args)
            if call_id:
                next_pending[call_id] = name
        session.pending_tool_calls = next_pending

    async def _evaluate_trailing_tool_results(
        self,
        session: "_LiteLLMSessionState",
        data: Any,
        messages: list[Any],
        mode: EnforcementMode,
    ) -> None:
        for message in _trailing_tool_messages(messages):
            call_id = _tool_message_call_id(message)
            name = session.pending_tool_calls.pop(call_id, None) if call_id else None
            if not name:
                if self.reject_unknown_tool_results and mode == EnforcementMode.ENFORCE:
                    _raise_litellm_block("acs_litellm_tool_result_unknown", f"Tool result references unknown tool_call_id {call_id!r}.")
                continue
            content = _message_content(message)
            result = await self._evaluate(
                InterventionPoint.POST_TOOL_CALL,
                {**self._ambient(data), "tool_call": _acs_tool_call(name, {}, call_id), "tool_result": content},
                mode,
            )
            if _has_transform(result, mode):
                _set_message_content(message, result.transformed_policy_target)

    async def _evaluate_output(self, data: Any, response: Any, mode: EnforcementMode) -> Any:
        content = _assistant_content(response)
        result = await self._evaluate(
            InterventionPoint.OUTPUT,
            {**self._ambient(data), "model_request": _jsonable(data), "model_response": _jsonable(response), "output": content},
            mode,
        )
        if _has_transform(result, mode):
            if _set_assistant_content(response, result.transformed_policy_target):
                return response
            return result.transformed_policy_target
        return response

    async def _evaluate(self, point: InterventionPoint, snapshot: Mapping[str, JsonValue], mode: EnforcementMode) -> InterventionPointResult:
        result = await self._control().evaluate_intervention_point(point, snapshot, mode)
        try:
            await self._control().enforce(point, result, mode)
        except AgentControlBlocked as exc:
            reason = exc.result.verdict.reason or f"acs_{point.value}_blocked"
            message = exc.result.verdict.message or str(exc)
            _raise_litellm_block(reason, message)
        return result

    def _ambient(self, data: Any) -> dict[str, JsonValue]:
        metadata = data.get("metadata") if isinstance(data, Mapping) else None
        return {
            **self.snapshot,
            "transport": {"adapter": "litellm_proxy_guardrail", "guardrail": self.guardrail_name},
            "metadata": dict(metadata) if isinstance(metadata, Mapping) else {},
        }


class _LiteLLMSessionState:
    def __init__(self) -> None:
        self.lock = __import__("asyncio").Lock()
        self.pending_tool_calls: dict[str, str] = {}
        self.last_used = __import__("time").monotonic()


class _LiteLLMSessionCache:
    def __init__(self, max_size: int, ttl_seconds: float) -> None:
        from collections import OrderedDict

        self.max_size = max(1, int(max_size))
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self._entries: OrderedDict[str, _LiteLLMSessionState] = OrderedDict()
        self._cache_lock = __import__("asyncio").Lock()

    def drop(self, sid: str) -> None:
        self._entries.pop(sid, None)

    def locked(self, sid: str):
        cache = self

        class _Guard:
            async def __aenter__(self) -> _LiteLLMSessionState:
                self.entry = await cache._entry(sid)
                await self.entry.lock.acquire()
                return self.entry

            async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
                self.entry.last_used = __import__("time").monotonic()
                self.entry.lock.release()

        return _Guard()

    async def _entry(self, sid: str) -> _LiteLLMSessionState:
        async with self._cache_lock:
            self._evict()
            entry = self._entries.get(sid)
            if entry is None:
                entry = _LiteLLMSessionState()
                self._entries[sid] = entry
            else:
                self._entries.move_to_end(sid)
            return entry

    def _evict(self) -> None:
        now = __import__("time").monotonic()
        if self.ttl_seconds:
            for key in list(self._entries):
                if now - self._entries[key].last_used > self.ttl_seconds:
                    self._entries.pop(key, None)
        while len(self._entries) > self.max_size:
            self._entries.popitem(last=False)


def _raise_litellm_block(reason: str, message: str) -> None:
    try:
        from fastapi import HTTPException
    except ImportError as exc:
        raise AdapterUnsupportedError(f"{reason}: {message}") from exc
    raise HTTPException(status_code=400, detail={"error": {"type": "acs_guardrail_block", "code": reason, "message": message}})


def _has_transform(result: InterventionPointResult, mode: EnforcementMode) -> bool:
    return mode == EnforcementMode.ENFORCE and result.verdict.decision.applies_effects and (
        result.transformed_policy_target_applied or result.transformed_policy_target is not None
    )


def _litellm_session_id(data: Mapping[str, Any]) -> str:
    metadata = data.get("metadata")
    if isinstance(metadata, Mapping):
        for key in ("agent_control_session_id", "acs_session_id", "litellm_session_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
    for key in ("litellm_session_id", "user"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return "ephemeral:" + __import__("uuid").uuid4().hex


def _message_role(message: Any) -> str | None:
    return _get(message, "role") if isinstance(_get(message, "role"), str) else None


def _message_content(message: Any) -> JsonValue:
    return _get(message, "content")


def _set_message_content(message: Any, content: JsonValue) -> None:
    _set(message, "content", content)


def _tool_message_call_id(message: Any) -> str | None:
    value = _get(message, "tool_call_id")
    return value if isinstance(value, str) and value else None


def _trailing_tool_messages(messages: list[Any]) -> list[Any]:
    out = []
    for message in reversed(messages):
        if _message_role(message) != "tool":
            break
        out.append(message)
    return list(reversed(out))


def _response_tool_calls(response: Any) -> list[Any]:
    message = _first_choice_message(response)
    calls = _get(message, "tool_calls") if message is not None else None
    return list(calls) if isinstance(calls, list) else []


def _assistant_content(response: Any) -> JsonValue:
    message = _first_choice_message(response)
    return _get(message, "content") if message is not None else response


def _set_assistant_content(response: Any, content: JsonValue) -> bool:
    message = _first_choice_message(response)
    if message is None:
        return False
    _set(message, "content", content)
    return True


def _first_choice_message(response: Any) -> Any | None:
    choices = _get(response, "choices")
    if not isinstance(choices, list) or not choices:
        return None
    return _get(choices[0], "message") or _get(choices[0], "delta")


def _tool_call_id(call: Any) -> str | None:
    value = _get(call, "id")
    return value if isinstance(value, str) and value else None


def _tool_call_name(call: Any) -> str | None:
    function = _get(call, "function")
    value = _get(function, "name")
    return value if isinstance(value, str) and value else None


def _tool_call_args(call: Any) -> JsonValue:
    function = _get(call, "function")
    raw = _get(function, "arguments")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw if raw is not None else {}


def _set_tool_call_args(call: Any, args: JsonValue) -> None:
    function = _get(call, "function")
    _set(function, "arguments", args if isinstance(args, str) else json.dumps(args, separators=(",", ":"), ensure_ascii=False))


def _acs_tool_call(name: str, args: JsonValue, call_id: str | None) -> dict[str, Any]:
    value: dict[str, Any] = {"name": name, "args": args}
    if call_id:
        value["id"] = call_id
    return value


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _set(obj: Any, name: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


def _assemble_litellm_chunks(chunks: list[Any]) -> dict[str, Any]:
    content = ""
    tool_calls: dict[int, dict[str, Any]] = {}
    finish_reason = None
    template: dict[str, Any] = {}
    for raw in chunks:
        chunk = _jsonable(raw)
        if not isinstance(chunk, Mapping):
            continue
        if not template:
            template = {k: chunk.get(k) for k in ("id", "created", "model") if k in chunk}
        choices = chunk.get("choices")
        if not isinstance(choices, list) or not choices:
            continue
        choice = choices[0]
        delta = choice.get("delta") or {}
        if isinstance(delta, Mapping):
            piece = delta.get("content")
            if isinstance(piece, str):
                content += piece
            for fragment in delta.get("tool_calls") or []:
                index = fragment.get("index", len(tool_calls))
                current = tool_calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                if fragment.get("id"):
                    current["id"] = fragment["id"]
                if fragment.get("type"):
                    current["type"] = fragment["type"]
                fn = fragment.get("function") or {}
                if fn.get("name"):
                    current["function"]["name"] = fn["name"]
                if isinstance(fn.get("arguments"), str):
                    current["function"]["arguments"] += fn["arguments"]
        if choice.get("finish_reason") is not None:
            finish_reason = choice.get("finish_reason")
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
    return {**template, "object": "chat.completion", "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}]}


def _stream_replacement_chunk(response: Any, template: Any) -> dict[str, Any]:
    data = _jsonable(response)
    first = _jsonable(template)
    if not isinstance(data, Mapping):
        data = {"choices": [{"message": {"content": str(data)}}]}
    message = (((data.get("choices") or [{}])[0]).get("message") or {}) if isinstance(data.get("choices"), list) else {}
    delta: dict[str, Any] = {"role": "assistant"}
    if message.get("content") is not None:
        delta["content"] = message.get("content")
    if message.get("tool_calls"):
        delta["tool_calls"] = message.get("tool_calls")
    return {
        "id": first.get("id") if isinstance(first, Mapping) else None,
        "object": "chat.completion.chunk",
        "created": first.get("created") if isinstance(first, Mapping) else None,
        "model": first.get("model") if isinstance(first, Mapping) else None,
        "choices": [{"index": 0, "delta": delta, "finish_reason": "tool_calls" if delta.get("tool_calls") else "stop"}],
    }
