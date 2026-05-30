from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from typing import Any

from .._orchestration import AgentControl
from .._types import EnforcementMode, JsonValue
from ._errors import AdapterUnsupportedError
from ._generic import run_model_call
from ._shared import (
    Execute,
    _body_bytes,
    _capture_asgi_send,
    _decode_json_body,
    _encode_json_body,
    _maybe_await,
    _read_asgi_body,
    _resolve_control_and_target,
    _response_json_from_asgi_messages,
    _scope_with_content_length,
    _send_json_asgi_response,
    _single_body_receive,
)
from ._sse import assemble_sse_stream, synthesize_sse_stream

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
        if not applies or post_result.transformed_policy_target is None:
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
