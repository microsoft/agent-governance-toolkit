from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from .._orchestration import AgentControl
from .._types import (
    EnforcementMode,
    JsonValue,
    InterventionPointResult,
)
from ._errors import AdapterUnsupportedError

Execute = Callable[..., JsonValue | Awaitable[JsonValue]]
SNAPSHOT_KWARG = "agent_control_snapshot"
TOOL_CALL_ID_KWARG = "agent_control_tool_call_id"


class _ObjectProxy:
    def __init__(
        self,
        target: Any,
        *,
        overrides: Mapping[str, Any] | None = None,
        blocked: Mapping[str, str] | None = None,
    ) -> None:
        object.__setattr__(self, "_agent_control_target", target)
        object.__setattr__(self, "_agent_control_overrides", dict(overrides or {}))
        object.__setattr__(self, "_agent_control_blocked", dict(blocked or {}))

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_agent_control_overrides")
        if name in overrides:
            return overrides[name]
        blocked = object.__getattribute__(self, "_agent_control_blocked")
        if name in blocked:
            message = blocked[name]

            def blocked_method(*args: Any, **kwargs: Any) -> None:
                raise AdapterUnsupportedError(message)

            return blocked_method
        return getattr(object.__getattribute__(self, "_agent_control_target"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_agent_control_target"), name, value)


async def _maybe_await(value: JsonValue | Awaitable[JsonValue]) -> JsonValue:
    if inspect.isawaitable(value):
        return await value
    return value


def _pop_common_adapter_kwargs(kwargs: dict[str, Any]) -> Mapping[str, JsonValue] | None:
    per_call_snapshot = kwargs.pop(SNAPSHOT_KWARG, None)
    if per_call_snapshot is not None and not isinstance(per_call_snapshot, Mapping):
        raise TypeError(f"{SNAPSHOT_KWARG} must be a mapping when provided")
    return per_call_snapshot


def _merge_snapshot(
    default_snapshot: Mapping[str, JsonValue],
    per_call_snapshot: Mapping[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    return {**dict(default_snapshot), **dict(per_call_snapshot or {})}


def _transformed_or(
    result: InterventionPointResult, fallback: JsonValue, mode: EnforcementMode
) -> JsonValue:
    """Return the engine's transformed policy target when the verdict was
    ``Decision.TRANSFORM`` in enforce mode, otherwise the fallback.

    Mirrors `_orchestration._transformed_or`. Per AGT D1 only
    ``Decision.TRANSFORM`` mutates the policy target.
    """

    if mode != EnforcementMode.ENFORCE:
        return fallback
    if not result.verdict.decision.applies_transform:
        return fallback
    if result.transformed_policy_target_applied or result.transformed_policy_target is not None:
        return result.transformed_policy_target
    return fallback


def _require_callable(target: Any, method_name: str, target_name: str) -> Execute:
    method = getattr(target, method_name, None)
    if not callable(method):
        raise AdapterUnsupportedError(f"{target_name} does not expose callable {method_name}.")
    return method


def _first_callable(target: Any, candidates: tuple[str, ...], target_name: str) -> str:
    for name in candidates:
        if callable(getattr(target, name, None)):
            return name
    raise AdapterUnsupportedError(
        f"{target_name} does not expose any supported method: {', '.join(candidates)}."
    )


def _has_path(target: Any, path: tuple[str, ...]) -> bool:
    current = target
    for name in path:
        if not hasattr(current, name):
            return False
        current = getattr(current, name)
    return callable(current) if path[-1] == "create" else True


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None



def _resolve_control_and_target(
    first: Any,
    second: Any,
    *,
    control: AgentControl | None,
    target_name: str,
    adapter_name: str,
) -> tuple[AgentControl, Any]:
    if isinstance(first, AgentControl):
        if control is not None:
            raise TypeError(f"{adapter_name}() got AgentControl both positionally and by keyword")
        if second is None:
            raise AdapterUnsupportedError(
                f"{adapter_name}() requires a {target_name} after the AgentControl instance."
            )
        return first, second
    if control is None:
        raise AdapterUnsupportedError(
            f"{adapter_name}() requires control=AgentControl(...) when the {target_name} is first."
        )
    if second is not None:
        raise TypeError(f"{adapter_name}() got unexpected second positional argument")
    return control, first


async def _read_asgi_body(receive: Execute) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await _maybe_await(receive())
        if not isinstance(message, Mapping):
            raise AdapterUnsupportedError("ASGI receive() must yield mapping messages.")
        if message.get("type") != "http.request":
            continue
        body = message.get("body", b"")
        if isinstance(body, str):
            body = body.encode()
        if body:
            chunks.append(body)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _decode_json_body(body: bytes, label: str) -> JsonValue:
    try:
        return json.loads(body.decode("utf-8") if body else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterUnsupportedError(f"{label} must be a UTF-8 JSON body.") from exc


def _encode_json_body(value: JsonValue) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _jsonable(value: Any) -> JsonValue:
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    method = getattr(value, "model_dump", None) or getattr(value, "dict", None)
    if callable(method):
        try:
            return _jsonable(method())
        except Exception:  # noqa: BLE001
            pass
    if hasattr(value, "__dict__"):
        return _jsonable({k: v for k, v in vars(value).items() if not k.startswith("_")})
    return repr(value)


def _single_body_receive(body: bytes) -> Callable[[], Awaitable[dict[str, Any]]]:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _capture_asgi_send(messages: list[dict[str, Any]]) -> Callable[[Mapping[str, Any]], Awaitable[None]]:
    async def send(message: Mapping[str, Any]) -> None:
        messages.append(dict(message))

    return send


def _response_json_from_asgi_messages(messages: list[dict[str, Any]]) -> JsonValue:
    body = b"".join(
        _body_bytes(message) for message in messages if message.get("type") == "http.response.body"
    )
    return _decode_json_body(body, "LiteLLM proxy response")


async def _send_json_asgi_response(
    send: Execute,
    captured_messages: list[dict[str, Any]],
    value: JsonValue,
) -> None:
    body = _encode_json_body(value)
    start = next(
        (dict(message) for message in captured_messages if message.get("type") == "http.response.start"),
        {"type": "http.response.start", "status": 200, "headers": []},
    )
    start["headers"] = _headers_with_content_length(start.get("headers", []), len(body))
    await _maybe_await(send(start))
    await _maybe_await(send({"type": "http.response.body", "body": body, "more_body": False}))


def _body_bytes(message: Mapping[str, Any]) -> bytes:
    body = message.get("body", b"")
    if isinstance(body, str):
        return body.encode()
    return body


def _scope_with_content_length(scope: Mapping[str, Any], content_length: int) -> dict[str, Any]:
    cloned = dict(scope)
    cloned["headers"] = _headers_with_content_length(scope.get("headers", []), content_length)
    return cloned


def _headers_with_content_length(headers: Any, content_length: int) -> list[tuple[bytes, bytes]]:
    normalized: list[tuple[bytes, bytes]] = []
    saw_content_type = False
    for raw_name, raw_value in headers or []:
        name = raw_name if isinstance(raw_name, bytes) else str(raw_name).encode("latin-1")
        value = raw_value if isinstance(raw_value, bytes) else str(raw_value).encode("latin-1")
        lower_name = name.lower()
        if lower_name == b"content-length":
            continue
        if lower_name == b"content-type":
            saw_content_type = True
        normalized.append((name, value))
    if not saw_content_type:
        normalized.append((b"content-type", b"application/json"))
    normalized.append((b"content-length", str(content_length).encode("ascii")))
    return normalized
