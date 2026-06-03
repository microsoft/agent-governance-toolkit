"""Buffer-mode SSE assembly and synthesis for the LiteLLM proxy guard.

Streaming responses can only be policy-checked once fully assembled: a
verdict over partial content races the bytes already sent to the client,
and Stage-2/3 tool-call validation needs complete ``arguments`` JSON. So
the guard buffers the upstream stream, assembles it into a non-streaming
chat-completion shape for evaluation, then either re-emits the original
bytes (allow) or a synthesized stream (transform). Anything that cannot
be faithfully assembled fails closed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .._types import JsonValue
from ._errors import AdapterUnsupportedError

# Buffering ceilings guard against unbounded or hostile upstreams.
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_STREAM_EVENTS = 10_000

_DONE = "[DONE]"
_DATA_FIELD = "data:"
_COMMENT_PREFIX = ":"
_CHUNK_OBJECT = "chat.completion.chunk"
_COMPLETION_OBJECT = "chat.completion"
_ASSISTANT_ROLE = "assistant"

# Keys whose data is captured by the assembled policy_target; any other key
# carrying a non-null value means the verbatim stream would leak content
# the policy never evaluated, so those streams fail closed.
_KNOWN_CHOICE_KEYS = frozenset({"index", "delta", "finish_reason"})
_KNOWN_DELTA_KEYS = frozenset({"role", "content", "tool_calls"})
_PASSTHROUGH_CHUNK_KEYS = ("id", "created", "model")


class _ToolCallAccumulator:
    """Reassembles one tool call from index-keyed streaming fragments."""

    def __init__(self) -> None:
        self.id: str | None = None
        self.type: str | None = None
        self.name: str | None = None
        self.arguments: str = ""

    def merge(self, fragment: Mapping[str, Any]) -> None:
        self.id = _merge_scalar(self.id, fragment.get("id"))
        self.type = _merge_scalar(self.type, fragment.get("type"))
        function = fragment.get("function") or {}
        if not isinstance(function, Mapping):
            raise AdapterUnsupportedError("Streaming tool_call.function must be an object.")
        self.name = _merge_scalar(self.name, function.get("name"))
        arguments = function.get("arguments")
        if arguments is not None:
            if not isinstance(arguments, str):
                raise AdapterUnsupportedError("Streaming tool_call arguments must be strings.")
            self.arguments += arguments

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id or "",
            "type": self.type or "function",
            "function": {"name": self.name or "", "arguments": self.arguments},
        }


def assemble_sse_stream(raw: bytes) -> dict[str, Any]:
    """Assemble buffered SSE bytes into a chat-completion response.

    Fails closed on malformed framing, multi-choice streams, unsupported
    fields, or empty output so the guard never evaluates a response that
    misrepresents what the client would receive.
    """

    if len(raw) > MAX_STREAM_BYTES:
        raise AdapterUnsupportedError("Streaming response exceeded the buffering byte limit.")

    chunks = _parse_sse_chunks(raw)
    if not chunks:
        raise AdapterUnsupportedError("Streaming response contained no data chunks.")

    content = ""
    finish_reason: Any = None
    tool_calls: dict[int, _ToolCallAccumulator] = {}
    template: dict[str, Any] = {}

    for chunk in chunks:
        if not template:
            template = {key: chunk.get(key) for key in _PASSTHROUGH_CHUNK_KEYS if key in chunk}
        choices = chunk.get("choices") or []
        if not isinstance(choices, list):
            raise AdapterUnsupportedError("Streaming chunk choices must be a list.")
        if not choices:
            continue
        if len(choices) > 1:
            raise AdapterUnsupportedError("Multi-choice streaming responses are not guarded.")
        choice = choices[0]
        if not isinstance(choice, Mapping):
            raise AdapterUnsupportedError("Streaming choice must be an object.")
        if choice.get("index", 0) != 0:
            raise AdapterUnsupportedError("Multi-choice streaming responses are not guarded.")
        if _carries_unrepresented_data(choice, _KNOWN_CHOICE_KEYS):
            raise AdapterUnsupportedError("Streaming choice carried unsupported fields.")

        delta = choice.get("delta") or {}
        if not isinstance(delta, Mapping):
            raise AdapterUnsupportedError("Streaming choice delta must be an object.")
        if _carries_unrepresented_data(delta, _KNOWN_DELTA_KEYS):
            raise AdapterUnsupportedError("Streaming delta carried unsupported fields.")

        piece = delta.get("content")
        if piece is not None:
            if not isinstance(piece, str):
                raise AdapterUnsupportedError("Streaming delta content must be a string.")
            content += piece

        _merge_tool_call_fragments(delta.get("tool_calls"), tool_calls)

        if choice.get("finish_reason") is not None:
            finish_reason = choice["finish_reason"]

    message: dict[str, Any] = {"role": _ASSISTANT_ROLE, "content": content}
    if tool_calls:
        message["tool_calls"] = [tool_calls[index].as_dict() for index in sorted(tool_calls)]

    return {
        **template,
        "object": _COMPLETION_OBJECT,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }


def synthesize_sse_stream(response: JsonValue, template: Mapping[str, Any]) -> bytes:
    """Render a transformed response back into a single-chunk SSE stream."""

    if not isinstance(response, Mapping):
        raise AdapterUnsupportedError("Transformed streaming response must be an object.")
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], Mapping):
        raise AdapterUnsupportedError("Transformed streaming response must carry a choice.")

    choice = choices[0]
    if choice.get("index", 0) != 0:
        raise AdapterUnsupportedError("Transformed streaming response must carry one zero-index choice.")
    message = choice.get("message") or {}
    if not isinstance(message, Mapping):
        raise AdapterUnsupportedError("Transformed streaming choice must carry a message.")

    delta: dict[str, Any] = {"role": _ASSISTANT_ROLE}
    if message.get("content") is not None:
        if not isinstance(message["content"], str):
            raise AdapterUnsupportedError("Transformed streaming content must be a string.")
        delta["content"] = message["content"]
    tool_calls = message.get("tool_calls")
    if tool_calls is not None:
        if not isinstance(tool_calls, list):
            raise AdapterUnsupportedError("Transformed streaming tool_calls must be a list.")
        if tool_calls:
            delta["tool_calls"] = [_streaming_tool_call(index, call) for index, call in enumerate(tool_calls)]

    finish_reason = choice.get("finish_reason")
    if finish_reason is None:
        finish_reason = "tool_calls" if tool_calls else "stop"

    chunk = {key: template[key] for key in _PASSTHROUGH_CHUNK_KEYS if key in template}
    chunk["object"] = _CHUNK_OBJECT
    chunk["choices"] = [{"index": 0, "delta": delta, "finish_reason": finish_reason}]

    return _sse_frame(json.dumps(chunk, separators=(",", ":"))) + _sse_frame(_DONE)


def _parse_sse_chunks(raw: bytes) -> list[dict[str, Any]]:
    text = raw.decode("utf-8", errors="strict").replace("\r\n", "\n").replace("\r", "\n")
    chunks: list[dict[str, Any]] = []
    done = False
    for block in text.split("\n\n"):
        data = _event_data(block)
        if data is None:
            continue
        if done:
            raise AdapterUnsupportedError("Streaming response sent data after [DONE].")
        if data == _DONE:
            done = True
            continue
        if len(chunks) >= MAX_STREAM_EVENTS:
            raise AdapterUnsupportedError("Streaming response exceeded the buffered event limit.")
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError as exc:
            raise AdapterUnsupportedError("Streaming response contained malformed SSE JSON.") from exc
        if not isinstance(chunk, dict):
            raise AdapterUnsupportedError("Streaming SSE chunk must be a JSON object.")
        chunks.append(chunk)
    if not done:
        raise AdapterUnsupportedError("Streaming response terminated before [DONE].")
    return chunks


def _event_data(block: str) -> str | None:
    lines = [line for line in block.split("\n") if line and not line.startswith(_COMMENT_PREFIX)]
    data_lines = [line[len(_DATA_FIELD):].lstrip(" ") for line in lines if line.startswith(_DATA_FIELD)]
    return "\n".join(data_lines) if data_lines else None


def _streaming_tool_call(index: int, call: Any) -> dict[str, Any]:
    if not isinstance(call, Mapping):
        raise AdapterUnsupportedError("Transformed streaming tool_call must be an object.")
    fragment = dict(call)
    existing = fragment.get("index")
    if existing is not None and existing != index:
        raise AdapterUnsupportedError("Transformed streaming tool_call index must match its order.")
    fragment["index"] = index
    return fragment


def _merge_tool_call_fragments(
    fragments: Any,
    accumulators: dict[int, _ToolCallAccumulator],
) -> None:
    if not fragments:
        return
    if not isinstance(fragments, list):
        raise AdapterUnsupportedError("Streaming tool_calls must be a list.")
    for fragment in fragments:
        if not isinstance(fragment, Mapping):
            raise AdapterUnsupportedError("Streaming tool_call fragment must be an object.")
        index = fragment.get("index")
        if not isinstance(index, int):
            raise AdapterUnsupportedError("Streaming tool_call fragments require an integer index.")
        accumulators.setdefault(index, _ToolCallAccumulator()).merge(fragment)


def _merge_scalar(current: str | None, incoming: Any) -> str | None:
    if incoming is None:
        return current
    if not isinstance(incoming, str):
        raise AdapterUnsupportedError("Streaming tool_call metadata must be strings.")
    if current is not None and current != incoming:
        raise AdapterUnsupportedError("Streaming tool_call metadata changed mid-stream.")
    return incoming


def _carries_unrepresented_data(mapping: Mapping[str, Any], known: frozenset[str]) -> bool:
    return any(
        key not in known and value not in (None, "", [], {})
        for key, value in mapping.items()
    )


def _sse_frame(data: str) -> bytes:
    return f"data: {data}\n\n".encode("utf-8")
