#!/usr/bin/env python3
"""Generate the shared streaming conformance fixtures from the normative
Python buffer-mode SSE guard.

The Python LiteLLM proxy guard in
``sdk/python/agent_control_specification/_adapters/_sse.py`` is the normative
reference for ACS buffer-mode streaming. Every SDK that guards a streaming
chat-completion surface must reproduce its behavior exactly. This script runs
the real ``assemble_sse_stream`` and ``synthesize_sse_stream`` over a battery
of inputs and writes language-neutral fixtures so the Node, .NET, Rust, and
Python runners can all assert the same outcomes. The fixtures are the source
of truth for parity; this generator records their provenance.

Run with the integration venv so the Python SDK is importable:

    .venv-int/bin/python tests/conformance/streaming/generate.py
"""

from __future__ import annotations

import json
import os
from typing import Any

from agent_control_specification._adapters import _sse
from agent_control_specification._adapters._errors import AdapterUnsupportedError

HERE = os.path.dirname(os.path.abspath(__file__))
INPUTS = os.path.join(HERE, "inputs")


def sse(*events: str) -> bytes:
    """Frame data events into an SSE byte stream the way a proxy emits them."""
    return ("".join(f"data: {e}\n\n" for e in events)).encode("utf-8")


def chunk(**kw: Any) -> str:
    base = {"id": "cmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x"}
    base.update(kw)
    return json.dumps(base, separators=(",", ":"))


def delta_chunk(delta: dict, finish: Any = None) -> str:
    return chunk(choices=[{"index": 0, "delta": delta, "finish_reason": finish}])


# Each assemble case is (name, raw_bytes, description). The expected result is
# computed by running the normative implementation below.
ASSEMBLE_CASES: list[tuple[str, bytes, str]] = [
    (
        "allow_text_only",
        sse(
            delta_chunk({"role": "assistant"}),
            delta_chunk({"content": "Hello"}),
            delta_chunk({"content": " world"}),
            delta_chunk({}, finish="stop"),
            "[DONE]",
        ),
        "Plain text completion across deltas, finishes with stop.",
    ),
    (
        "allow_tool_call_fragments",
        sse(
            delta_chunk({"role": "assistant"}),
            delta_chunk({"tool_calls": [{"index": 0, "id": "call_a", "type": "function",
                                         "function": {"name": "get_weather", "arguments": ""}}]}),
            delta_chunk({"tool_calls": [{"index": 0, "function": {"arguments": "{\"ci"}}]}),
            delta_chunk({"tool_calls": [{"index": 0, "function": {"arguments": "ty\":\"SF\"}"}}]}),
            delta_chunk({}, finish="tool_calls"),
            "[DONE]",
        ),
        "Tool call with name/id in first fragment and arguments split across chunks.",
    ),
    (
        "allow_two_tool_calls",
        sse(
            delta_chunk({"role": "assistant"}),
            delta_chunk({"tool_calls": [{"index": 0, "id": "c0", "type": "function",
                                         "function": {"name": "a", "arguments": "{}"}}]}),
            delta_chunk({"tool_calls": [{"index": 1, "id": "c1", "type": "function",
                                         "function": {"name": "b", "arguments": "{}"}}]}),
            delta_chunk({}, finish="tool_calls"),
            "[DONE]",
        ),
        "Two parallel tool calls keyed by index merge in index order.",
    ),
    (
        "allow_comments_and_keepalive",
        b": keepalive\n\n" + sse(
            delta_chunk({"role": "assistant", "content": "hi"}),
            delta_chunk({}, finish="stop"),
            "[DONE]",
        ),
        "Comment and keepalive lines are ignored, content still assembles.",
    ),
    (
        "fail_malformed_json",
        sse(delta_chunk({"content": "ok"}), "{not json}", "[DONE]"),
        "A data event with malformed JSON fails closed.",
    ),
    (
        "fail_multichoice",
        sse(
            chunk(choices=[
                {"index": 0, "delta": {"content": "a"}, "finish_reason": None},
                {"index": 1, "delta": {"content": "b"}, "finish_reason": None},
            ]),
            "[DONE]",
        ),
        "More than one choice in a chunk fails closed.",
    ),
    (
        "fail_second_choice_index",
        sse(
            delta_chunk({"role": "assistant", "content": "a"}),
            chunk(choices=[{"index": 1, "delta": {"content": "b"}, "finish_reason": None}]),
            "[DONE]",
        ),
        "A choice with a non-zero index fails closed.",
    ),
    (
        "fail_data_after_done",
        sse(delta_chunk({"content": "a"}), "[DONE]") + b"data: " + delta_chunk({"content": "b"}).encode() + b"\n\n",
        "A data event after [DONE] fails closed.",
    ),
    (
        "fail_unrepresented_choice_field",
        sse(
            chunk(choices=[{"index": 0, "delta": {"content": "a"}, "finish_reason": None,
                            "logprobs": {"tokens": ["a"]}}]),
            "[DONE]",
        ),
        "A non-null unknown field on the choice fails closed because it would leak unevaluated data.",
    ),
    (
        "fail_unrepresented_delta_field",
        sse(
            chunk(choices=[{"index": 0, "delta": {"content": "a", "function_call": {"name": "x"}},
                            "finish_reason": None}]),
            "[DONE]",
        ),
        "A non-null unknown field on the delta fails closed.",
    ),
    (
        "fail_nonstring_content",
        sse(chunk(choices=[{"index": 0, "delta": {"content": 123}, "finish_reason": None}]), "[DONE]"),
        "Non-string delta content fails closed.",
    ),
    (
        "fail_nonstring_tool_args",
        sse(
            chunk(choices=[{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"name": "a", "arguments": {"city": "SF"}}}]},
                "finish_reason": None}]),
            "[DONE]",
        ),
        "Non-string tool_call arguments fail closed.",
    ),
    (
        "fail_tool_call_no_index",
        sse(
            chunk(choices=[{"index": 0, "delta": {"tool_calls": [
                {"id": "c", "function": {"name": "a", "arguments": "{}"}}]},
                "finish_reason": None}]),
            "[DONE]",
        ),
        "A tool_call fragment without an integer index fails closed.",
    ),
    (
        "fail_empty_no_chunks",
        sse("[DONE]"),
        "A stream with only [DONE] and no data chunks fails closed.",
    ),
]

# Synthesize cases turn a (possibly transformed) non-streaming response back
# into a single-chunk SSE stream. (name, response, template, description).
SYNTHESIZE_CASES: list[tuple[str, Any, dict, str]] = [
    (
        "synth_text",
        {"choices": [{"index": 0, "message": {"role": "assistant", "content": "[redacted]"},
                      "finish_reason": "stop"}]},
        {"id": "cmpl-1", "created": 1, "model": "gpt-x"},
        "Transformed text response renders to a single chunk plus [DONE].",
    ),
    (
        "synth_tool_calls",
        {"choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                      "tool_calls": [{"id": "c0", "type": "function",
                                      "function": {"name": "a", "arguments": "{}"}}]},
                      "finish_reason": "tool_calls"}]},
        {"id": "cmpl-1", "created": 1, "model": "gpt-x"},
        "Transformed tool-call response renders tool_calls into the synthesized delta.",
    ),
]


def main() -> None:
    os.makedirs(INPUTS, exist_ok=True)
    manifest: dict[str, Any] = {
        "description": "Shared buffer-mode streaming conformance fixtures generated from "
                       "the normative Python guard in sdk/python/.../_adapters/_sse.py. "
                       "Every SDK that guards a streaming chat-completion surface must "
                       "reproduce these outcomes exactly.",
        "limits": {"max_stream_bytes": _sse.MAX_STREAM_BYTES, "max_stream_events": _sse.MAX_STREAM_EVENTS},
        "assemble": [],
        "synthesize": [],
    }

    for name, raw, desc in ASSEMBLE_CASES:
        path = os.path.join(INPUTS, f"{name}.sse")
        with open(path, "wb") as f:
            f.write(raw)
        entry: dict[str, Any] = {"name": name, "description": desc, "input": f"inputs/{name}.sse"}
        try:
            assembled = _sse.assemble_sse_stream(raw)
            entry["outcome"] = "ok"
            entry["assembled"] = assembled
            # On allow the proxy re-emits the original bytes verbatim, so the
            # allow re-emission is byte-for-byte identical to the input file.
            entry["allow_reemits_input_verbatim"] = True
        except AdapterUnsupportedError as exc:
            entry["outcome"] = "fail_closed"
            entry["error_message"] = str(exc)
        manifest["assemble"].append(entry)

    for name, response, template, desc in SYNTHESIZE_CASES:
        out = _sse.synthesize_sse_stream(response, template)
        out_path = os.path.join(INPUTS, f"{name}.expected.sse")
        with open(out_path, "wb") as f:
            f.write(out)
        manifest["synthesize"].append({
            "name": name,
            "description": desc,
            "response": response,
            "template": template,
            "expected_output": f"inputs/{name}.expected.sse",
        })

    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
        f.write("\n")

    ok = sum(1 for e in manifest["assemble"] if e["outcome"] == "ok")
    fc = sum(1 for e in manifest["assemble"] if e["outcome"] == "fail_closed")
    print(f"wrote {len(manifest['assemble'])} assemble cases ({ok} ok, {fc} fail_closed) "
          f"and {len(manifest['synthesize'])} synthesize cases")


if __name__ == "__main__":
    main()
