# Shared buffer-mode streaming conformance fixtures

These fixtures define the cross-SDK contract for guarding streaming chat-completion responses. They are generated from and validated against the normative Python guard in `sdk/python/agent_control_specification/_adapters/_sse.py` by `generate.py`. Every ACS SDK that guards a streaming surface MUST reproduce these outcomes exactly so the four SDKs behave identically on the security-critical streaming path.

## The buffer-mode contract

A streaming response cannot be policy-checked incrementally because a verdict over partial content races the bytes already sent to the caller, and tool-call validation needs complete `arguments` JSON. The guard therefore buffers the full upstream stream, assembles it into a single non-streaming chat-completion shape, evaluates that shape with the existing post-model policy path, and only then releases output. On allow it re-emits the original bytes verbatim. On a transform it synthesizes a single replacement chunk. Anything that cannot be faithfully assembled fails closed.

### Assembly rules

- Caps guard against hostile upstreams. See `limits` in `manifest.json` for `max_stream_bytes` and `max_stream_events`. Caps account for raw bytes and event count.
- SSE comment lines and keepalive lines are ignored.
- Exactly one choice is supported. Multi-choice chunks, or any choice whose index is not zero, fail closed because one choice could be allowed while another should deny.
- Delta `content` accumulates across chunks and must be a string.
- Tool calls are reassembled per integer `index`. The `id`, `type`, and `function.name` merge as scalars, and `function.arguments` concatenates as strings. A fragment without an integer index fails closed. Non-string metadata or arguments fail closed.
- Any non-null field on a choice outside `index`, `delta`, `finish_reason`, or on a delta outside `role`, `content`, `tool_calls`, fails closed because the verbatim stream would otherwise leak content the policy never evaluated.
- A data event after `[DONE]`, malformed SSE JSON, a non-object chunk, or a stream with no data chunks all fail closed.

### Allow re-emission

On allow the guard re-emits the original upstream bytes. Implementations MUST NOT parse and reserialize, because that can alter whitespace, field ordering, provider extensions, unicode escaping, or framing. The allow path is byte-for-byte identical to the input. Fixtures with `allow_reemits_input_verbatim: true` assert this.

### Transform synthesis

On a transform the guard renders the transformed non-streaming response into a single SSE chunk followed by `[DONE]`. If the transformed response cannot be represented as one canonical chat-completion chunk the guard fails closed. The `synthesize` fixtures pin the exact synthesized bytes.

## Files

- `manifest.json` lists every case. `assemble` cases carry the raw input path, the expected `outcome` (`ok` or `fail_closed`), and for `ok` cases the expected `assembled` JSON. `synthesize` cases carry the input `response`, the `template`, and the expected output bytes path.
- `inputs/*.sse` are the raw streamed bytes. `inputs/*.expected.sse` are the expected synthesized outputs.

## Regenerating

Run with the integration venv so the Python SDK is importable.

```sh
.venv-int/bin/python tests/conformance/streaming/generate.py
```

Regeneration is only valid when the Python guard behavior intentionally changes. Any regeneration requires re-verifying every SDK runner against the updated fixtures.
