# LiteLLM Proxy guardrail hook

ACS ships an optional LiteLLM Proxy guardrail hook for OpenAI compatible chat traffic. The hook is host integration code. The ACS runtime stays stateless and receives one complete snapshot per intervention point.

## Install

```sh
pip install "agent-control-specification[litellm-proxy]"
```

## Proxy YAML

```yaml
model_list:
  - model_name: gpt-4o-mini
    litellm_params:
      model: openai/gpt-4o-mini
      api_key: os.environ/OPENAI_API_KEY

guardrails:
  - guardrail_name: acs
    litellm_params:
      guardrail: agent_control_specification.AgentControlLiteLLMGuardrail
      mode: [pre_call, post_call]
      manifest_path: /etc/acs/manifest.yaml
      default_on: true
      streaming: buffer
      reject_unknown_tool_results: true
      session_cache_size: 512
      session_ttl_seconds: 1800
```

The proxy process loads the manifest through `AgentControl.from_path`. Rego policies use the bundled OPA dispatcher when `opa` is on `PATH`. Annotators run through the Python SDK default dispatcher or through dispatchers supplied by application code when a custom construction path is used.

## Hook mapping

| LiteLLM hook | ACS intervention point | Snapshot fields |
| --- | --- | --- |
| `async_pre_call_hook` with trailing `role=user` | `input` | `input`, `metadata`, `transport` |
| `async_pre_call_hook` for every forwarded request | `pre_model_call` | `model_request`, `metadata`, `transport` |
| `async_post_call_success_hook` | `post_model_call` | `model_request`, `model_response`, `metadata`, `transport` |
| `async_post_call_success_hook` with assistant `tool_calls` | `pre_tool_call` | `tool_call`, `model_response`, `metadata`, `transport` |
| next `async_pre_call_hook` with trailing `role=tool` | `post_tool_call` | `tool_call`, `tool_result`, `metadata`, `transport` |
| `async_post_call_success_hook` without tool calls | `output` | `output`, `model_request`, `model_response`, `metadata`, `transport` |
| `async_post_call_streaming_iterator_hook` | buffered `post_model_call`, `pre_tool_call`, or `output` | assembled complete response |

## Session correlation

LiteLLM splits assistant tool calls and later tool results across HTTP requests. The hook keeps a bounded per instance cache that maps model supplied `tool_call.id` values to tool names. This cache is adapter state only. It does not live in the ACS runtime and it does not create synthetic `tool_call.id` values in snapshots.

Session id resolution checks `metadata.agent_control_session_id`, `metadata.acs_session_id`, `metadata.litellm_session_id`, top level `litellm_session_id`, then top level `user`. If none are present the hook uses an ephemeral id for that hook call, so later tool results cannot correlate and fail closed under enforcement. Per session locks serialize hook bodies. LRU and idle TTL cleanup bound memory use.

## Streaming behavior

The default `streaming: buffer` setting drains the LiteLLM stream, reconstructs a complete assistant response, evaluates ACS, then replays original chunks on allow. A transformed response emits a replacement chunk. A deny in enforce mode raises before any buffered chunk is yielded.

`streaming: fail_closed` rejects streaming in enforce mode. `streaming: evaluate_only` buffers and evaluates but always replays the original chunks. Use evaluate only only for audit or rollout because it does not enforce transformed output on streams.

## Limitations

- Only OpenAI chat style `messages`, assistant `tool_calls`, and tool result messages are mapped.
- Unknown or fabricated tool result ids fail closed when `reject_unknown_tool_results` is enabled.
- Parallel tool calls are evaluated one by one. Hosts that need atomic batch rollback should disable parallel tool calls or use an in process adapter.
- Approval suspension is surfaced as the SDK exception path. A proxy deployment must translate it into an application specific approval flow.
- Local tools, client side tool execution, and non chat routes that bypass the proxy are outside ACS mediation.
