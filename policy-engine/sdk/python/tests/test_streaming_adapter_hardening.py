from __future__ import annotations

import asyncio
import json
import pathlib
import unittest
from collections import deque
from dataclasses import replace
from typing import Any

from agent_control_specification import (
    AdapterUnsupportedError,
    AgentControl,
    AgentControlBlocked,
    ApprovalResolution,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
    action_identity,
    guard_anthropic_client,
    guard_litellm_proxy,
    guard_openai_client,
    guard_tool,
)
from agent_control_specification._adapters import _sse

ROOT = pathlib.Path(__file__).resolve().parents[3]
STREAMING = ROOT / "tests" / "conformance" / "streaming"
MANIFEST = json.loads((STREAMING / "manifest.json").read_text())

try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    _NATIVE_AVAILABLE = False
else:
    _NATIVE_AVAILABLE = True


def verdict(decision=None, transformed_policy_target=None, reason=None):
    # AGT D1: TRANSFORM is the only mutating decision. Default to it when
    # the caller supplied a transformed_policy_target so adapter tests
    # exercise the canonical mutation path under the new gate.
    if decision is None:
        decision = Decision.TRANSFORM if transformed_policy_target is not None else Decision.ALLOW
    return InterventionPointResult(Verdict(decision, reason=reason), transformed_policy_target=transformed_policy_target)


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        result = self.results.popleft()
        if result.policy_input is not None and result.enforced_identity is not None:
            return result
        policy_input = {
            "intervention_point": request.intervention_point.value,
            "snapshot": dict(request.snapshot),
        }
        identity = action_identity(policy_input)
        return replace(
            result,
            policy_input=policy_input,
            input_identity=identity,
            enforced_identity=identity,
        )


class FailingRuntime:
    def __init__(self, exc):
        self.exc = exc

    async def evaluate_intervention_point(self, request):
        raise self.exc


def _chunk(content: str = "", finish_reason=None, **delta):
    payload = {"id": "cmpl-1", "created": 1, "model": "gpt-x"}
    actual_delta = {"content": content, **delta} if content else dict(delta)
    payload["choices"] = [{"index": 0, "delta": actual_delta, "finish_reason": finish_reason}]
    return payload


def _sse_bytes(*chunks: dict[str, Any], done: bool = True) -> bytes:
    frames = [f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks]
    if done:
        frames.append("data: [DONE]\n\n")
    return "".join(frames).encode("utf-8")


def _body_from_sent(sent):
    return b"".join(message.get("body", b"") for message in sent if message.get("type") == "http.response.body")


def _streaming_app(raw_sse: bytes, *, status=200, headers=None):
    async def app(scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers or [(b"content-type", b"text/event-stream")],
            }
        )
        midpoint = len(raw_sse) // 2
        await send({"type": "http.response.body", "body": raw_sse[:midpoint], "more_body": True})
        await send({"type": "http.response.body", "body": raw_sse[midpoint:], "more_body": False})

    return app


async def _call_litellm(raw_sse: bytes, runtime: QueueRuntime, *, path="/v1/chat/completions"):
    sent = []
    receive = deque([
        {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
    ])
    await guard_litellm_proxy(AgentControl(runtime), _streaming_app(raw_sse))(
        {"type": "http", "method": "POST", "path": path, "headers": []},
        receive.popleft,
        sent.append,
    )
    return sent


class StreamingAdapterHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_litellm_public_stream_allow_reemits_verbatim_and_transform_synthesizes_once(self):
        raw = _sse_bytes(_chunk("Hel", role="assistant"), _chunk("lo"), _chunk(finish_reason="stop"))
        allow_runtime = QueueRuntime([verdict(), verdict()])
        allow_sent = await _call_litellm(raw, allow_runtime)
        self.assertEqual(_body_from_sent(allow_sent), raw)
        self.assertEqual(
            allow_runtime.requests[1].snapshot["model_response"]["choices"][0]["message"]["content"],
            "Hello",
        )

        transformed = {
            "id": "cmpl-1",
            "created": 1,
            "model": "gpt-x",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "[redacted]"},
                    "finish_reason": "stop",
                }
            ],
        }
        transform_runtime = QueueRuntime([verdict(), verdict(transformed_policy_target=transformed)])
        transform_sent = await _call_litellm(raw, transform_runtime)
        body = _body_from_sent(transform_sent)
        self.assertEqual(body.count(b"data: "), 2)
        self.assertIn(b"[redacted]", body)
        self.assertNotIn(b"Hello", body)

    async def test_litellm_public_stream_deny_and_malformed_inputs_release_no_bytes(self):
        raw = _sse_bytes(_chunk("secret", role="assistant"), _chunk(finish_reason="stop"))
        sent = []
        receive = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        with self.assertRaises(AgentControlBlocked):
            await guard_litellm_proxy(
                AgentControl(QueueRuntime([verdict(), verdict(Decision.DENY)])),
                _streaming_app(raw),
            )(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                receive.popleft,
                sent.append,
            )
        self.assertEqual(sent, [])

        failing_cases = [case for case in MANIFEST["assemble"] if case["outcome"] != "ok"]
        for case in failing_cases:
            with self.subTest(case=case["name"]):
                receive = deque([
                    {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
                ])
                sent = []
                with self.assertRaises(AdapterUnsupportedError):
                    await guard_litellm_proxy(
                        AgentControl(QueueRuntime([verdict()])),
                        _streaming_app((STREAMING / case["input"]).read_bytes()),
                    )(
                        {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                        receive.popleft,
                        sent.append,
                    )
                self.assertEqual(sent, [])

    async def test_litellm_public_stream_oversize_limits_fail_closed(self):
        oversize_bytes = b": keepalive\n\n" + (b"x" * (_sse.MAX_STREAM_BYTES + 1))
        with self.assertRaises(AdapterUnsupportedError):
            await _call_litellm(oversize_bytes, QueueRuntime([verdict()]))

        event = _sse_bytes(_chunk("x"), done=False)
        too_many = event * (_sse.MAX_STREAM_EVENTS + 1) + b"data: [DONE]\n\n"
        with self.assertRaises(AdapterUnsupportedError):
            await _call_litellm(too_many, QueueRuntime([verdict()]))

    async def test_tool_call_streaming_many_fragments_parallel_indices_and_downstream_redaction(self):
        raw = _sse_bytes(
            _chunk(role="assistant", tool_calls=[{"index": 1, "id": "call_b", "type": "function", "function": {"name": "write", "arguments": "{\"path\":"}}]),
            _chunk(tool_calls=[{"index": 0, "id": "call_a", "type": "function", "function": {"name": "search", "arguments": "{\"query\":"}}]),
            _chunk(tool_calls=[{"index": 1, "function": {"arguments": "\"secret.py\"}"}}]),
            _chunk(tool_calls=[{"index": 0, "function": {"arguments": "\"token-123\"}"}}]),
            _chunk(finish_reason="tool_calls"),
        )
        transformed = _sse.assemble_sse_stream(raw)
        transformed["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"query":"[redacted]"}'
        runtime = QueueRuntime([verdict(), verdict(transformed_policy_target=transformed)])
        sent = await _call_litellm(raw, runtime)
        assembled = _sse.assemble_sse_stream(_body_from_sent(sent))
        calls = assembled["choices"][0]["message"]["tool_calls"]
        self.assertEqual([call["id"] for call in calls], ["call_a", "call_b"])
        seen = []

        async def downstream_tool(args):
            seen.append(args)
            return {"ok": True}

        args = json.loads(calls[0]["function"]["arguments"])
        await guard_tool(
            AgentControl(QueueRuntime([verdict(), verdict()])),
            calls[0]["function"]["name"],
            downstream_tool,
            tool_call_id=calls[0]["id"],
        )(args)
        self.assertEqual(seen, [{"query": "[redacted]"}])

    async def test_escalate_approval_seam_receives_exact_context_and_rejects_deterministically(self):
        raw = _sse_bytes(_chunk("needs approval", role="assistant"), _chunk(finish_reason="stop"))
        seen = []

        async def approve(point, result):
            seen.append((point, result.policy_input, result.action_identity))
            return ApprovalResolution.allow(result.action_identity)

        runtime = QueueRuntime([verdict(), verdict(Decision.ESCALATE, reason="review")])
        control = AgentControl(runtime, approval_resolver=approve)
        receive = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        sent = []
        await guard_litellm_proxy(control, _streaming_app(raw))(
            {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
            receive.popleft,
            sent.append,
        )
        self.assertEqual(_body_from_sent(sent), raw)
        self.assertEqual(seen[0][0], InterventionPoint.POST_MODEL_CALL)
        self.assertEqual(seen[0][1]["snapshot"], runtime.requests[1].snapshot)
        self.assertEqual(seen[0][1]["intervention_point"], "post_model_call")
        self.assertEqual(seen[0][2], action_identity(seen[0][1]))

        async def reject(point, result):
            return ApprovalResolution.deny()

        with self.assertRaises(AgentControlBlocked):
            await _call_litellm(raw, QueueRuntime([verdict(), verdict(Decision.ESCALATE, reason="review")]))
        receive = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        with self.assertRaises(AgentControlBlocked):
            await guard_litellm_proxy(
                AgentControl(QueueRuntime([verdict(), verdict(Decision.ESCALATE, reason="review")]), approval_resolver=reject),
                _streaming_app(raw),
            )(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                receive.popleft,
                lambda message: None,
            )

    async def test_runtime_and_adapter_failures_release_no_stream_bytes(self):
        raw = _sse_bytes(_chunk("secret", role="assistant"), _chunk(finish_reason="stop"))
        receive = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        sent = []
        with self.assertRaises(RuntimeError):
            await guard_litellm_proxy(AgentControl(FailingRuntime(RuntimeError("policy failed"))), _streaming_app(raw))(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                receive.popleft,
                sent.append,
            )
        self.assertEqual(sent, [])

        async def approval_raises(point, result):
            raise RuntimeError("approval failed")

        receive = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        sent = []
        with self.assertRaises(AgentControlBlocked):
            await guard_litellm_proxy(
                AgentControl(
                    QueueRuntime([verdict(), verdict(Decision.ESCALATE, reason="review")]),
                    approval_resolver=approval_raises,
                ),
                _streaming_app(raw),
            )(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                receive.popleft,
                sent.append,
            )
        self.assertEqual(sent, [])

        async def exploding_app(scope, receive, send):
            raise TypeError("not serializable")

        receive = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        sent = []
        with self.assertRaises(TypeError):
            await guard_litellm_proxy(
                AgentControl(QueueRuntime([verdict(transformed_policy_target={"stream": True, "bad": object()})])),
                exploding_app,
            )(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                receive.popleft,
                sent.append,
            )
        self.assertEqual(sent, [])

    async def test_concurrent_streams_do_not_share_buffer_or_decision_state(self):
        safe_raw = _sse_bytes(_chunk("safe", role="assistant"), _chunk(finish_reason="stop"))
        secret_raw = _sse_bytes(_chunk("secret", role="assistant"), _chunk(finish_reason="stop"))
        transformed = _sse.assemble_sse_stream(secret_raw)
        transformed["choices"][0]["message"]["content"] = "[redacted]"

        async def run_one(raw, runtime):
            return _body_from_sent(await _call_litellm(raw, runtime))

        allowed, redacted = await asyncio.gather(
            run_one(safe_raw, QueueRuntime([verdict(), verdict()])),
            run_one(secret_raw, QueueRuntime([verdict(), verdict(transformed_policy_target=transformed)])),
        )
        self.assertEqual(allowed, safe_raw)
        self.assertIn(b"[redacted]", redacted)
        self.assertNotIn(b"secret", redacted)

    async def test_openai_raw_sse_chat_stream_is_guarded_and_responses_stream_fails_closed(self):
        class ChatCompletions:
            async def create(self, **kwargs):
                self.kwargs = kwargs
                return _sse_bytes(_chunk("hello", role="assistant"), _chunk(finish_reason="stop"))

        class Responses:
            async def create(self, **kwargs):
                return b"data: [DONE]\n\n"

        client = type("Client", (), {})()
        client.chat = type("Chat", (), {"completions": ChatCompletions()})()
        client.responses = Responses()
        runtime = QueueRuntime([verdict(), verdict()])
        body = await guard_openai_client(AgentControl(runtime), client).chat.completions.create(
            model="gpt", messages=[], stream=True
        )
        self.assertEqual(body, _sse_bytes(_chunk("hello", role="assistant"), _chunk(finish_reason="stop")))
        self.assertEqual(runtime.requests[1].snapshot["model_response"]["choices"][0]["message"]["content"], "hello")

        with self.assertRaises(AdapterUnsupportedError):
            await guard_openai_client(AgentControl(QueueRuntime([])), client).responses.create(model="gpt", input="x", stream=True)

    async def test_openai_sdk_object_stream_is_guarded_and_anthropic_stream_fails_closed(self):
        class Chunk:
            def __init__(self, content=None, role=None, finish_reason=None):
                self.content = content
                self.role = role
                self.finish_reason = finish_reason

            def model_dump(self):
                delta = {}
                if self.role is not None:
                    delta["role"] = self.role
                if self.content is not None:
                    delta["content"] = self.content
                return {
                    "id": "chatcmpl-stream",
                    "object": "chat.completion.chunk",
                    "model": "gpt",
                    "choices": [
                        {"index": 0, "delta": delta, "finish_reason": self.finish_reason}
                    ],
                }

        class ObjectStream:
            def __iter__(self):
                yield Chunk("hello", role="assistant")
                yield Chunk(finish_reason="stop")

        class ChatCompletions:
            async def create(self, **kwargs):
                return ObjectStream()

        client = type("Client", (), {})()
        client.chat = type("Chat", (), {"completions": ChatCompletions()})()
        body = await guard_openai_client(
            AgentControl(
                QueueRuntime([
                    verdict(),
                    InterventionPointResult(
                        Verdict(Decision.TRANSFORM),
                        transformed_policy_target="redacted",
                        transformed_policy_target_applied=True,
                        policy_input={
                            "policy_target": {
                                "path": "$.model_response.choices[0].message.content"
                            }
                        },
                        enforced_identity="sha256:test",
                    ),
                ])
            ),
            client,
        ).chat.completions.create(
            model="gpt", messages=[], stream=True
        )
        self.assertEqual(_sse.assemble_sse_stream(body)["choices"][0]["message"]["content"], "redacted")

        class Messages:
            async def create(self, **kwargs):
                return object()

        anthropic = type("Anthropic", (), {"messages": Messages()})()
        with self.assertRaises(AdapterUnsupportedError):
            await guard_anthropic_client(AgentControl(QueueRuntime([])), anthropic).messages.create(
                model="claude", messages=[], stream=True
            )


@unittest.skipUnless(_NATIVE_AVAILABLE, "agent_control_specification._native extension is not built")
class AnnotatorOrderingStreamingTests(unittest.TestCase):
    def test_annotator_dispatch_precedes_policy_evaluation(self):
        manifest = """agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: custom
    adapter: test
intervention_points:
  post_model_call:
    policy:
      id: p
    policy_target: $.model_response
    annotations:
      normalize:
        from: $.model_response.choices[0].message.content
annotators:
  normalize:
    type: classifier
"""

        class Annotator:
            def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
                return {"normalized": preliminary_policy_input["policy_target"]["value"]["choices"][0]["message"]["content"].lower()}

        class Policy:
            def evaluate(self, invocation):
                normalized = invocation["input"]["annotations"]["normalize"]["normalized"]
                if normalized == "secret":
                    # AGT D1: effects[] rejected; use transform decision
                    # for single-target replacement.
                    return {
                        "decision": "transform",
                        "transform": {
                            "path": "$policy_target.choices[0].message.content",
                            "value": "[redacted]",
                        },
                    }
                return {"decision": "allow"}

        async def run():
            control = AgentControl.from_native(manifest, Annotator(), Policy())
            return await control.evaluate_intervention_point(
                InterventionPoint.POST_MODEL_CALL,
                {
                    "model_request": {"stream": True},
                    "model_response": {
                        "choices": [{"message": {"content": "SECRET"}, "finish_reason": "stop"}]
                    },
                },
            )

        result = asyncio.run(run())
        self.assertEqual(result.transformed_policy_target["choices"][0]["message"]["content"], "[redacted]")


if __name__ == "__main__":
    unittest.main()
