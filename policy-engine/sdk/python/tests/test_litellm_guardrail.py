# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import asyncio
import unittest
from collections import deque

from agent_control_specification import (
    AgentControl,
    AgentControlLiteLLMGuardrail,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    Transform,
    Verdict,
)


def result(decision=Decision.ALLOW, transformed_policy_target=None):
    if transformed_policy_target is not None and decision == Decision.ALLOW:
        decision = Decision.TRANSFORM
    transform = (
        Transform(path="$policy_target", value=transformed_policy_target)
        if decision == Decision.TRANSFORM
        else None
    )
    return InterventionPointResult(
        Verdict(decision, transform=transform),
        transformed_policy_target=transformed_policy_target,
    )


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()


class LiteLLMGuardrailHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_pre_call_maps_user_input_then_pre_model_and_applies_transforms(self):
        runtime = QueueRuntime([
            result(transformed_policy_target="safe user"),
            result(transformed_policy_target={"model": "gpt", "messages": [{"role": "user", "content": "final"}]}),
        ])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime))
        data = {"model": "gpt", "messages": [{"role": "user", "content": "raw user"}]}

        out = await guard.async_pre_call_hook(None, None, data, "completion")

        self.assertIs(out, data)
        self.assertEqual(data["messages"][0]["content"], "final")
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.INPUT, InterventionPoint.PRE_MODEL_CALL])
        self.assertEqual(runtime.requests[0].snapshot["input"], "raw user")
        self.assertEqual(runtime.requests[1].snapshot["model_request"]["messages"][0]["content"], "safe user")

    async def test_post_call_maps_post_model_pre_tool_and_records_correlation(self):
        runtime = QueueRuntime([
            result(),
            result(transformed_policy_target={"query": "redacted"}),
        ])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime))
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": '{"query":"secret"}'}}
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }

        out = await guard.async_post_call_success_hook({"metadata": {"acs_session_id": "s1"}}, None, response)

        self.assertIs(out, response)
        self.assertEqual(response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"], '{"query":"redacted"}')
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.POST_MODEL_CALL, InterventionPoint.PRE_TOOL_CALL])
        self.assertEqual(runtime.requests[1].snapshot["tool_call"], {"id": "call_1", "name": "search", "args": {"query": "secret"}})

    async def test_pre_call_maps_correlated_tool_result_to_post_tool_call(self):
        runtime = QueueRuntime([
            result(),
            result(),
            result(transformed_policy_target="clean result"),
            result(),
        ])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime))
        sid = {"metadata": {"acs_session_id": "s2"}}
        response = {"choices": [{"message": {"role": "assistant", "tool_calls": [{"id": "call_2", "function": {"name": "lookup", "arguments": "{}"}}]}}]}
        await guard.async_post_call_success_hook(sid, None, response)
        data = {**sid, "messages": [{"role": "tool", "tool_call_id": "call_2", "content": "raw result"}]}

        await guard.async_pre_call_hook(None, None, data, "completion")

        self.assertEqual(data["messages"][0]["content"], "clean result")
        self.assertEqual(runtime.requests[2].intervention_point, InterventionPoint.POST_TOOL_CALL)
        self.assertEqual(runtime.requests[2].snapshot["tool_call"], {"id": "call_2", "name": "lookup", "args": {}})

    async def test_evaluate_only_observes_without_mutating_request_response_tool_args_or_results(self):
        runtime = QueueRuntime([
            result(transformed_policy_target="safe user"),
            result(transformed_policy_target={"model": "gpt", "messages": [{"role": "user", "content": "final"}]}),
            result(),
            result(transformed_policy_target={"query": "redacted"}),
            result(transformed_policy_target="clean result"),
            result(transformed_policy_target={"messages": [{"role": "tool", "tool_call_id": "call_eval", "content": "clean result"}]}),
            result(),
            result(transformed_policy_target="redacted answer"),
        ])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime), mode="evaluate_only")

        request = {"model": "gpt", "messages": [{"role": "user", "content": "raw user"}]}
        await guard.async_pre_call_hook(None, None, request, "completion")
        self.assertEqual(request, {"model": "gpt", "messages": [{"role": "user", "content": "raw user"}]})

        sid = {"metadata": {"acs_session_id": "eval-only"}}
        tool_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {"id": "call_eval", "type": "function", "function": {"name": "search", "arguments": '{"query":"secret"}'}}
                        ],
                    }
                }
            ]
        }
        await guard.async_post_call_success_hook(sid, None, tool_response)
        self.assertEqual(tool_response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"], '{"query":"secret"}')

        tool_result_request = {**sid, "messages": [{"role": "tool", "tool_call_id": "call_eval", "content": "raw result"}]}
        await guard.async_pre_call_hook(None, None, tool_result_request, "completion")
        self.assertEqual(tool_result_request["messages"][0]["content"], "raw result")

        final_response = {"choices": [{"message": {"role": "assistant", "content": "secret answer"}}]}
        out = await guard.async_post_call_success_hook({}, None, final_response)
        self.assertIs(out, final_response)
        self.assertEqual(final_response["choices"][0]["message"]["content"], "secret answer")
        self.assertTrue(all(req.mode == EnforcementMode.EVALUATE_ONLY for req in runtime.requests))

    async def test_streaming_evaluate_only_uses_per_call_mode_without_disabling_enforcement(self):
        class BlockingRuntime:
            def __init__(self):
                self.requests = []
                self.started = asyncio.Event()
                self.release = asyncio.Event()

            async def evaluate_intervention_point(self, request):
                self.requests.append(request)
                response = request.snapshot.get("model_response")
                content = None
                if isinstance(response, dict):
                    content = response.get("choices", [{}])[0].get("message", {}).get("content")
                if content == "stream" and request.intervention_point == InterventionPoint.POST_MODEL_CALL:
                    self.started.set()
                    await self.release.wait()
                if request.intervention_point == InterventionPoint.OUTPUT:
                    return result(transformed_policy_target="enforced")
                return result()

        runtime = BlockingRuntime()
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime), streaming="evaluate_only")

        async def stream():
            yield {"id": "c3", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "stream"}, "finish_reason": "stop"}]}

        async def consume_stream():
            return [chunk async for chunk in guard.async_post_call_streaming_iterator_hook(None, stream(), {})]

        streaming_task = asyncio.create_task(consume_stream())
        await runtime.started.wait()
        normal_response = {"choices": [{"message": {"role": "assistant", "content": "normal"}}]}
        normal_out = await guard.async_post_call_success_hook({}, None, normal_response)
        runtime.release.set()
        stream_out = await streaming_task

        self.assertIs(normal_out, normal_response)
        self.assertEqual(normal_response["choices"][0]["message"]["content"], "enforced")
        self.assertEqual(stream_out[0]["choices"][0]["delta"]["content"], "stream")
        self.assertEqual(guard.mode, EnforcementMode.ENFORCE)
        self.assertIn(EnforcementMode.EVALUATE_ONLY, [req.mode for req in runtime.requests])
        self.assertIn(EnforcementMode.ENFORCE, [req.mode for req in runtime.requests])


    async def test_unknown_tool_result_fails_closed_before_pre_model(self):
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(QueueRuntime([])))
        data = {"messages": [{"role": "tool", "tool_call_id": "made-up", "content": "fabricated"}]}

        with self.assertRaises(Exception):
            await guard.async_pre_call_hook(None, None, data, "completion")

    async def test_output_transform_rewrites_final_assistant_content(self):
        runtime = QueueRuntime([
            result(),
            result(transformed_policy_target="redacted answer"),
        ])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime))
        response = {"choices": [{"message": {"role": "assistant", "content": "secret answer"}}]}

        out = await guard.async_post_call_success_hook({}, None, response)

        self.assertIs(out, response)
        self.assertEqual(response["choices"][0]["message"]["content"], "redacted answer")
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.POST_MODEL_CALL, InterventionPoint.OUTPUT])

    async def test_streaming_buffer_evaluates_complete_response_before_replay(self):
        runtime = QueueRuntime([result(), result()])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime))

        async def stream():
            yield {"id": "c1", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}}]}
            yield {"id": "c1", "choices": [{"index": 0, "delta": {"content": "lo"}, "finish_reason": "stop"}]}

        out = []
        async for chunk in guard.async_post_call_streaming_iterator_hook(None, stream(), {}):
            out.append(chunk)

        self.assertEqual(len(out), 2)
        self.assertEqual(runtime.requests[0].snapshot["model_response"]["choices"][0]["message"]["content"], "Hello")

    async def test_streaming_transform_emits_replacement_chunk(self):
        runtime = QueueRuntime([result(), result(transformed_policy_target="clean")])
        guard = AgentControlLiteLLMGuardrail(control=AgentControl(runtime))

        async def stream():
            yield {"id": "c2", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "secret"}, "finish_reason": "stop"}]}

        out = []
        async for chunk in guard.async_post_call_streaming_iterator_hook(None, stream(), {}):
            out.append(chunk)

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["choices"][0]["delta"]["content"], "clean")


if __name__ == "__main__":
    unittest.main()
