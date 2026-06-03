from __future__ import annotations

import json
import unittest
from collections import deque
from collections.abc import Mapping
from unittest.mock import patch

from agent_control_specification import (
    AdapterUnsupportedError,
    AgentControl,
    AgentControlBlocked,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
    guard_anthropic_client,
    guard_autogen_agent,
    guard_crewai_crew,
    guard_langchain_runnable,
    guard_litellm_proxy,
    guard_mcp_server,
    guard_mcp_tool,
    guard_model_call,
    guard_openai_agents_runner,
    guard_openai_client,
    guard_run,
    guard_semantic_kernel_filter,
    guard_semantic_kernel_function,
    guard_tool,
    run_model_call,
)


def result(decision=None, transformed_policy_target=None, transformed_policy_target_applied=False):
    # AGT D1: only Decision.TRANSFORM applies the engine's
    # transformed_policy_target. Helper defaults to TRANSFORM when the
    # caller supplied a transformed_policy_target so existing call sites
    # exercise the canonical mutation path without spelling it out.
    if decision is None:
        decision = (
            Decision.TRANSFORM
            if transformed_policy_target is not None or transformed_policy_target_applied
            else Decision.ALLOW
        )
    return InterventionPointResult(
        Verdict(decision),
        transformed_policy_target=transformed_policy_target,
        transformed_policy_target_applied=transformed_policy_target_applied,
    )


def _sse(*chunks):
    frames = [f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks]
    frames.append("data: [DONE]\n\n")
    return "".join(frames).encode("utf-8")


def _chat_stream_chunks():
    base = {"id": "c1", "model": "gpt", "created": 1}
    return [
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hello"}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"content": " world"}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]


def _streaming_app(sse_bytes, seen_bodies=None, content_type=b"text/event-stream"):
    async def app(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        if seen_bodies is not None:
            seen_bodies.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", content_type)]})
        await send({"type": "http.response.body", "body": sse_bytes, "more_body": False})

    return app


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_guard_run_merges_snapshots_and_keeps_non_reserved_kwargs(self):
        runtime = QueueRuntime([result(transformed_policy_target={"text": "safe"}), result(transformed_policy_target={"answer": "redacted"})])
        seen = []

        async def execute(value, suffix="", **kwargs):
            seen.append((value, kwargs))
            return {"answer": value["text"] + suffix}

        guarded = guard_run(AgentControl(runtime), execute, snapshot={"tenant": "base", "trace": "t"})
        value = await guarded(
            {"text": "raw"},
            suffix="!",
            agent_control_snapshot={"tenant": "override", "request_id": "r1"},
            agent_control_mode="caller-value",
        )

        self.assertEqual(value, {"answer": "redacted"})
        self.assertEqual(seen, [({"text": "safe"}, {"agent_control_mode": "caller-value"})])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.INPUT, InterventionPoint.OUTPUT])
        self.assertEqual(runtime.requests[0].snapshot, {"tenant": "override", "trace": "t", "request_id": "r1", "input": {"text": "raw"}})

    async def test_wrapper_mode_controls_enforcement_not_per_call_kwargs(self):
        denied = QueueRuntime([result(Decision.DENY)])
        guarded = guard_run(AgentControl(denied), lambda value, **kwargs: value)
        with self.assertRaises(AgentControlBlocked):
            await guarded("unsafe", agent_control_mode="evaluate_only")
        self.assertEqual(denied.requests[0].mode, EnforcementMode.ENFORCE)

        observed = QueueRuntime([result(Decision.DENY), result()])
        executed = False

        async def execute(value):
            nonlocal executed
            executed = True
            return value

        await guard_run(AgentControl(observed), execute, mode=EnforcementMode.EVALUATE_ONLY)("observed")
        self.assertTrue(executed)
        self.assertEqual([r.mode for r in observed.requests], [EnforcementMode.EVALUATE_ONLY, EnforcementMode.EVALUATE_ONLY])

    async def test_run_model_call_transforms_pre_and_post_policy_targets(self):
        runtime = QueueRuntime([
            result(transformed_policy_target={"messages": [{"content": "safe"}]}),
            result(transformed_policy_target={"content": "redacted"}),
        ])
        seen = []

        async def call_model(request):
            seen.append(request)
            return {"content": "raw response"}

        model_result = await run_model_call(AgentControl(runtime), {"messages": [{"content": "raw"}]}, call_model, snapshot={"conversation_id": "c1"})

        self.assertEqual(model_result.value, {"content": "redacted"})
        self.assertEqual(seen, [{"messages": [{"content": "safe"}]}])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_MODEL_CALL, InterventionPoint.POST_MODEL_CALL])
        self.assertEqual(runtime.requests[0].snapshot["model_request"]["messages"][0]["content"], "raw")
        self.assertEqual(runtime.requests[1].snapshot["model_response"], {"content": "raw response"})

    async def test_run_model_call_applies_explicit_null_transform(self):
        runtime = QueueRuntime([
            result(transformed_policy_target=None, transformed_policy_target_applied=True),
            result(),
        ])
        seen = []

        async def call_model(request):
            seen.append(request)
            return {"content": "raw response"}

        await run_model_call(AgentControl(runtime), {"messages": [{"content": "raw"}]}, call_model)

        self.assertEqual(seen, [None])

    async def test_guard_model_call_blocks_before_execute(self):
        runtime = QueueRuntime([result(Decision.DENY)])
        executed = False

        async def call_model(request):
            nonlocal executed
            executed = True
            return request

        with self.assertRaises(AgentControlBlocked):
            await guard_model_call(AgentControl(runtime), call_model)({"messages": []})
        self.assertFalse(executed)
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_MODEL_CALL])

    async def test_guard_tool_transforms_args_result_and_allows_absent_call_id(self):
        runtime = QueueRuntime([result(transformed_policy_target={"x": 2}), result(transformed_policy_target={"sum": 4})])
        seen = []

        async def add(args, increment):
            seen.append(args)
            return {"sum": args["x"] + increment}

        guarded = guard_tool(AgentControl(runtime), "adder", add, snapshot={"scope": "tools"})
        value = await guarded({"x": 1}, 1, agent_control_tool_call_id="tool-1", agent_control_snapshot={"turn": "t1"})

        self.assertEqual(value, {"sum": 4})
        self.assertEqual(seen, [{"x": 2}])
        self.assertEqual(runtime.requests[0].snapshot["tool_call"], {"id": "tool-1", "name": "adder", "args": {"x": 1}})
        self.assertEqual(runtime.requests[1].snapshot["tool_result"], {"sum": 3})
        self.assertEqual(runtime.requests[1].snapshot["turn"], "t1")

        guarded_no_id = guard_tool(AgentControl(QueueRuntime([result(), result()])), "adder", add)
        await guarded_no_id({"x": 1}, 1)

    async def test_mcp_tool_alias_uses_tool_intervention_points(self):
        runtime = QueueRuntime([result(transformed_policy_target={"query": "safe"}), result(transformed_policy_target={"value": "redacted"})])
        seen = []

        async def handler(args, context=None):
            seen.append((args, context))
            return {"value": args["query"], "context": context}

        guarded = guard_mcp_tool(AgentControl(runtime), "search", handler, snapshot={"server": "mcp"})
        value = await guarded({"query": "raw"}, context={"user": "u1"}, agent_control_tool_call_id="mcp-call-1", agent_control_snapshot={"turn": "t1"})

        self.assertEqual(value, {"value": "redacted"})
        self.assertEqual(seen, [({"query": "safe"}, {"user": "u1"})])
        self.assertEqual(runtime.requests[1].snapshot["server"], "mcp")
        self.assertEqual(runtime.requests[1].snapshot["turn"], "t1")

    async def test_langchain_adapter_wraps_ainvoke_and_blocks_sync_bypass(self):
        class FakeRunnable:
            async def ainvoke(self, value, config=None):
                return {"answer": value["text"], "config": config}

            def invoke(self, value):
                return {"unguarded": value}

        runtime = QueueRuntime([result(transformed_policy_target={"text": "safe"}), result(transformed_policy_target={"answer": "redacted"})])
        guarded = guard_langchain_runnable(AgentControl(runtime), FakeRunnable())

        self.assertEqual(await guarded.ainvoke({"text": "raw"}, config={"tags": ["demo"]}), {"answer": "redacted"})
        self.assertEqual(runtime.requests[1].snapshot["output"], {"answer": "safe", "config": {"tags": ["demo"]}})
        with self.assertRaises(AdapterUnsupportedError):
            guarded.invoke({"text": "raw"})

    async def test_openai_adapter_guards_chat_completions_create(self):
        class FakeCompletions:
            def __init__(self):
                self.calls = []

            async def create(self, **kwargs):
                self.calls.append(kwargs)
                return {"choices": [{"message": {"content": kwargs["messages"][0]["content"]}}]}

        class FakeClient:
            def __init__(self):
                self.chat = type("Chat", (), {"completions": FakeCompletions()})()

        runtime = QueueRuntime([
            result(transformed_policy_target={"model": "gpt", "messages": [{"content": "safe"}]}),
            result(transformed_policy_target={"choices": []}),
        ])
        client = FakeClient()
        value = await guard_openai_client(AgentControl(runtime), client, snapshot={"provider": "openai"}).chat.completions.create(
            model="gpt",
            messages=[{"content": "raw"}],
            agent_control_snapshot={"request_id": "r2"},
        )

        self.assertEqual(value, {"choices": []})
        self.assertEqual(client.chat.completions.calls, [{"model": "gpt", "messages": [{"content": "safe"}]}])
        self.assertEqual(runtime.requests[1].snapshot["provider"], "openai")
        self.assertEqual(runtime.requests[1].snapshot["request_id"], "r2")

    async def test_openai_adapter_jsonifies_and_restores_sdk_response_shape(self):
        class FakeCompletion:
            def __init__(self, data):
                self.data = data
                self.choices = data["choices"]

            def model_dump(self):
                return self.data

            @classmethod
            def model_validate(cls, data):
                return cls({**data, "validated": True})

        class FakeCompletions:
            async def create(self, **kwargs):
                return FakeCompletion(
                    {
                        "id": "chatcmpl-test",
                        "object": "chat.completion",
                        "choices": [
                            {"message": {"role": "assistant", "content": kwargs["messages"][0]["content"]}}
                        ],
                    }
                )

        client = type("Client", (), {})()
        client.chat = type("Chat", (), {"completions": FakeCompletions()})()
        runtime = QueueRuntime([
            result(),
            InterventionPointResult(
                Verdict(Decision.TRANSFORM),
                transformed_policy_target="redacted",
                transformed_policy_target_applied=True,
                policy_input={
                    "policy_target": {
                        "path": "$.model_response.choices[0].message.content"
                    }
                },
            ),
        ])

        value = await guard_openai_client(AgentControl(runtime), client).chat.completions.create(
            model="gpt",
            messages=[{"content": "secret"}],
        )

        self.assertIsInstance(value, FakeCompletion)
        self.assertEqual(value.choices[0]["message"]["content"], "redacted")
        self.assertTrue(value.data["validated"])
        self.assertEqual(
            runtime.requests[1].snapshot["model_response"]["choices"][0]["message"]["content"],
            "secret",
        )

    async def test_openai_agents_adapter_preserves_final_output_shape_when_redacting(self):
        class FakeRunResult:
            def __init__(self, final_output, trace):
                self.final_output = final_output
                self.trace = trace

        class Runner:
            def __init__(self):
                self.calls = []

            async def run(self, agent, value, **kwargs):
                self.calls.append((agent, value, kwargs))
                return FakeRunResult("token SRC-ABCDEFGH", trace=["kept"])

        runtime = QueueRuntime([
            result(),
            result(transformed_policy_target="token [REDACTED]", transformed_policy_target_applied=True),
        ])
        runner = Runner()
        guarded = guard_openai_agents_runner(AgentControl(runtime), runner)

        value = await guarded.run("agent", "research", max_turns=1)

        self.assertIsInstance(value, FakeRunResult)
        self.assertEqual(value.final_output, "token [REDACTED]")
        self.assertEqual(value.trace, ["kept"])
        self.assertEqual(runner.calls, [("agent", "research", {"max_turns": 1})])
        self.assertEqual(runtime.requests[1].snapshot["output"], "token SRC-ABCDEFGH")

    async def test_openai_agents_runner_handles_positional_keyword_inputs_and_blocks_bypasses(self):
        class FakeRunner:
            def __init__(self):
                self.calls = []

            async def run(self, agent, input, **kwargs):
                self.calls.append((agent, input, kwargs))
                return {"answer": input["text"]}

            def run_sync(self, agent, input):
                return input

            async def run_streamed(self, agent, input):
                return input

        runtime = QueueRuntime([
            result(transformed_policy_target={"text": "safe-pos"}), result(transformed_policy_target={"answer": "redacted-pos"}),
            result(transformed_policy_target={"text": "safe-kw"}), result(transformed_policy_target={"answer": "redacted-kw"}),
        ])
        runner = FakeRunner()
        agent = object()
        guarded = guard_openai_agents_runner(AgentControl(runtime), runner, snapshot={"provider": "openai-agents"})

        self.assertEqual(await guarded.run(agent, {"text": "raw-pos"}, session="s1", agent_control_snapshot={"request_id": "r-pos"}), {"answer": "redacted-pos"})
        self.assertEqual(await guarded.run(agent, input={"text": "raw-kw"}, session="s2"), {"answer": "redacted-kw"})
        self.assertEqual(runner.calls, [(agent, {"text": "safe-pos"}, {"session": "s1"}), (agent, {"text": "safe-kw"}, {"session": "s2"})])
        self.assertEqual(runtime.requests[1].snapshot["provider"], "openai-agents")
        with self.assertRaises(AdapterUnsupportedError):
            guarded.run_sync(agent, {"text": "raw"})
        with self.assertRaises(AdapterUnsupportedError):
            guarded.run_streamed(agent, input={"text": "raw"})

    async def test_openai_agents_runner_mode_kwarg_cannot_downgrade_enforcement(self):
        class FakeRunner:
            executed = False

            async def run(self, agent, input, **kwargs):
                self.executed = True
                return input

        runtime = QueueRuntime([result(Decision.DENY)])
        runner = FakeRunner()
        with self.assertRaises(AgentControlBlocked):
            await guard_openai_agents_runner(AgentControl(runtime), runner).run(object(), "unsafe", agent_control_mode="evaluate_only")
        self.assertFalse(runner.executed)
        self.assertEqual(runtime.requests[0].mode, EnforcementMode.ENFORCE)

    async def test_anthropic_adapter_guards_messages_create(self):
        class FakeMessages:
            def __init__(self):
                self.calls = []

            async def create(self, **kwargs):
                self.calls.append(kwargs)
                return {"content": [{"text": kwargs["messages"][0]["content"]}]}

        client = type("Client", (), {"messages": FakeMessages()})()
        runtime = QueueRuntime([
            result(transformed_policy_target={"model": "claude", "messages": [{"content": "safe"}]}),
            result(transformed_policy_target={"content": [{"text": "redacted"}]}),
        ])

        self.assertEqual(await guard_anthropic_client(AgentControl(runtime), client).messages.create(model="claude", messages=[{"content": "raw"}]), {"content": [{"text": "redacted"}]})
        self.assertEqual(client.messages.calls, [{"model": "claude", "messages": [{"content": "safe"}]}])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_MODEL_CALL, InterventionPoint.POST_MODEL_CALL])

    async def test_autogen_and_crewai_adapters_guard_duck_typed_methods(self):
        class FakeAutoGenAgent:
            async def run(self, input):
                return {"autogen": input["task"]}

        class FakeCrew:
            async def kickoff(self, inputs):
                return {"crew": inputs["topic"]}

        runtime = QueueRuntime([
            result(transformed_policy_target={"task": "safe task"}), result(transformed_policy_target={"autogen": "redacted"}),
            result(transformed_policy_target={"topic": "safe topic"}), result(transformed_policy_target={"crew": "redacted"}),
        ])
        control = AgentControl(runtime)

        self.assertEqual(await guard_autogen_agent(control, FakeAutoGenAgent()).run({"task": "raw task"}), {"autogen": "redacted"})
        self.assertEqual(await guard_crewai_crew(control, FakeCrew()).kickoff(inputs={"topic": "raw topic"}), {"crew": "redacted"})
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.INPUT, InterventionPoint.OUTPUT, InterventionPoint.INPUT, InterventionPoint.OUTPUT])

    async def test_mcp_server_tool_provider_guards_call_tool(self):
        class FakeMcpServer:
            def __init__(self):
                self.calls = []

            async def call_tool(self, request, context=None):
                self.calls.append((request, context))
                return {"value": request["arguments"]["query"], "context": context}

        runtime = QueueRuntime([result(transformed_policy_target={"query": "safe"}), result(transformed_policy_target={"value": "redacted"})])
        server = FakeMcpServer()
        value = await guard_mcp_server(AgentControl(runtime), server, snapshot={"server": "mcp"}).call_tool(
            {"id": "mcp-call-2", "name": "search", "arguments": {"query": "raw"}},
            {"user": "u1"},
            agent_control_snapshot={"turn": "t2"},
        )

        self.assertEqual(value, {"value": "redacted"})
        self.assertEqual(server.calls, [({"id": "mcp-call-2", "name": "search", "arguments": {"query": "safe"}}, {"user": "u1"})])
        self.assertEqual(runtime.requests[0].snapshot["tool_call"]["args"], {"query": "raw"})
        self.assertEqual(runtime.requests[1].snapshot["server"], "mcp")

    async def test_mcp_server_rejects_explicit_empty_tool_call_id(self):
        class FakeMcpServer:
            async def call_tool(self, request):
                return {"value": request["arguments"]["query"]}

        runtime = QueueRuntime([result(), result()])
        server = guard_mcp_server(AgentControl(runtime), FakeMcpServer())

        with self.assertRaisesRegex(ValueError, "non-empty"):
            await server.call_tool({"id": "", "name": "search", "arguments": {"query": "raw"}})
        self.assertEqual(runtime.requests, [])

    async def test_mcp_server_blocks_unsupported_provider_methods(self):
        class FakeMcpServer:
            def __init__(self):
                self.calls = []

            async def call_tool(self, request):
                self.calls.append(("call_tool", request))
                return {"value": request["arguments"]["query"]}

            async def read_resource(self, request):
                self.calls.append(("read_resource", request))
                return {"content": "raw"}

            async def get_prompt(self, request):
                self.calls.append(("get_prompt", request))
                return {"prompt": "raw"}

            async def stream(self, request):
                self.calls.append(("stream", request))
                return {"chunk": "raw"}

            async def initialize(self):
                self.calls.append(("initialize", None))
                return {"ok": True}

        runtime = QueueRuntime([result(), result()])
        raw_server = FakeMcpServer()
        server = guard_mcp_server(AgentControl(runtime), raw_server)

        for method_name in ("read_resource", "get_prompt", "stream", "initialize"):
            with self.subTest(method_name=method_name):
                with self.assertRaises(AdapterUnsupportedError):
                    await getattr(server, method_name)({})

        self.assertEqual(raw_server.calls, [])
        self.assertEqual(runtime.requests, [])

    async def test_semantic_kernel_function_allow_path_returns_result(self):
        class FakeFunction:
            name = "search"

            async def invoke(self, kernel, arguments):
                return {"value": arguments["query"], "kernel": kernel}

        runtime = QueueRuntime([result(), result()])
        value = await guard_semantic_kernel_function(
            AgentControl(runtime),
            FakeFunction(),
            tool_call_id="sk-call-1",
        ).invoke("kernel", {"query": "safe"})

        self.assertEqual(value, {"value": "safe", "kernel": "kernel"})
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL])

    async def test_semantic_kernel_function_transform_mutates_invoke_arguments(self):
        class FakeFunction:
            name = "search"

            def __init__(self):
                self.calls = []

            async def invoke(self, kernel, arguments):
                self.calls.append(dict(arguments))
                return {"value": arguments["query"]}

        function = FakeFunction()
        runtime = QueueRuntime([result(transformed_policy_target={"query": "safe"}), result()])
        value = await guard_semantic_kernel_function(
            AgentControl(runtime),
            function,
            tool_call_id="sk-call-2",
        ).invoke("kernel", {"query": "raw"})

        self.assertEqual(value, {"value": "safe"})
        self.assertEqual(function.calls, [{"query": "safe"}])

    async def test_semantic_kernel_function_transform_mutation_failure_raises(self):
        class ImmutableArguments(Mapping):
            def __init__(self):
                self._values = {"query": "raw"}

            def __getitem__(self, key):
                return self._values[key]

            def __iter__(self):
                return iter(self._values)

            def __len__(self):
                return len(self._values)

        class FakeFunction:
            name = "search"
            called = False

            async def invoke(self, kernel, arguments):
                self.called = True
                return {"value": arguments["query"]}

        function = FakeFunction()
        runtime = QueueRuntime([result(transformed_policy_target={"query": "safe"})])
        with self.assertRaises(AdapterUnsupportedError):
            await guard_semantic_kernel_function(
                AgentControl(runtime),
                function,
                tool_call_id="sk-call-3",
            ).invoke("kernel", ImmutableArguments())
        self.assertFalse(function.called)

    async def test_semantic_kernel_filter_omits_call_id_when_absent_and_sets_result(self):
        class FakeFunction:
            name = "lookup"

        class FakeContext:
            def __init__(self):
                self.function = FakeFunction()
                self.arguments = {"query": "raw"}
                self.result = None

        async def next_filter(context):
            context.result = {"value": context.arguments["query"]}

        context = FakeContext()
        runtime = QueueRuntime([result(transformed_policy_target={"query": "safe"}), result(transformed_policy_target={"value": "redacted"})])
        await guard_semantic_kernel_filter(AgentControl(runtime))(context, next_filter)

        self.assertNotIn("id", runtime.requests[0].snapshot["tool_call"])
        self.assertNotIn("id", runtime.requests[1].snapshot["tool_call"])
        self.assertEqual(context.arguments, {"query": "safe"})
        self.assertEqual(context.result, {"value": "redacted"})

    async def test_semantic_kernel_function_exception_propagates(self):
        class FakeFunction:
            name = "explode"

            async def invoke(self, kernel, arguments):
                raise RuntimeError("boom")

        runtime = QueueRuntime([result()])
        with self.assertRaisesRegex(RuntimeError, "boom"):
            await guard_semantic_kernel_function(
                AgentControl(runtime),
                FakeFunction(),
                tool_call_id="sk-call-4",
            ).invoke("kernel", {"query": "raw"})
        self.assertEqual(len(runtime.requests), 1)

    async def test_litellm_proxy_guards_json_model_call(self):
        runtime = QueueRuntime([
            result(transformed_policy_target={"model": "gpt", "messages": [{"content": "safe"}]}),
            result(transformed_policy_target={"choices": [{"message": {"content": "redacted"}}]}),
        ])
        seen_requests = []

        async def app(scope, receive, send):
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            seen_requests.append((scope, body))
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"choices":[{"message":{"content":"raw model response"}}]}'})

        sent = []
        messages = deque([{"type": "http.request", "body": b'{"model":"gpt","messages":[{"content":"raw"}]}', "more_body": False}])
        await guard_litellm_proxy(AgentControl(runtime), app, snapshot={"provider": "litellm"})(
            {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
            messages.popleft,
            sent.append,
        )

        self.assertEqual(seen_requests[0][1], b'{"model":"gpt","messages":[{"content":"safe"}]}')
        self.assertEqual(sent[1]["body"], b'{"choices":[{"message":{"content":"redacted"}}]}')
        self.assertEqual(runtime.requests[1].snapshot["transport"]["path"], "/v1/chat/completions")

    async def test_litellm_proxy_streaming_allow_path_reemits_bytes_verbatim(self):
        runtime = QueueRuntime([result(), result()])
        chunks = _chat_stream_chunks()
        seen_bodies = []
        sent = []
        messages = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        await guard_litellm_proxy(AgentControl(runtime), _streaming_app(_sse(*chunks), seen_bodies))(
            {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
            messages.popleft,
            sent.append,
        )

        body = b"".join(m["body"] for m in sent if m["type"] == "http.response.body")
        self.assertEqual(body, _sse(*chunks))
        post_snapshot = runtime.requests[1].snapshot
        self.assertEqual(
            post_snapshot["model_response"]["choices"][0]["message"]["content"], "Hello world"
        )

    async def test_litellm_proxy_streaming_pre_transform_reaches_upstream(self):
        runtime = QueueRuntime([
            result(transformed_policy_target={"model": "gpt", "messages": [{"content": "safe"}], "stream": True}),
            result(),
        ])
        seen_bodies = []
        sent = []
        messages = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[{"content":"raw"}],"stream":true}', "more_body": False}
        ])
        await guard_litellm_proxy(AgentControl(runtime), _streaming_app(_sse(*_chat_stream_chunks()), seen_bodies))(
            {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
            messages.popleft,
            sent.append,
        )

        self.assertEqual(
            json.loads(seen_bodies[0]),
            {"model": "gpt", "messages": [{"content": "safe"}], "stream": True},
        )

    async def test_litellm_proxy_streaming_transform_synthesizes_chunk(self):
        runtime = QueueRuntime([
            result(),
            result(transformed_policy_target={
                "id": "c1",
                "model": "gpt",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "REDACTED"}, "finish_reason": "stop"}],
            }),
        ])
        sent = []
        messages = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        await guard_litellm_proxy(AgentControl(runtime), _streaming_app(_sse(*_chat_stream_chunks())))(
            {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
            messages.popleft,
            sent.append,
        )

        body = b"".join(m["body"] for m in sent if m["type"] == "http.response.body").decode()
        self.assertIn('"object":"chat.completion.chunk"', body)
        self.assertIn('"content":"REDACTED"', body)
        self.assertNotIn("Hello world", body)
        self.assertTrue(body.rstrip().endswith("data: [DONE]"))
        start = next(m for m in sent if m["type"] == "http.response.start")
        self.assertIn((b"content-type", b"text/event-stream"), start["headers"])
        self.assertTrue(all(name.lower() != b"content-length" for name, _ in start["headers"]))

    async def test_litellm_proxy_streaming_block_fails_closed_without_emitting(self):
        runtime = QueueRuntime([result(), result(Decision.DENY)])
        sent = []
        messages = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        with self.assertRaises(AgentControlBlocked):
            await guard_litellm_proxy(AgentControl(runtime), _streaming_app(_sse(*_chat_stream_chunks())))(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                messages.popleft,
                sent.append,
            )
        self.assertEqual(sent, [])

    async def test_litellm_proxy_streaming_rejects_non_chat_paths(self):
        called = False

        async def app(scope, receive, send):
            nonlocal called
            called = True

        messages = deque([{"type": "http.request", "body": b'{"stream":true}', "more_body": False}])
        with self.assertRaises(AdapterUnsupportedError):
            await guard_litellm_proxy(AgentControl(QueueRuntime([])), app)(
                {"type": "http", "method": "POST", "path": "/v1/embeddings", "headers": []},
                messages.popleft,
                lambda message: None,
            )
        self.assertFalse(called)

    async def test_litellm_proxy_streaming_fails_closed_on_non_event_stream(self):
        runtime = QueueRuntime([result()])
        messages = deque([
            {"type": "http.request", "body": b'{"model":"gpt","messages":[],"stream":true}', "more_body": False}
        ])
        app = _streaming_app(b'{"choices":[]}', content_type=b"application/json")
        with self.assertRaises(AdapterUnsupportedError):
            await guard_litellm_proxy(AgentControl(runtime), app)(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                messages.popleft,
                lambda message: None,
            )

    def test_litellm_proxy_lazy_import_reports_missing_proxy_extra(self):
        with patch(
            "agent_control_specification._adapters.litellm.import_module",
            side_effect=ImportError("missing proxy"),
        ):
            with self.assertRaisesRegex(ImportError, r"pip install 'litellm\[proxy\]'"):
                guard_litellm_proxy(AgentControl(QueueRuntime([])))

    async def test_unsupported_adapter_shapes_fail_loudly(self):
        for call in (
            lambda: guard_mcp_server(object()),
            lambda: guard_mcp_server(AgentControl(QueueRuntime([])), object()),
            lambda: guard_litellm_proxy(object(), object()),
            lambda: guard_openai_client(AgentControl(QueueRuntime([])), object()),
            lambda: guard_anthropic_client(AgentControl(QueueRuntime([])), object()),
        ):
            with self.assertRaises(AdapterUnsupportedError):
                call()


if __name__ == "__main__":
    unittest.main()
