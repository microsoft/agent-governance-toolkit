from __future__ import annotations

import json
import unittest
from collections import deque

from agent_control_specification import (
    AdapterUnsupportedError,
    AgentControl,
    AgentControlBlocked,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
    guard_anthropic_client,
    guard_autogen_agent,
    guard_crewai_crew,
    guard_langchain_runnable,
    guard_litellm_proxy,
    guard_mcp_server,
    guard_openai_agents_runner,
    guard_openai_client,
    guard_semantic_kernel_filter,
    guard_semantic_kernel_function,
)


def verdict(decision=None, transformed_policy_target=None):
    # AGT D1: TRANSFORM is the only mutating decision; auto-pick it when
    # the caller provided a transformed_policy_target.
    if decision is None:
        decision = Decision.TRANSFORM if transformed_policy_target is not None else Decision.ALLOW
    return InterventionPointResult(Verdict(decision), transformed_policy_target=transformed_policy_target)


class QueueRuntime:
    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()


class AdapterMediationTests(unittest.IsolatedAsyncioTestCase):
    async def test_langchain_mediation_and_sync_bypass_block(self):
        class Runnable:
            def __init__(self):
                self.calls = []

            async def ainvoke(self, value, config=None):
                self.calls.append((value, config))
                return {"answer": value["q"]}

            def invoke(self, value):
                self.calls.append((value, "sync"))
                return value

        denied = Runnable()
        with self.assertRaises(AgentControlBlocked):
            await guard_langchain_runnable(AgentControl(QueueRuntime([verdict(Decision.DENY)])), denied).ainvoke({"q": "raw"})
        self.assertEqual(denied.calls, [])

        runtime = QueueRuntime([verdict(transformed_policy_target={"q": "safe"}), verdict(transformed_policy_target={"answer": "checked"})])
        runnable = Runnable()
        guarded = guard_langchain_runnable(AgentControl(runtime), runnable)
        self.assertEqual(await guarded.ainvoke({"q": "raw"}), {"answer": "checked"})
        self.assertEqual(runnable.calls, [({"q": "safe"}, None)])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.INPUT, InterventionPoint.OUTPUT])
        with self.assertRaises(AdapterUnsupportedError):
            guarded.invoke({"q": "raw"})

    async def test_openai_and_anthropic_clients_mediate_model_calls(self):
        class Endpoint:
            def __init__(self):
                self.calls = []

            async def create(self, **kwargs):
                self.calls.append(kwargs)
                return {"text": kwargs["prompt"]}

        class OpenAiClient:
            def __init__(self):
                self.responses = Endpoint()

        denied_client = OpenAiClient()
        with self.assertRaises(AgentControlBlocked):
            await guard_openai_client(AgentControl(QueueRuntime([verdict(Decision.DENY)])), denied_client).responses.create(prompt="raw")
        self.assertEqual(denied_client.responses.calls, [])

        runtime = QueueRuntime([verdict(transformed_policy_target={"prompt": "safe"}), verdict(transformed_policy_target={"text": "checked"})])
        client = OpenAiClient()
        self.assertEqual(await guard_openai_client(AgentControl(runtime), client).responses.create(prompt="raw"), {"text": "checked"})
        self.assertEqual(client.responses.calls, [{"prompt": "safe"}])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_MODEL_CALL, InterventionPoint.POST_MODEL_CALL])

        class AnthropicMessages:
            def __init__(self):
                self.calls = []

            async def create(self, request):
                self.calls.append(request)
                return {"content": request["messages"]}

        anthropic = type("Client", (), {"messages": AnthropicMessages()})()
        with self.assertRaises(AgentControlBlocked):
            await guard_anthropic_client(AgentControl(QueueRuntime([verdict(Decision.DENY)])), anthropic).messages.create({"messages": []})
        self.assertEqual(anthropic.messages.calls, [])

    async def test_openai_agents_autogen_and_crewai_mediate_agent_runs(self):
        class Runner:
            def __init__(self):
                self.calls = []

            async def run(self, agent, input):
                self.calls.append((agent, input))
                return {"answer": input["task"]}

            def run_sync(self, agent, input):
                return {"sync": input}

        runner = Runner()
        with self.assertRaises(AgentControlBlocked):
            await guard_openai_agents_runner(AgentControl(QueueRuntime([verdict(Decision.DENY)])), runner).run(object(), {"task": "raw"})
        self.assertEqual(runner.calls, [])

        runtime = QueueRuntime([verdict(transformed_policy_target={"task": "safe"}), verdict(transformed_policy_target={"answer": "checked"})])
        self.assertEqual(await guard_openai_agents_runner(AgentControl(runtime), runner).run("agent", {"task": "raw"}), {"answer": "checked"})
        self.assertEqual(runner.calls, [("agent", {"task": "safe"})])
        with self.assertRaises(AdapterUnsupportedError):
            guard_openai_agents_runner(AgentControl(QueueRuntime([])), runner).run_sync("agent", {"task": "raw"})

        class AutoGen:
            def __init__(self):
                self.calls = []

            async def run(self, input):
                self.calls.append(input)
                return {"done": input["task"]}

        class Crew:
            def __init__(self):
                self.calls = []

            async def kickoff(self, inputs):
                self.calls.append(inputs)
                return {"done": inputs["task"]}

        for factory, target in ((guard_autogen_agent, AutoGen()), (guard_crewai_crew, Crew())):
            with self.subTest(factory=factory.__name__):
                with self.assertRaises(AgentControlBlocked):
                    await factory(AgentControl(QueueRuntime([verdict(Decision.DENY)])), target).run({"task": "raw"}) if factory is guard_autogen_agent else await factory(AgentControl(QueueRuntime([verdict(Decision.DENY)])), target).kickoff({"task": "raw"})
                self.assertEqual(target.calls, [])

    async def test_mcp_and_semantic_kernel_mediate_tool_calls(self):
        class McpServer:
            def __init__(self):
                self.calls = []

            async def call_tool(self, request):
                self.calls.append(request)
                return {"value": request["arguments"]["q"]}

        server = McpServer()
        with self.assertRaises(AgentControlBlocked):
            await guard_mcp_server(AgentControl(QueueRuntime([verdict(Decision.DENY)])), server).call_tool({"id": "m1", "name": "lookup", "arguments": {"q": "raw"}})
        self.assertEqual(server.calls, [])

        runtime = QueueRuntime([verdict(transformed_policy_target={"q": "safe"}), verdict(transformed_policy_target={"value": "checked"})])
        self.assertEqual(await guard_mcp_server(AgentControl(runtime), server).call_tool({"id": "m2", "name": "lookup", "arguments": {"q": "raw"}}), {"value": "checked"})
        self.assertEqual(server.calls, [{"id": "m2", "name": "lookup", "arguments": {"q": "safe"}}])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL])

        class Function:
            name = "lookup"

            def __init__(self):
                self.calls = []

            async def invoke(self, kernel, arguments):
                self.calls.append((kernel, dict(arguments)))
                return {"value": arguments["q"]}

        function = Function()
        with self.assertRaises(AgentControlBlocked):
            await guard_semantic_kernel_function(AgentControl(QueueRuntime([verdict(Decision.DENY)])), function).invoke("kernel", {"q": "raw"})
        self.assertEqual(function.calls, [])

        class Context:
            def __init__(self):
                self.function = type("Fn", (), {"name": "lookup"})()
                self.arguments = {"q": "raw"}
                self.result = None
                self.next_called = False

        context = Context()

        async def next_filter(ctx):
            ctx.next_called = True
            ctx.result = {"value": ctx.arguments["q"]}

        with self.assertRaises(AgentControlBlocked):
            await guard_semantic_kernel_filter(AgentControl(QueueRuntime([verdict(Decision.DENY)])))(context, next_filter)
        self.assertFalse(context.next_called)

    async def test_litellm_proxy_pre_model_deny_does_not_call_upstream(self):
        called = False

        async def app(scope, receive, send):
            nonlocal called
            called = True

        messages = deque([{"type": "http.request", "body": b'{"model":"gpt","messages":[]}', "more_body": False}])
        with self.assertRaises(AgentControlBlocked):
            await guard_litellm_proxy(AgentControl(QueueRuntime([verdict(Decision.DENY)])), app)(
                {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []},
                messages.popleft,
                lambda message: None,
            )
        self.assertFalse(called)

    async def test_proxy_adapters_require_hosts_to_discard_original_references(self):
        class Runnable:
            async def ainvoke(self, value):
                return value

        original = Runnable()
        guarded = guard_langchain_runnable(AgentControl(QueueRuntime([verdict(), verdict()])), original)
        self.assertIsNot(guarded, original)
        self.assertIs(guarded._agent_control_target, original)


if __name__ == "__main__":
    unittest.main()
