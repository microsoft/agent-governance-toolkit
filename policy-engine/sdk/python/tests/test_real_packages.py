"""Gated integration tests against real framework packages.

These verify the dependency-free duck-typed adapters wrap genuine
third-party objects (not just hand-rolled stubs). They use a fake
runtime (QueueRuntime) so policy verdicts stay deterministic while the
*adapter <-> real package* seam is exercised end to end, with no network
calls. Each test skips when its package is absent, so the default
dependency-free suite is unaffected. Install with the
``realpkg-tests`` extra to run them.
"""

from __future__ import annotations

import importlib.util
import json
import os
import unittest
from collections import deque
from collections.abc import Mapping
from typing import Any

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
    guard_langchain_tool,
    guard_litellm_proxy,
    guard_mcp_server,
    guard_mcp_tool,
    guard_openai_agents_runner,
    guard_openai_client,
    guard_semantic_kernel_function,
)

_HAS_LANGCHAIN = importlib.util.find_spec("langchain_core") is not None
_HAS_LANGGRAPH = _HAS_LANGCHAIN and importlib.util.find_spec("langgraph") is not None
_HAS_OPENAI = (
    importlib.util.find_spec("openai") is not None
    and importlib.util.find_spec("httpx") is not None
)
_HAS_OPENAI_AGENTS = importlib.util.find_spec("agents") is not None
_HAS_ANTHROPIC = (
    importlib.util.find_spec("anthropic") is not None
    and importlib.util.find_spec("httpx") is not None
)
_HAS_SEMANTIC_KERNEL = importlib.util.find_spec("semantic_kernel") is not None
_HAS_AUTOGEN = (
    importlib.util.find_spec("autogen_agentchat") is not None
    and importlib.util.find_spec("autogen_core") is not None
)
_HAS_CREWAI = importlib.util.find_spec("crewai") is not None
_HAS_MCP = importlib.util.find_spec("mcp") is not None
_HAS_LITELLM = (
    importlib.util.find_spec("litellm") is not None
    and importlib.util.find_spec("fastapi") is not None
)


def result(decision=None, transformed_policy_target=None):
    # AGT D1: TRANSFORM is the only mutating decision. Default to it when
    # the caller supplied a transformed_policy_target.
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


class SentinelRuntime:
    """Deterministic smoke-policy stand-in for real-package adapter tests."""

    def __init__(self):
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        if _contains_blockme(request.snapshot):
            return InterventionPointResult(
                Verdict(
                    Decision.DENY,
                    reason=f"{request.intervention_point.value}_sentinel_detected",
                )
            )
        return result()


def _contains_blockme(value: Any, seen: set[int] | None = None) -> bool:
    if seen is None:
        seen = set()
    if isinstance(value, str):
        return "BLOCKME" in value
    if isinstance(value, bytes | bytearray):
        return b"BLOCKME" in bytes(value)
    if isinstance(value, Mapping):
        return any(_contains_blockme(k, seen) or _contains_blockme(v, seen) for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_blockme(item, seen) for item in value)
    obj_id = id(value)
    if obj_id in seen:
        return False
    seen.add(obj_id)
    method = getattr(value, "model_dump", None) or getattr(value, "dict", None)
    if callable(method):
        try:
            if _contains_blockme(method(), seen):
                return True
        except Exception:  # noqa: BLE001
            pass
    return "BLOCKME" in repr(value)


def _control() -> AgentControl:
    return AgentControl(SentinelRuntime())


def _assert_blocked(testcase: unittest.TestCase, exc: Any, point: InterventionPoint) -> None:
    testcase.assertEqual(exc.exception.intervention_point, point)


@unittest.skipUnless(_HAS_LANGCHAIN, "langchain-core not installed")
class LangChainRealPackageTests(unittest.IsolatedAsyncioTestCase):
    async def test_guard_wraps_real_runnable_and_transforms_input(self):
        from langchain_core.runnables import RunnableLambda

        seen = []

        async def echo(value):
            seen.append(value)
            return {"echo": value}

        runnable = RunnableLambda(echo)
        runtime = QueueRuntime([result(transformed_policy_target="safe"), result()])
        guarded = guard_langchain_runnable(AgentControl(runtime), runnable)

        output = await guarded.ainvoke("raw")

        self.assertEqual(seen, ["safe"])
        self.assertEqual(output, {"echo": "safe"})

    async def test_guard_transforms_real_runnable_output(self):
        from langchain_core.runnables import RunnableLambda

        runnable = RunnableLambda(lambda value: {"echo": value})
        runtime = QueueRuntime([result(), result(transformed_policy_target={"echo": "redacted"})])
        guarded = guard_langchain_runnable(AgentControl(runtime), runnable)

        output = await guarded.ainvoke("raw")

        self.assertEqual(output, {"echo": "redacted"})

    async def test_guard_blocks_real_runnable_input(self):
        from langchain_core.runnables import RunnableLambda

        runnable = RunnableLambda(lambda value: value)
        guarded = guard_langchain_runnable(_control(), runnable)

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.ainvoke("BLOCKME")
        _assert_blocked(self, exc, InterventionPoint.INPUT)

    async def test_guard_blocks_real_runnable_output(self):
        from langchain_core.runnables import RunnableLambda

        runnable = RunnableLambda(lambda value: "BLOCKME")
        guarded = guard_langchain_runnable(_control(), runnable)

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.ainvoke("hi")
        _assert_blocked(self, exc, InterventionPoint.OUTPUT)

    async def test_guard_mediates_sync_invoke_and_composed_batch(self):
        from langchain_core.runnables import Runnable, RunnableLambda, RunnableSequence

        runtime = QueueRuntime([result(transformed_policy_target="safe"), result()] * 5)
        guarded = guard_langchain_runnable(AgentControl(runtime), RunnableLambda(lambda value: value))

        self.assertIsInstance(guarded, Runnable)
        self.assertEqual(guarded.invoke("raw"), "safe")
        self.assertEqual(guarded.batch(["raw", "raw"]), ["safe", "safe"])
        composed = RunnableSequence(guarded, RunnableLambda(lambda value: value + "!"))
        self.assertEqual(composed.invoke("raw"), "safe!")
        self.assertEqual(composed.batch(["raw"]), ["safe!"])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.INPUT, InterventionPoint.OUTPUT] * 5)
        with self.assertRaisesRegex(AgentControlBlocked, "adapter unsupported"):
            guarded.with_config({"tags": ["bypass"]})


@unittest.skipUnless(_HAS_LANGGRAPH, "langgraph not installed")
class LangGraphRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _graph(self, node):
        from langgraph.graph import END, START, MessagesState, StateGraph

        graph = StateGraph(MessagesState)
        graph.add_node("tools", node)
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        return graph.compile()

    async def test_tool_node_accepts_guarded_tool_on_sync_and_async_paths(self):
        from langchain_core.messages import AIMessage
        from langchain_core.tools import BaseTool, tool
        from langgraph.prebuilt import ToolNode

        calls = []

        @tool
        def lookup(q: str) -> str:
            """Look up a value."""
            calls.append(q)
            return q

        runtime = QueueRuntime([result(transformed_policy_target={"q": "safe"}), result()] * 2)
        guarded = guard_langchain_tool(AgentControl(runtime), lookup)
        self.assertIsInstance(guarded, BaseTool)
        graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
        message = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-1"}])

        for output in (graph.invoke({"messages": [message]}), await graph.ainvoke({"messages": [message]})):
            self.assertEqual(output["messages"][-1].content, "safe")
            self.assertEqual(output["messages"][-1].tool_call_id, "call-1")
        self.assertEqual(calls, ["safe", "safe"])
        self.assertEqual([r.intervention_point for r in runtime.requests], [InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL] * 2)
        self.assertEqual(runtime.requests[0].snapshot["tool_call"]["args"], {"q": "raw"})
        self.assertEqual(runtime.requests[0].snapshot["tool_call"]["id"], "call-1")
        json.dumps(runtime.requests[1].snapshot["tool_result"])

    async def test_tool_node_terminal_deny_is_structured_and_does_not_call_tool(self):
        from langchain_core.messages import AIMessage, ToolMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import ToolNode

        calls = []

        @tool
        def lookup(q: str) -> str:
            """Look up a value."""
            calls.append(q)
            return q

        denied = InterventionPointResult(
            Verdict(Decision.DENY, reason="tool_not_permitted", message="lookup is not permitted for this agent.")
        )
        runtime = QueueRuntime([denied, denied, denied])
        guarded = guard_langchain_tool(AgentControl(runtime), lookup, on_deny="tool_error")
        graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
        message = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-1"}])

        for output in (graph.invoke({"messages": [message]}), await graph.ainvoke({"messages": [message]})):
            response = output["messages"][-1]
            self.assertIsInstance(response, ToolMessage)
            self.assertEqual(response.status, "error")
            self.assertEqual(response.tool_call_id, "call-1")
            self.assertIn("lookup is not permitted", response.content)
            self.assertNotIn("fix your mistakes", response.content.lower())
            self.assertEqual(response.additional_kwargs["agent_control"]["terminal"], True)
            self.assertEqual(response.additional_kwargs["agent_control"]["reason"], "tool_not_permitted")
        self.assertEqual(calls, [])
        self.assertEqual(len(runtime.requests), 2)

        from langgraph.graph import END, START, MessagesState, StateGraph

        model_calls = []

        def model(state):
            model_calls.append(state)
            return state

        routing = StateGraph(MessagesState)
        routing.add_node("tools", ToolNode([guarded], handle_tool_errors=False))
        routing.add_node("model", model)
        routing.add_edge(START, "tools")
        routing.add_conditional_edges(
            "tools",
            lambda state: END if state["messages"][-1].additional_kwargs["agent_control"]["terminal"] else "model",
        )
        routing.add_edge("model", END)
        routed = routing.compile().invoke({"messages": [message]})
        self.assertEqual(routed["messages"][-1].status, "error")
        self.assertEqual(model_calls, [])
        self.assertEqual(len(runtime.requests), 3)

        with self.assertRaises(ValueError):
            guard_langchain_tool(AgentControl(QueueRuntime([])), lookup, on_deny="skip")

    async def test_tool_node_post_deny_is_terminal_without_leaking_output(self):
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import ToolNode

        calls = []

        @tool
        def lookup(q: str) -> str:
            """Look up a value."""
            calls.append(q)
            return "private result"

        denied = InterventionPointResult(
            Verdict(Decision.DENY, reason="sensitive_result", message="The result is not permitted.")
        )
        guarded = guard_langchain_tool(
            AgentControl(QueueRuntime([result(), denied])), lookup, on_deny="tool_error"
        )
        graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
        message = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-2"}])

        response = graph.invoke({"messages": [message]})["messages"][-1]
        self.assertEqual(response.status, "error")
        self.assertNotIn("private result", response.content)
        self.assertEqual(response.additional_kwargs["agent_control"]["reason"], "sensitive_result")
        self.assertEqual(calls, ["raw"])

        raising = guard_langchain_tool(
            AgentControl(QueueRuntime([denied])), lookup,
        )
        with self.assertRaises(AgentControlBlocked):
            self._graph(ToolNode([raising], handle_tool_errors=False)).invoke({"messages": [message]})
        self.assertEqual(calls, ["raw"])

    async def test_tool_node_post_transform_redacts_message_content(self):
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import ToolNode

        @tool
        def lookup(q: str) -> str:
            """Look up a value."""
            return "private result"

        runtime = QueueRuntime([result(), result(transformed_policy_target="redacted")])
        guarded = guard_langchain_tool(AgentControl(runtime), lookup)
        graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
        message = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-3"}])

        response = graph.invoke({"messages": [message]})["messages"][-1]
        self.assertEqual(response.content, "redacted")
        self.assertEqual(response.tool_call_id, "call-3")
        self.assertEqual(runtime.requests[1].snapshot["tool_result"]["content"], "private result")

    async def test_tool_node_does_not_expose_injected_state_to_tool_args_policy(self):
        from typing import Annotated

        from langchain_core.messages import AIMessage, HumanMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import InjectedState, ToolNode

        seen = []

        def lookup(q: str, state: Annotated[dict, InjectedState]) -> str:
            """Look up a value with graph state."""
            seen.append((q, state))
            return q

        lookup.__annotations__["state"] = Annotated[dict, InjectedState]
        lookup = tool(lookup)

        runtime = QueueRuntime([result(transformed_policy_target={"q": "safe"}), result()] * 2)
        guarded = guard_langchain_tool(AgentControl(runtime), lookup)
        graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
        history = HumanMessage(content="secret in prior conversation")
        call = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-5"}])

        for output in (
            graph.invoke({"messages": [history, call]}),
            await graph.ainvoke({"messages": [history, call]}),
        ):
            self.assertEqual(output["messages"][-1].content, "safe")
        self.assertEqual([request.snapshot["tool_call"]["args"] for request in runtime.requests], [{"q": "raw"}, {"q": "safe"}] * 2)
        self.assertEqual([q for q, _ in seen], ["safe", "safe"])
        self.assertTrue(all(state["messages"][0] == history for _, state in seen))

        unsafe = guard_langchain_tool(
            AgentControl(QueueRuntime([result(transformed_policy_target={"q": "safe", "state": {}})])),
            lookup,
        )
        with self.assertRaisesRegex(AdapterUnsupportedError, "injected.*arguments"):
            self._graph(ToolNode([unsafe], handle_tool_errors=False)).invoke({"messages": [history, call]})
        self.assertEqual(len(seen), 2)

    async def test_tool_node_raises_on_unserializable_artifact(self):
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import ToolNode

        @tool(response_format="content_and_artifact")
        def lookup(q: str) -> tuple[str, object]:
            """Look up a value with an artifact."""
            return "public", object()

        runtime = QueueRuntime([result(), result()])
        guarded = guard_langchain_tool(AgentControl(runtime), lookup)
        graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
        call = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-6"}])

        with self.assertRaisesRegex(AdapterUnsupportedError, "artifact.*JSON"):
            graph.invoke({"messages": [call]})
        self.assertEqual(len(runtime.requests), 1)

    async def test_tool_node_propagates_runtime_failures_even_with_tool_error_mode(self):
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import ToolNode

        called = []

        @tool
        def lookup(q: str) -> str:
            """Look up a value."""
            called.append(q)
            return q

        call = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "raw"}, "id": "call-7"}])
        for reason in ("runtime_error:policy_invocation_failed", "runtime_error:policy_output_invalid", "host_error:approval_unresolved"):
            for post in (False, True):
                with self.subTest(reason=reason, post=post):
                    responses = [result()] if post else []
                    responses.append(InterventionPointResult(Verdict(Decision.DENY, reason=reason)))
                    guarded = guard_langchain_tool(AgentControl(QueueRuntime(responses)), lookup, on_deny="tool_error")
                    graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
                    with self.assertRaises(AgentControlBlocked) as exc:
                        graph.invoke({"messages": [call]})
                    self.assertEqual(exc.exception.result.verdict.reason, reason)
        self.assertEqual(called, ["raw"] * 3)

    async def test_tool_node_uses_native_policy_for_allow_and_terminal_deny(self):
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.prebuilt import ToolNode

        manifest = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: langgraph-native-check
policies:
  lookup:
    type: custom
    adapter: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    policy:
      id: lookup
    policy_target: $snap.tool_call.args
  post_tool_call:
    policy_target_kind: tool_result
    policy:
      id: lookup
    policy_target: $snap.tool_result
"""

        class Policy:
            def __init__(self, decision):
                self.decision = decision

            def evaluate(self, invocation):
                if self.decision == "raises":
                    raise ValueError("policy dispatch failed")
                if self.decision == "none":
                    return None
                if self.decision == "unknown":
                    return {"decision": "unknown"}
                return {
                    "decision": self.decision,
                    "reason": "tool_not_permitted" if self.decision == "deny" else "permitted",
                    "message": "lookup is not permitted for this agent.",
                }

        @tool
        def lookup(q: str) -> str:
            """Look up a value."""
            return "result for " + q

        message = AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "x"}, "id": "call-4"}])
        for decision, status in (("allow", "success"), ("deny", "error")):
            with self.subTest(decision=decision):
                guarded = guard_langchain_tool(
                    AgentControl.from_native(manifest, None, Policy(decision)),
                    lookup,
                    on_deny="tool_error",
                )
                graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
                for response in (
                    graph.invoke({"messages": [message]})["messages"][-1],
                    (await graph.ainvoke({"messages": [message]}))["messages"][-1],
                ):
                    self.assertEqual(response.status, status)
                    self.assertEqual(response.tool_call_id, "call-4")
                    if decision == "deny":
                        self.assertEqual(response.additional_kwargs["agent_control"]["reason"], "tool_not_permitted")
                    else:
                        self.assertEqual(response.content, "result for x")

        for decision in ("raises", "none", "unknown"):
            with self.subTest(decision=decision):
                guarded = guard_langchain_tool(
                    AgentControl.from_native(manifest, None, Policy(decision)),
                    lookup,
                    on_deny="tool_error",
                )
                graph = self._graph(ToolNode([guarded], handle_tool_errors=False))
                with self.assertRaises(AgentControlBlocked) as sync_failure:
                    graph.invoke({"messages": [message]})
                with self.assertRaises(AgentControlBlocked) as async_failure:
                    await graph.ainvoke({"messages": [message]})
                for exc in (sync_failure.exception, async_failure.exception):
                    self.assertTrue(exc.result.verdict.reason.startswith("runtime_error:"))


@unittest.skipUnless(_HAS_OPENAI, "openai/httpx not installed")
class OpenAIRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _client(self, handler):
        import httpx
        from openai import AsyncOpenAI

        return AsyncOpenAI(
            api_key="test-key",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )

    def _completion(self, content):
        return {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-4o",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }

    async def test_guard_allows_and_returns_real_chat_completion(self):
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=self._completion("hello there"))

        runtime = QueueRuntime([result(), result()])
        guarded = guard_openai_client(AgentControl(runtime), self._client(handler))

        response = await guarded.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
        )

        self.assertEqual(type(response).__name__, "ChatCompletion")
        self.assertEqual(response.choices[0].message.content, "hello there")
        self.assertEqual(runtime.requests[0].snapshot["model_request"]["model"], "gpt-4o")

    async def test_guard_pre_transform_reaches_real_client(self):
        import httpx

        sent = {}

        def handler(request: httpx.Request) -> httpx.Response:
            sent["messages"] = json.loads(request.content)["messages"]
            return httpx.Response(200, json=self._completion("ok"))

        runtime = QueueRuntime([
            result(transformed_policy_target={"model": "gpt-4o", "messages": [{"role": "user", "content": "safe"}]}),
            result(),
        ])
        guarded = guard_openai_client(AgentControl(runtime), self._client(handler))

        await guarded.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "raw"}]
        )

        self.assertEqual(sent["messages"], [{"role": "user", "content": "safe"}])

    async def test_guard_blocks_before_calling_real_client(self):
        import httpx

        called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return httpx.Response(200, json=self._completion("nope"))

        runtime = QueueRuntime([result(Decision.DENY)])
        guarded = guard_openai_client(AgentControl(runtime), self._client(handler))

        with self.assertRaises(AgentControlBlocked):
            await guarded.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
            )
        self.assertFalse(called)

    async def test_guard_blocks_real_client_post_model_call(self):
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=self._completion("BLOCKME"))

        guarded = guard_openai_client(_control(), self._client(handler))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
            )
        _assert_blocked(self, exc, InterventionPoint.POST_MODEL_CALL)


@unittest.skipUnless(_HAS_ANTHROPIC, "anthropic/httpx not installed")
class AnthropicRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _client(self, content: str):
        import httpx
        from anthropic import AsyncAnthropic

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": content}],
                    "model": "claude-3-5-sonnet-latest",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )

        return AsyncAnthropic(
            api_key="test-key",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )

    async def test_guard_allows_real_messages_create(self):
        guarded = guard_anthropic_client(_control(), self._client("hello"))

        response = await guarded.messages.create(
            model="claude-3-5-sonnet-latest",
            max_tokens=8,
            messages=[{"role": "user", "content": "hi"}],
        )

        self.assertEqual(type(response).__name__, "Message")
        self.assertEqual(response.content[0].text, "hello")

    async def test_guard_blocks_real_messages_pre_model_call(self):
        guarded = guard_anthropic_client(_control(), self._client("unreached"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.messages.create(
                model="claude-3-5-sonnet-latest",
                max_tokens=8,
                messages=[{"role": "user", "content": "BLOCKME"}],
            )
        _assert_blocked(self, exc, InterventionPoint.PRE_MODEL_CALL)

    async def test_guard_blocks_real_messages_post_model_call(self):
        guarded = guard_anthropic_client(_control(), self._client("BLOCKME"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.messages.create(
                model="claude-3-5-sonnet-latest",
                max_tokens=8,
                messages=[{"role": "user", "content": "hi"}],
            )
        _assert_blocked(self, exc, InterventionPoint.POST_MODEL_CALL)


@unittest.skipUnless(_HAS_OPENAI_AGENTS, "openai-agents not installed")
class OpenAIAgentsRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _agent(self, output: str):
        from agents import Agent
        from agents.items import ModelResponse, ResponseOutputMessage, ResponseOutputText
        from agents.models.interface import Model
        from agents.usage import Usage

        class StaticModel(Model):
            async def get_response(self, *args, **kwargs):
                return ModelResponse(
                    output=[
                        ResponseOutputMessage(
                            id="msg_1",
                            type="message",
                            role="assistant",
                            status="completed",
                            content=[
                                ResponseOutputText(
                                    type="output_text",
                                    text=output,
                                    annotations=[],
                                )
                            ],
                        )
                    ],
                    usage=Usage(),
                    response_id="resp_1",
                )

            async def stream_response(self, *args, **kwargs):
                if False:
                    yield None

        return Agent(name="real-agent", model=StaticModel())

    async def test_guard_allows_real_runner(self):
        from agents import Runner

        guarded = guard_openai_agents_runner(_control(), Runner)
        response = await guarded.run(self._agent("hello"), "hi", max_turns=1)

        self.assertEqual(response.final_output, "hello")

    async def test_guard_blocks_real_runner_input(self):
        from agents import Runner

        guarded = guard_openai_agents_runner(_control(), Runner)
        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.run(self._agent("unreached"), "BLOCKME", max_turns=1)
        _assert_blocked(self, exc, InterventionPoint.INPUT)

    async def test_guard_blocks_real_runner_output(self):
        from agents import Runner

        guarded = guard_openai_agents_runner(_control(), Runner)
        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.run(self._agent("BLOCKME"), "hi", max_turns=1)
        _assert_blocked(self, exc, InterventionPoint.OUTPUT)


@unittest.skipUnless(_HAS_SEMANTIC_KERNEL, "semantic-kernel not installed")
class SemanticKernelRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _function(self, output: str | None = None):
        from semantic_kernel import Kernel
        from semantic_kernel.functions import kernel_function

        class Plugin:
            @kernel_function(name="echo")
            def echo(self, value: str) -> str:
                return output or value

        plugin = Kernel().add_plugin(Plugin(), plugin_name="real_plugin")
        return plugin.functions["echo"]

    async def test_guard_allows_real_kernel_function(self):
        from semantic_kernel import Kernel
        from semantic_kernel.functions import KernelArguments

        guarded = guard_semantic_kernel_function(_control(), self._function())
        response = await guarded.invoke(Kernel(), KernelArguments(value="hello"))

        self.assertEqual(str(response.value), "hello")

    async def test_guard_blocks_real_kernel_function_pre_tool_call(self):
        from semantic_kernel import Kernel
        from semantic_kernel.functions import KernelArguments

        guarded = guard_semantic_kernel_function(_control(), self._function())
        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.invoke(Kernel(), KernelArguments(value="BLOCKME"))
        _assert_blocked(self, exc, InterventionPoint.PRE_TOOL_CALL)

    async def test_guard_blocks_real_kernel_function_post_tool_call(self):
        from semantic_kernel import Kernel
        from semantic_kernel.functions import KernelArguments

        guarded = guard_semantic_kernel_function(_control(), self._function("BLOCKME"))
        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.invoke(Kernel(), KernelArguments(value="hello"))
        _assert_blocked(self, exc, InterventionPoint.POST_TOOL_CALL)


@unittest.skipUnless(_HAS_AUTOGEN, "autogen-agentchat/autogen-core not installed")
class AutoGenRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _agent(self, output: str):
        from autogen_agentchat.agents import AssistantAgent
        from autogen_core.models import ChatCompletionClient, CreateResult, RequestUsage

        class StaticChatCompletionClient(ChatCompletionClient):
            async def create(self, messages, **kwargs):
                return CreateResult(
                    finish_reason="stop",
                    content=output,
                    usage=RequestUsage(prompt_tokens=1, completion_tokens=1),
                    cached=False,
                )

            async def create_stream(self, messages, **kwargs):
                yield await self.create(messages, **kwargs)

            async def close(self):
                return None

            def actual_usage(self):
                return RequestUsage(prompt_tokens=1, completion_tokens=1)

            def total_usage(self):
                return RequestUsage(prompt_tokens=1, completion_tokens=1)

            def count_tokens(self, messages, *, tools=()):
                return 1

            def remaining_tokens(self, messages, *, tools=()):
                return 4096

            @property
            def capabilities(self):
                return self.model_info

            @property
            def model_info(self):
                return {
                    "vision": False,
                    "function_calling": False,
                    "json_output": False,
                    "family": "unknown",
                    "structured_output": False,
                }

        return AssistantAgent("real_autogen_agent", model_client=StaticChatCompletionClient())

    async def test_guard_allows_real_assistant_agent(self):
        guarded = guard_autogen_agent(_control(), self._agent("hello"))
        response = await guarded.run(task="hi")

        self.assertIn("hello", repr(response))

    async def test_guard_blocks_real_assistant_agent_input(self):
        guarded = guard_autogen_agent(_control(), self._agent("unreached"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.run(task="BLOCKME")
        _assert_blocked(self, exc, InterventionPoint.INPUT)

    async def test_guard_blocks_real_assistant_agent_output(self):
        guarded = guard_autogen_agent(_control(), self._agent("BLOCKME"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.run(task="hi")
        _assert_blocked(self, exc, InterventionPoint.OUTPUT)


@unittest.skipUnless(_HAS_CREWAI, "crewai not installed")
class CrewAIRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        os.environ.setdefault("CREWAI_TESTING", "true")
        os.environ.setdefault("OTEL_SDK_DISABLED", "true")
        os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

    def _crew(self, output: str):
        from crewai import Agent, Crew, Task
        from crewai.llms.base_llm import BaseLLM

        class StaticLLM(BaseLLM):
            def __init__(self):
                super().__init__(model="static")

            def call(
                self,
                messages,
                tools=None,
                callbacks=None,
                available_functions=None,
                from_task=None,
                from_agent=None,
                response_model=None,
            ):
                return output

        agent = Agent(role="tester", goal="return a local answer", backstory="local", llm=StaticLLM())
        task = Task(description="Say {topic}", expected_output="local answer", agent=agent)
        return Crew(agents=[agent], tasks=[task], verbose=False, tracing=False)

    async def test_guard_allows_real_crew(self):
        guarded = guard_crewai_crew(_control(), self._crew("hello"))

        response = await guarded.kickoff(inputs={"topic": "hi"})

        self.assertIn("hello", str(response))

    async def test_guard_blocks_real_crew_input(self):
        guarded = guard_crewai_crew(_control(), self._crew("unreached"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.kickoff(inputs={"topic": "BLOCKME"})
        _assert_blocked(self, exc, InterventionPoint.INPUT)

    async def test_guard_blocks_real_crew_output(self):
        guarded = guard_crewai_crew(_control(), self._crew("BLOCKME"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.kickoff(inputs={"topic": "hi"})
        _assert_blocked(self, exc, InterventionPoint.OUTPUT)


@unittest.skipUnless(_HAS_MCP, "mcp not installed")
class MCPRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _server(self, output: str | None = None):
        from mcp.server.fastmcp import FastMCP

        server = FastMCP("real-mcp")

        @server.tool()
        def echo(value: str) -> str:
            return output or value

        return server

    async def test_guard_allows_real_fastmcp_server(self):
        guarded = guard_mcp_server(_control(), self._server())

        response = await guarded.call_tool("echo", {"value": "hello"})

        self.assertIn("hello", repr(response))

    async def test_guard_blocks_real_fastmcp_server_pre_tool_call(self):
        guarded = guard_mcp_server(_control(), self._server("unreached"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.call_tool("echo", {"value": "BLOCKME"})
        _assert_blocked(self, exc, InterventionPoint.PRE_TOOL_CALL)

    async def test_guard_blocks_real_fastmcp_server_post_tool_call(self):
        guarded = guard_mcp_server(_control(), self._server("BLOCKME"))

        with self.assertRaises(AgentControlBlocked) as exc:
            await guarded.call_tool("echo", {"value": "hello"})
        _assert_blocked(self, exc, InterventionPoint.POST_TOOL_CALL)

    async def test_guard_allows_real_fastmcp_tool_handler(self):
        server = self._server()
        guarded = guard_mcp_tool(
            _control(),
            "echo",
            lambda args: server.call_tool("echo", args),
            tool_call_id="call_1",
        )

        response = await guarded({"value": "hello"})

        self.assertIn("hello", repr(response))


@unittest.skipUnless(_HAS_LITELLM, "litellm[proxy]/fastapi not installed")
class LiteLLMRealPackageTests(unittest.IsolatedAsyncioTestCase):
    def _proxy_app(self, content: str):
        import litellm.proxy.proxy_server as proxy_server
        from fastapi.responses import JSONResponse

        app = proxy_server.app
        path = f"/acs-realpkg-{id(self)}-{len(app.router.routes)}"

        @app.post(path)
        async def acs_realpkg_endpoint():
            return JSONResponse(
                {
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": content},
                            "finish_reason": "stop",
                        }
                    ],
                }
            )

        return app, path

    async def _call_asgi(self, app, path: str, body: Mapping[str, Any]):
        messages = []
        raw = json.dumps(body).encode("utf-8")
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send(message):
            messages.append(dict(message))

        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())],
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive,
            send,
        )
        return messages

    def _response_body(self, messages):
        raw = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        return json.loads(raw.decode("utf-8"))

    async def test_guard_allows_real_litellm_proxy_asgi_app(self):
        app, path = self._proxy_app("hello")
        guarded = guard_litellm_proxy(_control(), app, paths=(path,))

        response = await self._call_asgi(
            guarded,
            path,
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
        )

        self.assertEqual(self._response_body(response)["choices"][0]["message"]["content"], "hello")

    async def test_guard_blocks_real_litellm_proxy_pre_model_call(self):
        app, path = self._proxy_app("unreached")
        guarded = guard_litellm_proxy(_control(), app, paths=(path,))

        with self.assertRaises(AgentControlBlocked) as exc:
            await self._call_asgi(
                guarded,
                path,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "BLOCKME"}]},
            )
        _assert_blocked(self, exc, InterventionPoint.PRE_MODEL_CALL)

    async def test_guard_blocks_real_litellm_proxy_post_model_call(self):
        app, path = self._proxy_app("BLOCKME")
        guarded = guard_litellm_proxy(_control(), app, paths=(path,))

        with self.assertRaises(AgentControlBlocked) as exc:
            await self._call_asgi(
                guarded,
                path,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
            )
        _assert_blocked(self, exc, InterventionPoint.POST_MODEL_CALL)


if __name__ == "__main__":
    unittest.main()
