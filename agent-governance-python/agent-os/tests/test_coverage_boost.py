# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Coverage boost tests for agent-os.

Targets: openai_agents_sdk.py, autogen_adapter.py, semantic_kernel_adapter.py, base_agent.py
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

# ---------------------------------------------------------------------------
# 1. OpenAI Agents SDK Integration
# ---------------------------------------------------------------------------
from agent_os.integrations.openai_agents_sdk import (
    GovernancePolicy as OAIGovernancePolicy,
    ExecutionContext as OAIExecutionContext,
    PolicyViolationError as OAIPolicyViolationError,
    OpenAIAgentsKernel,
)


class TestOAIGovernancePolicy:
    def test_defaults(self):
        p = OAIGovernancePolicy()
        assert p.max_tool_calls == 50
        assert p.max_handoffs == 5
        assert p.timeout_seconds == 300
        assert p.allowed_tools == []
        assert p.blocked_tools == []
        assert p.blocked_patterns == []
        assert p.pii_detection is True
        assert p.require_human_approval is False
        assert p.approval_threshold == 0.8
        assert p.log_all_calls is True
        assert p.checkpoint_frequency == 5

    def test_custom(self):
        p = OAIGovernancePolicy(max_tool_calls=10, blocked_tools=["rm"])
        assert p.max_tool_calls == 10
        assert p.blocked_tools == ["rm"]


class TestOAIExecutionContext:
    def test_creation(self):
        p = OAIGovernancePolicy()
        ctx = OAIExecutionContext(session_id="s1", agent_id="a1", policy=p)
        assert ctx.session_id == "s1"
        assert ctx.agent_id == "a1"
        assert ctx.tool_calls == 0
        assert ctx.handoffs == 0
        assert ctx.events == []
        assert isinstance(ctx.started_at, datetime)

    def test_record_event(self):
        p = OAIGovernancePolicy()
        ctx = OAIExecutionContext(session_id="s1", agent_id="a1", policy=p)
        ctx.record_event("test_event", {"key": "val"})
        assert len(ctx.events) == 1
        assert ctx.events[0]["type"] == "test_event"
        assert ctx.events[0]["data"] == {"key": "val"}
        assert "timestamp" in ctx.events[0]


class TestOAIPolicyViolationError:
    def test_basic(self):
        err = OAIPolicyViolationError("tool_filter", "blocked tool")
        assert err.policy_name == "tool_filter"
        assert err.description == "blocked tool"
        assert err.severity == "high"
        assert "tool_filter" in str(err)

    def test_custom_severity(self):
        err = OAIPolicyViolationError("x", "y", severity="low")
        assert err.severity == "low"


class TestOpenAIAgentsKernel:
    def test_init_defaults(self):
        k = OpenAIAgentsKernel()
        assert isinstance(k.policy, OAIGovernancePolicy)
        assert k._contexts == {}
        assert k._wrapped_agents == {}

    def test_init_custom_policy(self):
        p = OAIGovernancePolicy(max_tool_calls=5)
        k = OpenAIAgentsKernel(policy=p)
        assert k.policy.max_tool_calls == 5

    def test_init_custom_violation_handler(self):
        handler = MagicMock()
        k = OpenAIAgentsKernel(on_violation=handler)
        assert k.on_violation is handler

    def test_default_violation_handler_logs(self):
        k = OpenAIAgentsKernel()
        err = OAIPolicyViolationError("p", "d")
        # Should not raise
        k._default_violation_handler(err)

    # _check_tool_allowed
    def test_tool_allowed_no_restrictions(self):
        k = OpenAIAgentsKernel()
        ok, reason = k._check_tool_allowed("any_tool")
        assert ok is True
        assert reason == ""

    def test_tool_blocked(self):
        p = OAIGovernancePolicy(blocked_tools=["dangerous"])
        k = OpenAIAgentsKernel(policy=p)
        ok, reason = k._check_tool_allowed("dangerous")
        assert ok is False
        assert "blocked" in reason

    def test_tool_not_in_allowed_list(self):
        p = OAIGovernancePolicy(allowed_tools=["safe"])
        k = OpenAIAgentsKernel(policy=p)
        ok, reason = k._check_tool_allowed("unsafe")
        assert ok is False
        assert "not in allowed" in reason

    def test_tool_in_allowed_list(self):
        p = OAIGovernancePolicy(allowed_tools=["safe"])
        k = OpenAIAgentsKernel(policy=p)
        ok, reason = k._check_tool_allowed("safe")
        assert ok is True

    # _check_content
    def test_content_ok(self):
        k = OpenAIAgentsKernel()
        ok, reason = k._check_content("hello world")
        assert ok is True

    def test_content_blocked(self):
        p = OAIGovernancePolicy(blocked_patterns=["DROP TABLE"])
        k = OpenAIAgentsKernel(policy=p)
        ok, reason = k._check_content("please DROP TABLE users")
        assert ok is False
        assert "DROP TABLE" in reason

    def test_content_blocked_case_insensitive(self):
        p = OAIGovernancePolicy(blocked_patterns=["secret"])
        k = OpenAIAgentsKernel(policy=p)
        ok, reason = k._check_content("this is SECRET data")
        assert ok is False

    # wrap / unwrap
    def test_wrap_creates_governed_agent(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "test-agent"
        agent.model = "gpt-4o"
        agent.instructions = "do stuff"
        agent.tools = []
        wrapped = k.wrap(agent)
        assert wrapped.name == "test-agent"
        assert wrapped.original is agent
        assert len(k._contexts) == 1
        assert "test-agent" in k._wrapped_agents

    def test_wrap_agent_without_name(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock(spec=[])  # no 'name' attribute
        wrapped = k.wrap(agent)
        assert wrapped._original is agent

    def test_unwrap_returns_original(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "a"
        wrapped = k.wrap(agent)
        assert k.unwrap(wrapped) is agent

    def test_unwrap_non_wrapped(self):
        k = OpenAIAgentsKernel()
        obj = MagicMock(spec=[])
        assert k.unwrap(obj) is obj

    def test_wrapped_getattr_passthrough(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "a"
        agent.custom_field = 42
        wrapped = k.wrap(agent)
        assert wrapped.custom_field == 42

    # create_tool_guard
    @pytest.mark.asyncio
    async def test_tool_guard_allows(self):
        k = OpenAIAgentsKernel()
        guard = k.create_tool_guard()

        @guard
        async def my_tool(x):
            return x * 2

        result = await my_tool(5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_tool_guard_blocks_tool(self):
        p = OAIGovernancePolicy(blocked_tools=["blocked_func"])
        k = OpenAIAgentsKernel(policy=p)
        guard = k.create_tool_guard()

        @guard
        async def blocked_func():
            return "should not get here"

        with pytest.raises(OAIPolicyViolationError):
            await blocked_func()

    @pytest.mark.asyncio
    async def test_tool_guard_blocks_content_in_args(self):
        p = OAIGovernancePolicy(blocked_patterns=["rm -rf"])
        k = OpenAIAgentsKernel(policy=p)
        guard = k.create_tool_guard()

        @guard
        async def run_cmd(cmd):
            return cmd

        with pytest.raises(OAIPolicyViolationError):
            await run_cmd("rm -rf /")

    @pytest.mark.asyncio
    async def test_tool_guard_blocks_content_in_kwargs(self):
        p = OAIGovernancePolicy(blocked_patterns=["DROP TABLE"])
        k = OpenAIAgentsKernel(policy=p)
        guard = k.create_tool_guard()

        @guard
        async def query(sql=""):
            return sql

        with pytest.raises(OAIPolicyViolationError):
            await query(sql="DROP TABLE users")

    @pytest.mark.asyncio
    async def test_tool_guard_sync_function(self):
        k = OpenAIAgentsKernel()
        guard = k.create_tool_guard()

        @guard
        def sync_tool(x):
            return x + 1

        result = await sync_tool(3)
        assert result == 4

    # create_guardrail
    @pytest.mark.asyncio
    async def test_guardrail_allows(self):
        k = OpenAIAgentsKernel()
        guardrail = k.create_guardrail()
        result = await guardrail(MagicMock(), MagicMock(), "hello")
        assert result is None

    @pytest.mark.asyncio
    async def test_guardrail_blocks_content(self):
        p = OAIGovernancePolicy(blocked_patterns=["bad_word"])
        k = OpenAIAgentsKernel(policy=p)
        guardrail = k.create_guardrail()
        result = await guardrail(MagicMock(), MagicMock(), "this has bad_word")
        assert result is not None
        assert "blocked" in result.lower()

    @pytest.mark.asyncio
    async def test_guardrail_blocks_tool_calls(self):
        p = OAIGovernancePolicy(blocked_tools=["evil_tool"])
        k = OpenAIAgentsKernel(policy=p)
        guardrail = k.create_guardrail()
        ctx = MagicMock()
        tc = MagicMock()
        tc.name = "evil_tool"
        ctx.tool_calls = [tc]
        result = await guardrail(ctx, MagicMock(), "ok input")
        assert result is not None
        assert "blocked" in result.lower()

    # get_context / get_audit_log / get_stats
    def test_get_context_found(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "x"
        wrapped = k.wrap(agent)
        session_id = wrapped._context.session_id
        assert k.get_context(session_id) is wrapped._context

    def test_get_context_not_found(self):
        k = OpenAIAgentsKernel()
        assert k.get_context("nonexistent") is None

    def test_get_audit_log_with_events(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "a"
        wrapped = k.wrap(agent)
        session_id = wrapped._context.session_id
        wrapped._context.record_event("test", {"x": 1})
        log = k.get_audit_log(session_id)
        assert len(log) == 1
        assert log[0]["type"] == "test"

    def test_get_audit_log_no_session(self):
        k = OpenAIAgentsKernel()
        assert k.get_audit_log("nope") == []

    def test_get_stats(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "s"
        k.wrap(agent)
        stats = k.get_stats()
        assert stats["total_sessions"] == 1
        assert stats["wrapped_agents"] == 1
        assert stats["total_tool_calls"] == 0
        assert stats["total_handoffs"] == 0
        assert "policy" in stats


# ---------------------------------------------------------------------------
# 2. AutoGen Adapter
# ---------------------------------------------------------------------------
from agent_os.integrations.autogen_adapter import AutoGenKernel
from agent_os.integrations.base import GovernancePolicy, ExecutionContext


class TestAutoGenKernel:
    def test_init_default(self):
        k = AutoGenKernel()
        assert isinstance(k.policy, GovernancePolicy)
        assert k._governed_agents == {}

    def test_init_custom_policy(self):
        p = GovernancePolicy(max_tool_calls=3)
        k = AutoGenKernel(policy=p)
        assert k.policy.max_tool_calls == 3

    def test_wrap_single_agent(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "agent1"
        result = k.wrap(agent)
        assert result is agent
        assert "agent1" in k._governed_agents

    def test_govern_multiple_agents(self):
        k = AutoGenKernel()
        a1 = MagicMock()
        a1.name = "a1"
        a2 = MagicMock()
        a2.name = "a2"
        governed = k.govern(a1, a2)
        assert len(governed) == 2
        assert "a1" in k._governed_agents
        assert "a2" in k._governed_agents

    def test_govern_agent_without_name(self):
        k = AutoGenKernel()
        agent = MagicMock(spec=[])
        # Should use id-based fallback name
        governed = k.govern(agent)
        assert len(governed) == 1

    def test_wrap_initiate_chat(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "sender"
        agent.initiate_chat.return_value = "chat_result"
        recipient = MagicMock()
        recipient.__str__ = lambda self: "recipient"

        k.govern(agent)
        result = agent.initiate_chat(recipient, message="hello")
        assert result == "chat_result"

    def test_wrap_initiate_chat_blocked(self):
        from agent_os.integrations.base import PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["evil"])
        k = AutoGenKernel(policy=p)
        agent = MagicMock()
        agent.name = "sender"
        original_initiate = agent.initiate_chat

        k.govern(agent)
        with pytest.raises(PolicyViolationError):
            agent.initiate_chat(MagicMock(), message="evil plan")

    def test_wrap_generate_reply(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "replier"
        agent.generate_reply.return_value = "reply"

        k.govern(agent)
        result = agent.generate_reply(messages=["hi"], sender=MagicMock())
        assert result == "reply"

    def test_wrap_generate_reply_blocked(self):
        p = GovernancePolicy(blocked_patterns=["forbidden"])
        k = AutoGenKernel(policy=p)
        agent = MagicMock()
        agent.name = "replier"

        k.govern(agent)
        result = agent.generate_reply(messages=["forbidden content"], sender=MagicMock())
        assert "[BLOCKED" in result

    def test_wrap_receive(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "receiver"
        agent.receive.return_value = None

        k.govern(agent)
        result = agent.receive("hello", MagicMock())
        assert result is None

    def test_wrap_receive_blocked(self):
        from agent_os.integrations.base import PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["password"])
        k = AutoGenKernel(policy=p)
        agent = MagicMock()
        agent.name = "receiver"

        k.govern(agent)
        with pytest.raises(PolicyViolationError):
            agent.receive("my password is 123", MagicMock())

    def test_wrap_skips_missing_methods(self):
        k = AutoGenKernel()
        agent = MagicMock(spec=[])  # No initiate_chat, generate_reply, receive
        agent.name = "bare"
        # Should not raise
        k.govern(agent)

    def test_unwrap_restores_original(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "restorable"
        original_initiate = agent.initiate_chat
        original_receive = agent.receive

        k.govern(agent)
        # Methods should be wrapped now
        assert agent.initiate_chat is not original_initiate

        k.unwrap(agent)
        # Methods should be restored
        assert agent.initiate_chat is original_initiate
        assert agent.receive is original_receive
        assert "restorable" not in k._governed_agents

    def test_signal_sigstop_blocks_execution(self):
        from agent_os.integrations.base import PolicyViolationError
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "stoppable"
        agent.initiate_chat.return_value = "result"

        k.govern(agent)
        k.signal("stoppable", "SIGSTOP")

        with pytest.raises(PolicyViolationError, match="stopped"):
            agent.initiate_chat(MagicMock(), message="hello")

    def test_signal_sigcont_resumes(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "resumable"
        agent.initiate_chat.return_value = "result"

        k.govern(agent)
        k.signal("resumable", "SIGSTOP")
        k.signal("resumable", "SIGCONT")

        result = agent.initiate_chat(MagicMock(), message="hello")
        assert result == "result"

    def test_signal_sigkill_unwraps(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "killable"

        k.govern(agent)
        assert "killable" in k._governed_agents

        k.signal("killable", "SIGKILL")
        assert "killable" not in k._governed_agents

    def test_generate_reply_blocked_when_stopped(self):
        k = AutoGenKernel()
        agent = MagicMock()
        agent.name = "stopped-replier"
        agent.generate_reply.return_value = "reply"

        k.govern(agent)
        k.signal("stopped-replier", "SIGSTOP")

        result = agent.generate_reply(messages=["hi"], sender=MagicMock())
        assert "[BLOCKED" in result


# ---------------------------------------------------------------------------
# LlamaIndex Adapter
# ---------------------------------------------------------------------------
from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel


class TestLlamaIndexKernel:
    def test_init_default(self):
        k = LlamaIndexKernel()
        assert isinstance(k.policy, GovernancePolicy)

    def test_wrap_query_engine(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "test-engine"
        engine.query.return_value = "answer"

        governed = k.wrap(engine)
        result = governed.query("What is AI?")
        assert result == "answer"

    def test_query_blocked_pattern(self):
        from agent_os.integrations.langchain_adapter import PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["secret"])
        k = LlamaIndexKernel(policy=p)
        engine = MagicMock()
        engine.name = "blocked-engine"

        governed = k.wrap(engine)
        with pytest.raises(PolicyViolationError):
            governed.query("tell me the secret")

    def test_chat_governed(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "chat-engine"
        engine.chat.return_value = "hello back"

        governed = k.wrap(engine)
        result = governed.chat("hello")
        assert result == "hello back"

    def test_chat_blocked_pattern(self):
        from agent_os.integrations.langchain_adapter import PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["password"])
        k = LlamaIndexKernel(policy=p)
        engine = MagicMock()
        engine.name = "chat-blocked"

        governed = k.wrap(engine)
        with pytest.raises(PolicyViolationError):
            governed.chat("my password is 123")

    def test_retrieve_governed(self):
        k = LlamaIndexKernel()
        retriever = MagicMock()
        retriever.name = "retriever"
        retriever.retrieve.return_value = ["doc1", "doc2"]

        governed = k.wrap(retriever)
        result = governed.retrieve("search query")
        assert result == ["doc1", "doc2"]

    def test_stream_chat_governed(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "stream-engine"
        engine.stream_chat.return_value = "streaming response"

        governed = k.wrap(engine)
        result = governed.stream_chat("hello")
        assert result == "streaming response"

    def test_unwrap_returns_original(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "unwrap-test"

        governed = k.wrap(engine)
        original = k.unwrap(governed)
        assert original is engine

    def test_call_count_increments(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "counter"
        engine.query.return_value = "answer"

        governed = k.wrap(engine)
        governed.query("q1")
        governed.query("q2")
        governed.query("q3")

        ctx = k.contexts["counter"]
        assert ctx.call_count == 3

    def test_max_calls_exceeded(self):
        from agent_os.integrations.langchain_adapter import PolicyViolationError
        p = GovernancePolicy(max_tool_calls=2)
        k = LlamaIndexKernel(policy=p)
        engine = MagicMock()
        engine.name = "limited"
        engine.query.return_value = "answer"

        governed = k.wrap(engine)
        governed.query("q1")
        governed.query("q2")
        with pytest.raises(PolicyViolationError):
            governed.query("q3")

    def test_signal_sigstop(self):
        from agent_os.integrations.langchain_adapter import PolicyViolationError
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "stoppable"

        governed = k.wrap(engine)
        k.signal("stoppable", "SIGSTOP")

        with pytest.raises(PolicyViolationError, match="stopped"):
            governed.query("hello")

    def test_signal_sigcont_resumes(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "resumable"
        engine.query.return_value = "answer"

        governed = k.wrap(engine)
        k.signal("resumable", "SIGSTOP")
        k.signal("resumable", "SIGCONT")

        result = governed.query("hello")
        assert result == "answer"

    def test_getattr_passthrough(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "passthrough"
        engine.custom_attr = "custom_value"

        governed = k.wrap(engine)
        assert governed.custom_attr == "custom_value"


# ---------------------------------------------------------------------------
# Async Integration Tests (LangChain, CrewAI, LlamaIndex)
# ---------------------------------------------------------------------------

class TestLangChainAsync:
    """Async tests for LangChain adapter."""

    @pytest.mark.asyncio
    async def test_ainvoke_governed(self):
        from agent_os.integrations.langchain_adapter import LangChainKernel
        k = LangChainKernel()
        chain = MagicMock()
        chain.name = "async-chain"
        chain.ainvoke = AsyncMock(return_value="async result")

        governed = k.wrap(chain)
        result = await governed.ainvoke({"input": "hello"})
        assert result == "async result"

    @pytest.mark.asyncio
    async def test_ainvoke_blocked(self):
        from agent_os.integrations.langchain_adapter import LangChainKernel, PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["evil"])
        k = LangChainKernel(policy=p)
        chain = MagicMock()
        chain.name = "blocked-async"
        chain.ainvoke = AsyncMock(return_value="result")

        governed = k.wrap(chain)
        with pytest.raises(PolicyViolationError):
            await governed.ainvoke({"input": "evil plan"})

    @pytest.mark.asyncio
    async def test_ainvoke_call_count(self):
        from agent_os.integrations.langchain_adapter import LangChainKernel
        k = LangChainKernel()
        chain = MagicMock()
        chain.name = "counter-async"
        chain.ainvoke = AsyncMock(return_value="result")

        governed = k.wrap(chain)
        await governed.ainvoke({"input": "q1"})
        await governed.ainvoke({"input": "q2"})

        ctx = k.contexts["counter-async"]
        assert ctx.call_count == 2


class TestCrewAIAsync:
    """Async tests for CrewAI adapter."""

    @pytest.mark.asyncio
    async def test_kickoff_async_governed(self):
        from agent_os.integrations.crewai_adapter import CrewAIKernel
        k = CrewAIKernel()
        crew = MagicMock()
        crew.id = "async-crew"
        crew.name = "async-crew"
        crew.agents = []
        crew.kickoff_async = AsyncMock(return_value="crew result")

        governed = k.wrap(crew)
        result = await governed.kickoff_async({"input": "task"})
        assert result == "crew result"

    @pytest.mark.asyncio
    async def test_kickoff_async_blocked(self):
        from agent_os.integrations.crewai_adapter import CrewAIKernel
        from agent_os.integrations.base import PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["forbidden"])
        k = CrewAIKernel(policy=p)
        crew = MagicMock()
        crew.id = "blocked-crew"
        crew.name = "blocked-crew"
        crew.agents = []

        governed = k.wrap(crew)
        with pytest.raises(PolicyViolationError):
            await governed.kickoff_async({"input": "forbidden content"})

    @pytest.mark.asyncio
    async def test_kickoff_async_max_calls(self):
        from agent_os.integrations.crewai_adapter import CrewAIKernel
        from agent_os.integrations.base import PolicyViolationError
        p = GovernancePolicy(max_tool_calls=1)
        k = CrewAIKernel(policy=p)
        crew = MagicMock()
        crew.id = "limited-crew"
        crew.name = "limited-crew"
        crew.agents = []
        crew.kickoff.return_value = "r1"
        crew.kickoff_async = AsyncMock(return_value="r2")

        governed = k.wrap(crew)
        governed.kickoff()  # consumes the 1 allowed call
        with pytest.raises(PolicyViolationError):
            await governed.kickoff_async({"input": "second call"})


class TestLlamaIndexAsync:
    """Async tests for LlamaIndex adapter."""

    @pytest.mark.asyncio
    async def test_aquery_governed(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "async-engine"
        engine.aquery = AsyncMock(return_value="async answer")

        governed = k.wrap(engine)
        result = await governed.aquery("What is AI?")
        assert result == "async answer"

    @pytest.mark.asyncio
    async def test_aquery_blocked(self):
        from agent_os.integrations.langchain_adapter import PolicyViolationError
        p = GovernancePolicy(blocked_patterns=["secret"])
        k = LlamaIndexKernel(policy=p)
        engine = MagicMock()
        engine.name = "blocked-async"

        governed = k.wrap(engine)
        with pytest.raises(PolicyViolationError):
            await governed.aquery("tell me the secret")

    @pytest.mark.asyncio
    async def test_achat_governed(self):
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "async-chat"
        engine.achat = AsyncMock(return_value="async chat reply")

        governed = k.wrap(engine)
        result = await governed.achat("hello")
        assert result == "async chat reply"

    @pytest.mark.asyncio
    async def test_aquery_stopped(self):
        from agent_os.integrations.langchain_adapter import PolicyViolationError
        k = LlamaIndexKernel()
        engine = MagicMock()
        engine.name = "stopped-async"
        engine.aquery = AsyncMock(return_value="answer")

        governed = k.wrap(engine)
        k.signal("stopped-async", "SIGSTOP")

        with pytest.raises(PolicyViolationError, match="stopped"):
            await governed.aquery("hello")


class TestCrossAdapterSignals:
    """Cross-adapter signal tests."""

    def test_langchain_signal_not_shared_with_llamaindex(self):
        """Signals are isolated per adapter instance."""
        from agent_os.integrations.langchain_adapter import LangChainKernel
        lc = LangChainKernel()
        li = LlamaIndexKernel()

        chain = MagicMock()
        chain.name = "lc-agent"
        chain.invoke = MagicMock(return_value="result")

        engine = MagicMock()
        engine.name = "li-agent"
        engine.query = MagicMock(return_value="answer")

        lc_governed = lc.wrap(chain)
        li_governed = li.wrap(engine)

        # Stop LangChain agent - LlamaIndex should still work
        li.signal("li-agent", "SIGSTOP")
        result = lc_governed.invoke({"input": "test"})
        assert result == "result"

    def test_autogen_signal_isolated(self):
        """AutoGen signals don't affect other adapters."""
        from agent_os.integrations.langchain_adapter import LangChainKernel
        lc = LangChainKernel()
        ag = AutoGenKernel()

        chain = MagicMock()
        chain.name = "lc-agent"
        chain.invoke = MagicMock(return_value="result")

        agent = MagicMock()
        agent.name = "ag-agent"

        lc_governed = lc.wrap(chain)
        ag.govern(agent)

        ag.signal("ag-agent", "SIGSTOP")
        # LangChain should still work
        result = lc_governed.invoke({"input": "test"})
        assert result == "result"


# ---------------------------------------------------------------------------
# 3. Semantic Kernel Adapter
# ---------------------------------------------------------------------------
from agent_os.integrations.semantic_kernel_adapter import (
    SKContext,
    SemanticKernelWrapper,
    GovernedSemanticKernel,
    GovernedPlan,
    PolicyViolationError as SKPolicyViolationError,
    ExecutionStoppedError,
    ExecutionKilledError,
)


class TestSKContext:
    def test_creation(self):
        p = GovernancePolicy()
        ctx = SKContext(
            agent_id="a1", session_id="s1", policy=p, kernel_id="sk-1"
        )
        assert ctx.kernel_id == "sk-1"
        assert ctx.plugins_loaded == []
        assert ctx.functions_invoked == []
        assert ctx.memory_operations == []
        assert ctx.prompt_tokens == 0
        assert ctx.completion_tokens == 0


class TestSemanticKernelWrapper:
    def test_init_defaults(self):
        w = SemanticKernelWrapper()
        assert w._kernel is None
        assert w._stopped is False
        assert w._killed is False

    def test_init_with_kernel(self):
        mock_kernel = MagicMock()
        w = SemanticKernelWrapper(kernel=mock_kernel)
        assert w._kernel is mock_kernel

    def test_wrap_returns_governed(self):
        w = SemanticKernelWrapper()
        kernel = MagicMock()
        governed = w.wrap(kernel)
        assert isinstance(governed, GovernedSemanticKernel)

    def test_unwrap_governed(self):
        w = SemanticKernelWrapper()
        kernel = MagicMock()
        governed = w.wrap(kernel)
        assert w.unwrap(governed) is kernel

    def test_unwrap_non_governed(self):
        w = SemanticKernelWrapper()
        obj = "not_governed"
        assert w.unwrap(obj) == "not_governed"

    def test_signal_stop_continue(self):
        w = SemanticKernelWrapper()
        assert w.is_stopped() is False
        w.signal_stop("sk-1")
        assert w.is_stopped() is True
        w.signal_continue("sk-1")
        assert w.is_stopped() is False

    def test_signal_kill(self):
        w = SemanticKernelWrapper()
        assert w.is_killed() is False
        w.signal_kill("sk-1")
        assert w.is_killed() is True


class TestGovernedSemanticKernel:
    def _make_governed(self, policy=None):
        w = SemanticKernelWrapper(policy=policy)
        kernel = MagicMock()
        governed = w.wrap(kernel)
        return governed, w, kernel

    @pytest.mark.asyncio
    async def test_invoke_with_function(self):
        governed, w, kernel = self._make_governed()
        kernel.invoke = AsyncMock(return_value="result")
        func = MagicMock()
        func.name = "my_func"
        result = await governed.invoke(function=func, input="data")
        assert result == "result"

    @pytest.mark.asyncio
    async def test_invoke_with_plugin_and_function_name(self):
        governed, w, kernel = self._make_governed()
        mock_func = MagicMock()
        kernel.plugins = {"plugin": {"func": mock_func}}
        kernel.invoke = AsyncMock(return_value="plugin_result")
        result = await governed.invoke(plugin_name="plugin", function_name="func")
        assert result == "plugin_result"

    @pytest.mark.asyncio
    async def test_invoke_raises_on_kill(self):
        governed, w, kernel = self._make_governed()
        w.signal_kill("any")
        with pytest.raises(ExecutionKilledError):
            await governed.invoke(function=MagicMock())

    @pytest.mark.asyncio
    async def test_invoke_no_function_raises(self):
        governed, w, kernel = self._make_governed()
        with pytest.raises(ValueError, match="Must provide"):
            await governed.invoke()

    @pytest.mark.asyncio
    async def test_invoke_blocked_by_allowed_tools(self):
        p = GovernancePolicy(allowed_tools=["safe.func"])
        governed, w, kernel = self._make_governed(policy=p)
        with pytest.raises(SKPolicyViolationError, match="not allowed"):
            await governed.invoke(plugin_name="other", function_name="func")

    @pytest.mark.asyncio
    async def test_invoke_allowed_by_wildcard(self):
        p = GovernancePolicy(allowed_tools=["myplugin.*"])
        governed, w, kernel = self._make_governed(policy=p)
        mock_func = MagicMock()
        kernel.plugins = {"myplugin": {"func": mock_func}}
        kernel.invoke = AsyncMock(return_value="ok")
        result = await governed.invoke(plugin_name="myplugin", function_name="func")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_invoke_function_not_allowed_no_plugin(self):
        p = GovernancePolicy(allowed_tools=["safe.func"])
        governed, w, kernel = self._make_governed(policy=p)
        func = MagicMock()
        func.name = "other_func"
        with pytest.raises(SKPolicyViolationError, match="not allowed"):
            await governed.invoke(function=func)

    def test_add_plugin(self):
        governed, w, kernel = self._make_governed()
        plugin = MagicMock()
        kernel.add_plugin.return_value = "added"
        result = governed.add_plugin(plugin, "my_plugin")
        assert result == "added"
        assert "my_plugin" in governed._ctx.plugins_loaded

    @pytest.mark.asyncio
    async def test_invoke_prompt(self):
        governed, w, kernel = self._make_governed()
        kernel.invoke_prompt = AsyncMock(return_value="prompt_result")
        result = await governed.invoke_prompt("tell me a joke")
        assert result == "prompt_result"

    @pytest.mark.asyncio
    async def test_invoke_prompt_killed(self):
        governed, w, kernel = self._make_governed()
        w.signal_kill("x")
        with pytest.raises(ExecutionKilledError):
            await governed.invoke_prompt("hello")

    @pytest.mark.asyncio
    async def test_invoke_prompt_blocked(self):
        p = GovernancePolicy(blocked_patterns=["hack"])
        governed, w, kernel = self._make_governed(policy=p)
        with pytest.raises(SKPolicyViolationError, match="Prompt blocked"):
            await governed.invoke_prompt("hack the system")

    def test_sigkill(self):
        governed, w, kernel = self._make_governed()
        governed.sigkill()
        assert w.is_killed() is True

    def test_sigstop(self):
        governed, w, kernel = self._make_governed()
        governed.sigstop()
        assert w.is_stopped() is True

    def test_sigcont(self):
        governed, w, kernel = self._make_governed()
        governed.sigstop()
        governed.sigcont()
        assert w.is_stopped() is False

    def test_get_context(self):
        governed, w, kernel = self._make_governed()
        ctx = governed.get_context()
        assert isinstance(ctx, SKContext)

    def test_get_audit_log(self):
        governed, w, kernel = self._make_governed()
        log = governed.get_audit_log()
        assert "kernel_id" in log
        assert "session_id" in log
        assert "plugins_loaded" in log

    def test_getattr_passthrough(self):
        governed, w, kernel = self._make_governed()
        kernel.some_property = "value"
        assert governed.some_property == "value"

    def test_plugins_property(self):
        governed, w, kernel = self._make_governed()
        kernel.plugins = {"p1": {}}
        assert governed.plugins == {"p1": {}}


class TestGovernedPlan:
    @pytest.mark.asyncio
    async def test_invoke_plan(self):
        w = SemanticKernelWrapper()
        ctx = SKContext(agent_id="a", session_id="s", policy=GovernancePolicy(), kernel_id="k")
        plan = MagicMock()
        plan.invoke = AsyncMock(return_value="plan_result")
        gp = GovernedPlan(plan, w, ctx)
        result = await gp.invoke()
        assert result == "plan_result"

    @pytest.mark.asyncio
    async def test_invoke_plan_killed(self):
        w = SemanticKernelWrapper()
        w.signal_kill("k")
        ctx = SKContext(agent_id="a", session_id="s", policy=GovernancePolicy(), kernel_id="k")
        plan = MagicMock()
        gp = GovernedPlan(plan, w, ctx)
        with pytest.raises(ExecutionKilledError):
            await gp.invoke()

    @pytest.mark.asyncio
    async def test_invoke_plan_step_not_allowed(self):
        p = GovernancePolicy(allowed_tools=["safe_step"])
        w = SemanticKernelWrapper(policy=p)
        ctx = SKContext(agent_id="a", session_id="s", policy=p, kernel_id="k")
        plan = MagicMock()
        step = MagicMock()
        step.name = "bad_step"
        plan._steps = [step]
        gp = GovernedPlan(plan, w, ctx)
        with pytest.raises(SKPolicyViolationError, match="not allowed"):
            await gp.invoke()

    def test_getattr_passthrough(self):
        plan = MagicMock()
        plan.description = "test plan"
        w = SemanticKernelWrapper()
        ctx = SKContext(agent_id="a", session_id="s", policy=GovernancePolicy(), kernel_id="k")
        gp = GovernedPlan(plan, w, ctx)
        assert gp.description == "test plan"


class TestSKExceptions:
    def test_policy_violation_error(self):
        err = SKPolicyViolationError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"

    def test_execution_stopped_error(self):
        err = ExecutionStoppedError("stopped")
        assert isinstance(err, Exception)

    def test_execution_killed_error(self):
        err = ExecutionKilledError("killed")
        assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# 4. Base Agent
# ---------------------------------------------------------------------------
from agent_os.base_agent import (
    AuditEntry,
    BaseAgent,
    AgentConfig,
    PolicyDecision,
    ToolUsingAgent,
    TypedResult,
)
from agent_os.stateless import ExecutionResult, ExecutionContext as StatelessExecutionContext


class TestAuditEntry:
    def test_to_dict(self):
        entry = AuditEntry(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            agent_id="agent-1",
            request_id="req-1",
            action="test",
            params={"key1": "val1", "key2": "val2"},
            decision=PolicyDecision.ALLOW,
            result_success=True,
            error=None,
        )
        d = entry.to_dict()
        assert d["agent_id"] == "agent-1"
        assert d["request_id"] == "req-1"
        assert d["action"] == "test"
        assert d["decision"] == "allow"
        assert d["result_success"] is True
        assert d["error"] is None
        assert set(d["params_keys"]) == {"key1", "key2"}
        assert "2024-01-01" in d["timestamp"]

    def test_to_dict_with_error(self):
        entry = AuditEntry(
            timestamp=datetime(2024, 6, 15, tzinfo=timezone.utc),
            agent_id="a",
            request_id="r",
            action="fail",
            params={},
            decision=PolicyDecision.DENY,
            result_success=False,
            error="something broke",
        )
        d = entry.to_dict()
        assert d["decision"] == "deny"
        assert d["error"] == "something broke"
        assert d["result_success"] is False


class ConcreteAgent(BaseAgent):
    """Concrete implementation for testing."""
    async def run(self, task: str = "") -> ExecutionResult:
        return await self._execute("run_task", {"task": task})


class TestBaseAgent:
    def test_init(self):
        config = AgentConfig(agent_id="test-agent", policies=["read_only"])
        agent = ConcreteAgent(config)
        assert agent.agent_id == "test-agent"
        assert agent.policies == ["read_only"]

    def test_agent_id_property(self):
        config = AgentConfig(agent_id="my-id")
        agent = ConcreteAgent(config)
        assert agent.agent_id == "my-id"

    def test_new_context(self):
        config = AgentConfig(
            agent_id="ctx-agent",
            policies=["p1"],
            metadata={"env": "test"},
        )
        agent = ConcreteAgent(config)
        ctx = agent._new_context(extra="data")
        assert ctx.agent_id == "ctx-agent"
        assert ctx.policies == ["p1"]
        assert ctx.metadata["env"] == "test"
        assert ctx.metadata["extra"] == "data"

    @pytest.mark.asyncio
    async def test_execute(self):
        config = AgentConfig(agent_id="exec-agent")
        agent = ConcreteAgent(config)
        result = await agent.run("hello")
        assert isinstance(result, ExecutionResult)

    @pytest.mark.asyncio
    async def test_get_audit_log(self):
        config = AgentConfig(agent_id="audit-agent")
        agent = ConcreteAgent(config)
        await agent.run("task1")
        log = agent.get_audit_log()
        assert len(log) == 1
        assert log[0]["agent_id"] == "audit-agent"
        assert log[0]["action"] == "run_task"

    @pytest.mark.asyncio
    async def test_clear_audit_log(self):
        config = AgentConfig(agent_id="clear-agent")
        agent = ConcreteAgent(config)
        await agent.run("t")
        assert len(agent.get_audit_log()) == 1
        agent.clear_audit_log()
        assert len(agent.get_audit_log()) == 0

    @pytest.mark.asyncio
    async def test_multiple_executions_audit(self):
        config = AgentConfig(agent_id="multi")
        agent = ConcreteAgent(config)
        await agent.run("a")
        await agent.run("b")
        assert len(agent.get_audit_log()) == 2


class ConcreteToolAgent(ToolUsingAgent):
    """Concrete implementation for testing."""
    async def run(self, task: str = "") -> ExecutionResult:
        return await self._use_tool("default_tool", {"task": task})


class TestToolUsingAgent:
    def test_init_no_tools(self):
        config = AgentConfig(agent_id="tool-agent")
        agent = ConcreteToolAgent(config)
        assert agent._allowed_tools is None

    def test_init_with_tools(self):
        config = AgentConfig(agent_id="tool-agent")
        agent = ConcreteToolAgent(config, tools=["tool_a", "tool_b"])
        assert agent._allowed_tools == {"tool_a", "tool_b"}

    @pytest.mark.asyncio
    async def test_use_tool_allowed(self):
        config = AgentConfig(agent_id="tool-agent")
        agent = ConcreteToolAgent(config, tools=["default_tool"])
        result = await agent.run("test")
        assert isinstance(result, ExecutionResult)

    @pytest.mark.asyncio
    async def test_use_tool_blocked(self):
        config = AgentConfig(agent_id="tool-agent")
        agent = ConcreteToolAgent(config, tools=["other_tool"])
        result = await agent._use_tool("forbidden_tool", {})
        assert result.success is False
        assert "not in allowed" in result.error

    def test_list_allowed_tools(self):
        config = AgentConfig(agent_id="tool-list-agent")
        agent = ConcreteToolAgent(config, tools=["a", "b"])
        tools = agent.list_allowed_tools()
        assert set(tools) == {"a", "b"}

    def test_list_allowed_tools_none(self):
        config = AgentConfig(agent_id="tool-list-agent")
        agent = ConcreteToolAgent(config)
        assert agent.list_allowed_tools() is None


class TestTypedResult:
    def test_from_execution_result_success(self):
        er = ExecutionResult(success=True, data=42)
        tr = TypedResult.from_execution_result(er)
        assert tr.success is True
        assert tr.data == 42
        assert tr.error is None

    def test_from_execution_result_with_transform(self):
        er = ExecutionResult(success=True, data="10")
        tr = TypedResult.from_execution_result(er, transform=int)
        assert tr.data == 10

    def test_from_execution_result_failure(self):
        er = ExecutionResult(success=False, data=None, error="fail")
        tr = TypedResult.from_execution_result(er)
        assert tr.success is False
        assert tr.data is None
        assert tr.error == "fail"

    def test_from_execution_result_failure_no_transform(self):
        er = ExecutionResult(success=False, data="ignored", error="err")
        tr = TypedResult.from_execution_result(er, transform=str.upper)
        assert tr.data is None

    def test_from_execution_result_success_none_data(self):
        er = ExecutionResult(success=True, data=None)
        tr = TypedResult.from_execution_result(er, transform=str.upper)
        assert tr.data is None


# ---------------------------------------------------------------------------
# 5. Additional coverage: OpenAI Agents SDK wrap_runner
# ---------------------------------------------------------------------------


class TestOpenAIAgentsKernelWrapRunner:
    @pytest.mark.asyncio
    async def test_wrap_runner_success(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "a"
        wrapped_agent = k.wrap(agent)

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value="runner_result")
        GovernedRunner = k.wrap_runner(mock_runner)

        result = await GovernedRunner.run(wrapped_agent, "hello")
        assert result == "runner_result"

    @pytest.mark.asyncio
    async def test_wrap_runner_content_blocked_with_approval(self):
        p = OAIGovernancePolicy(
            blocked_patterns=["bad"], require_human_approval=True
        )
        k = OpenAIAgentsKernel(policy=p)
        agent = MagicMock()
        agent.name = "a"
        wrapped_agent = k.wrap(agent)

        mock_runner = MagicMock()
        GovernedRunner = k.wrap_runner(mock_runner)

        with pytest.raises(OAIPolicyViolationError):
            await GovernedRunner.run(wrapped_agent, "bad input")

    @pytest.mark.asyncio
    async def test_wrap_runner_content_blocked_no_approval(self):
        p = OAIGovernancePolicy(
            blocked_patterns=["bad"], require_human_approval=False
        )
        handler = MagicMock()
        k = OpenAIAgentsKernel(policy=p, on_violation=handler)
        agent = MagicMock()
        agent.name = "a"
        wrapped_agent = k.wrap(agent)

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value="ok")
        GovernedRunner = k.wrap_runner(mock_runner)

        result = await GovernedRunner.run(wrapped_agent, "bad input")
        assert result == "ok"
        handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_wrap_runner_error_propagates(self):
        k = OpenAIAgentsKernel()
        agent = MagicMock()
        agent.name = "a"
        wrapped_agent = k.wrap(agent)

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(side_effect=RuntimeError("boom"))
        GovernedRunner = k.wrap_runner(mock_runner)

        with pytest.raises(RuntimeError, match="boom"):
            await GovernedRunner.run(wrapped_agent, "input")

    @pytest.mark.asyncio
    async def test_wrap_runner_no_context(self):
        k = OpenAIAgentsKernel()
        # Agent without _context attribute
        agent = MagicMock(spec=[])

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value="result")
        GovernedRunner = k.wrap_runner(mock_runner)

        result = await GovernedRunner.run(agent, "hello")
        assert result == "result"


# ---------------------------------------------------------------------------
# 6. Additional coverage: SK memory_save, memory_search, invoke_sync
# ---------------------------------------------------------------------------


class TestGovernedSKMemory:
    def _make_governed(self, policy=None):
        w = SemanticKernelWrapper(policy=policy)
        kernel = MagicMock()
        governed = w.wrap(kernel)
        return governed, w, kernel

    @pytest.mark.asyncio
    async def test_memory_save_no_memory(self):
        governed, w, kernel = self._make_governed()
        kernel.memory = None
        result = await governed.memory_save("coll", "text", id="1")
        assert result is None
        assert len(governed._ctx.memory_operations) == 1

    @pytest.mark.asyncio
    async def test_memory_save_with_memory(self):
        governed, w, kernel = self._make_governed()
        kernel.memory = MagicMock()
        kernel.memory.save_information = AsyncMock(return_value="saved")
        result = await governed.memory_save("coll", "text", id="1")
        assert result == "saved"

    @pytest.mark.asyncio
    async def test_memory_save_killed(self):
        governed, w, kernel = self._make_governed()
        w.signal_kill("x")
        with pytest.raises(ExecutionKilledError):
            await governed.memory_save("coll", "text")

    @pytest.mark.asyncio
    async def test_memory_save_blocked(self):
        p = GovernancePolicy(blocked_patterns=["secret"])
        governed, w, kernel = self._make_governed(policy=p)
        with pytest.raises(SKPolicyViolationError, match="Memory save blocked"):
            await governed.memory_save("coll", "secret data")

    @pytest.mark.asyncio
    async def test_memory_search_no_memory(self):
        governed, w, kernel = self._make_governed()
        kernel.memory = None
        result = await governed.memory_search("coll", "query")
        assert result == []
        assert len(governed._ctx.memory_operations) == 1

    @pytest.mark.asyncio
    async def test_memory_search_with_memory(self):
        governed, w, kernel = self._make_governed()
        kernel.memory = MagicMock()
        kernel.memory.search = AsyncMock(return_value=["r1", "r2"])
        result = await governed.memory_search("coll", "query", limit=2)
        assert result == ["r1", "r2"]

    @pytest.mark.asyncio
    async def test_memory_search_killed(self):
        governed, w, kernel = self._make_governed()
        w.signal_kill("x")
        with pytest.raises(ExecutionKilledError):
            await governed.memory_search("coll", "query")

    @pytest.mark.asyncio
    async def test_invoke_prompt_post_check_blocks(self):
        governed, w, kernel = self._make_governed()
        kernel.invoke_prompt = AsyncMock(return_value="bad_result")
        # Override post_execute to block
        original_post = w.post_execute
        def blocking_post(ctx, output):
            return False, "Output blocked"
        w.post_execute = blocking_post
        with pytest.raises(SKPolicyViolationError, match="Result blocked"):
            await governed.invoke_prompt("prompt")


# ---------------------------------------------------------------------------
# 7. Additional: base integration interceptors coverage
# ---------------------------------------------------------------------------
from agent_os.integrations.base import (
    ToolCallRequest,
    ToolCallResult,
    PolicyInterceptor,
    CompositeInterceptor,
    BoundedSemaphore,
)


class TestPolicyInterceptor:
    def test_allows_when_no_restrictions(self):
        pi = PolicyInterceptor(GovernancePolicy())
        req = ToolCallRequest(tool_name="any", arguments={})
        result = pi.intercept(req)
        assert result.allowed is True

    def test_blocks_tool_not_in_allowed(self):
        pi = PolicyInterceptor(GovernancePolicy(allowed_tools=["safe"]))
        req = ToolCallRequest(tool_name="unsafe", arguments={})
        result = pi.intercept(req)
        assert result.allowed is False

    def test_blocks_pattern(self):
        pi = PolicyInterceptor(GovernancePolicy(blocked_patterns=["password"]))
        req = ToolCallRequest(tool_name="t", arguments={"data": "my password"})
        result = pi.intercept(req)
        assert result.allowed is False

    def test_blocks_max_calls(self):
        ctx = ExecutionContext(
            agent_id="a", session_id="s", policy=GovernancePolicy(max_tool_calls=2)
        )
        ctx.call_count = 2
        pi = PolicyInterceptor(GovernancePolicy(max_tool_calls=2), context=ctx)
        req = ToolCallRequest(tool_name="t", arguments={})
        result = pi.intercept(req)
        assert result.allowed is False


class TestCompositeInterceptor:
    def test_all_allow(self):
        ci = CompositeInterceptor()
        i1 = MagicMock()
        i1.intercept.return_value = ToolCallResult(allowed=True)
        ci.add(i1)
        result = ci.intercept(ToolCallRequest(tool_name="t", arguments={}))
        assert result.allowed is True

    def test_first_blocks(self):
        ci = CompositeInterceptor()
        i1 = MagicMock()
        i1.intercept.return_value = ToolCallResult(allowed=False, reason="no")
        ci.add(i1)
        result = ci.intercept(ToolCallRequest(tool_name="t", arguments={}))
        assert result.allowed is False


class TestBoundedSemaphore:
    def test_acquire_release(self):
        sem = BoundedSemaphore(max_concurrent=2)
        ok, _ = sem.try_acquire()
        assert ok is True
        assert sem.active == 1
        sem.release()
        assert sem.active == 0

    def test_max_reached(self):
        sem = BoundedSemaphore(max_concurrent=1)
        sem.try_acquire()
        ok, reason = sem.try_acquire()
        assert ok is False
        assert "Max" in reason

    def test_backpressure(self):
        sem = BoundedSemaphore(max_concurrent=5, backpressure_threshold=2)
        sem.try_acquire()
        sem.try_acquire()
        assert sem.is_under_pressure is True

    def test_stats(self):
        sem = BoundedSemaphore(max_concurrent=10, backpressure_threshold=8)
        sem.try_acquire()
        s = sem.stats()
        assert s["active"] == 1
        assert s["available"] == 9
        assert s["total_acquired"] == 1
        assert s["total_rejected"] == 0

    def test_release_at_zero(self):
        sem = BoundedSemaphore()
        sem.release()  # should not go negative
        assert sem.active == 0
