# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for deep framework integration hooks (issue #73).

Covers tool registry interception, memory write validation, sub-agent
spawn detection, function call pipeline hooks, GroupChat interception,
and state change tracking across all three adapters:
  - LangChainKernel
  - CrewAIKernel
  - AutoGenKernel

All tests use mock objects — no real framework imports are required.

Run with: python -m pytest tests/test_deep_integrations.py -v --tb=short
"""

from unittest.mock import MagicMock, patch
import pytest

from agent_os.integrations.base import GovernancePolicy, PolicyViolationError
from agent_os.integrations.langchain_adapter import (
    LangChainKernel,
    PolicyViolationError as LangChainPolicyViolationError,
)
from agent_os.integrations.crewai_adapter import CrewAIKernel
from agent_os.integrations.autogen_adapter import AutoGenKernel


# =============================================================================
# Helpers
# =============================================================================


def _make_mock_tool(name="web_search", result="tool-result"):
    """Create a mock LangChain-style tool with _run and _arun."""
    tool = MagicMock()
    tool.name = name
    tool._run = MagicMock(return_value=result)
    tool._arun = MagicMock(return_value=result)
    tool._deep_governed = False
    return tool


def _make_mock_memory():
    """Create a mock LangChain memory with save_context."""
    memory = MagicMock()
    memory.save_context = MagicMock(return_value=None)
    memory._deep_governed = False
    return memory


def _make_mock_chain(name="test-chain", tools=None, memory=None):
    """Create a mock LangChain chain/agent."""
    chain = MagicMock()
    chain.name = name
    chain.invoke = MagicMock(return_value="invoke-result")
    chain.run = MagicMock(return_value="run-result")
    chain.batch = MagicMock(return_value=["batch-1"])
    chain.stream = MagicMock(return_value=iter(["chunk-1"]))
    chain._spawn_governed = False
    if tools is not None:
        chain.tools = tools
    if memory is not None:
        chain.memory = memory
    return chain


def _make_crewai_tool(name="web_search"):
    """Create a mock CrewAI tool."""
    tool = MagicMock()
    tool.name = name
    tool._run = MagicMock(return_value="tool result")
    tool._governed = False
    return tool


def _make_crewai_agent(name="researcher", tools=None, memory=None):
    """Create a mock CrewAI agent with optional tools and memory."""
    agent = MagicMock()
    agent.name = name
    agent.tools = tools or []
    agent.execute_task = MagicMock(return_value="task done")
    agent.delegate_work = MagicMock(return_value="delegated")
    agent.step = MagicMock(return_value="step done")
    if memory is not None:
        agent.memory = memory
    return agent


def _make_crewai_crew(agents=None):
    """Create a mock CrewAI crew."""
    crew = MagicMock()
    crew.name = "test-crew"
    crew.id = None
    crew.agents = agents or []
    crew.kickoff = MagicMock(return_value="crew result")
    return crew


def _make_autogen_agent(name="assistant", function_map=None, groupchat=None):
    """Create a mock AutoGen agent."""
    agent = MagicMock()
    agent.name = name
    agent.initiate_chat = MagicMock(return_value="chat-result")
    agent.generate_reply = MagicMock(return_value="reply")
    agent.receive = MagicMock(return_value=None)
    agent.update_system_message = MagicMock(return_value=None)
    agent.reset = MagicMock(return_value=None)
    if function_map is not None:
        agent.function_map = function_map
    if groupchat is not None:
        agent.groupchat = groupchat
    return agent


# =============================================================================
# LangChain Deep Integration Tests
# =============================================================================


class TestLangChainToolRegistryInterception:
    """Test tool registry interception in the LangChain adapter."""

    def test_tool_run_governed_with_allowed_tools(self):
        """Tool calls should pass when the tool is in the allowlist."""
        tool = _make_mock_tool("web_search")
        chain = _make_mock_chain(tools=[tool])

        policy = GovernancePolicy(allowed_tools=["web_search", "read_file"])
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        kernel.wrap(chain)

        # The tool's _run should now be governed; call it
        tool._run(query="hello")
        assert len(kernel._tool_invocations) == 1
        assert kernel._tool_invocations[0]["tool_name"] == "web_search"

    def test_tool_blocked_by_allowlist(self):
        """Tool not in the allowlist should be blocked."""
        tool = _make_mock_tool("dangerous_tool")
        chain = _make_mock_chain(tools=[tool])

        policy = GovernancePolicy(allowed_tools=["web_search"])
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        kernel.wrap(chain)

        with pytest.raises((PolicyViolationError, LangChainPolicyViolationError)):
            tool._run(query="test")

    def test_tool_blocked_by_pattern_in_args(self):
        """Tool args matching a blocked pattern should be rejected."""
        tool = _make_mock_tool("web_search")
        chain = _make_mock_chain(tools=[tool])

        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        kernel.wrap(chain)

        with pytest.raises((PolicyViolationError, LangChainPolicyViolationError)):
            tool._run(query="DROP TABLE users")

    def test_tool_invocations_tracked(self):
        """Each tool invocation should be recorded in the audit log."""
        tool1 = _make_mock_tool("search")
        tool2 = _make_mock_tool("calculator")
        chain = _make_mock_chain(tools=[tool1, tool2])

        kernel = LangChainKernel(deep_hooks_enabled=True)
        kernel.wrap(chain)

        tool1._run(query="hello")
        tool2._run(expression="1+1")

        assert len(kernel._tool_invocations) == 2
        names = [r["tool_name"] for r in kernel._tool_invocations]
        assert "search" in names
        assert "calculator" in names

    def test_deep_hooks_disabled_skips_tool_interception(self):
        """When deep_hooks_enabled=False, tools should NOT be intercepted."""
        tool = _make_mock_tool("web_search")
        original_run = tool._run
        chain = _make_mock_chain(tools=[tool])

        policy = GovernancePolicy(allowed_tools=["other_tool"])
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=False)
        kernel.wrap(chain)

        # _run should still be the original (not governed)
        assert tool._deep_governed is False
        assert len(kernel._tool_invocations) == 0


class TestLangChainMemoryInterception:
    """Test memory write interception in the LangChain adapter."""

    def test_clean_memory_write_passes(self):
        """Memory writes without sensitive data should succeed."""
        memory = _make_mock_memory()
        chain = _make_mock_chain(memory=memory)

        kernel = LangChainKernel(deep_hooks_enabled=True)
        kernel.wrap(chain)

        memory.save_context({"input": "hello"}, {"output": "world"})
        assert len(kernel._memory_audit_log) == 1

    def test_memory_write_blocked_on_pii(self):
        """Memory writes containing PII patterns should be blocked."""
        memory = _make_mock_memory()
        chain = _make_mock_chain(memory=memory)

        kernel = LangChainKernel(deep_hooks_enabled=True)
        kernel.wrap(chain)

        with pytest.raises((PolicyViolationError, LangChainPolicyViolationError)):
            memory.save_context(
                {"input": "ssn is 123-45-6789"},
                {"output": "stored"},
            )

    def test_memory_write_blocked_on_policy_pattern(self):
        """Memory writes matching blocked patterns should be blocked."""
        memory = _make_mock_memory()
        chain = _make_mock_chain(memory=memory)

        policy = GovernancePolicy(blocked_patterns=["confidential"])
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        kernel.wrap(chain)

        with pytest.raises((PolicyViolationError, LangChainPolicyViolationError)):
            memory.save_context(
                {"input": "this is confidential data"},
                {"output": "stored"},
            )


class TestLangChainSubAgentSpawnDetection:
    """Test sub-agent spawn detection in the LangChain adapter."""

    def test_delegation_tracked(self):
        """Sub-agent invocations should be recorded in delegation chains."""
        chain = _make_mock_chain()

        kernel = LangChainKernel(deep_hooks_enabled=True)
        governed = kernel.wrap(chain)

        # The original's invoke was wrapped by _detect_agent_spawning
        chain.invoke({"input": "delegate this"})
        assert len(kernel._delegation_chains) == 1
        assert kernel._delegation_chains[0]["parent_agent"] == "test-chain"

    def test_delegation_depth_exceeded(self):
        """Exceeding max delegation depth should raise PolicyViolationError."""
        chain = _make_mock_chain()

        policy = GovernancePolicy(max_tool_calls=2)
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        kernel.wrap(chain)

        # First two calls should succeed
        chain.invoke({"input": "call 1"})
        chain.invoke({"input": "call 2"})

        # Third call exceeds max_tool_calls used as delegation depth
        with pytest.raises((PolicyViolationError, LangChainPolicyViolationError)):
            chain.invoke({"input": "call 3"})


# =============================================================================
# CrewAI Deep Integration Tests
# =============================================================================


class TestCrewAIStepInterception:
    """Test step-level task execution in the CrewAI adapter."""

    def test_step_interception_logs_steps(self):
        """Individual steps within a task should be logged."""
        agent = _make_crewai_agent("researcher")
        crew = _make_crewai_crew(agents=[agent])

        kernel = CrewAIKernel(deep_hooks_enabled=True)
        governed = kernel.wrap(crew)
        governed.kickoff()

        # The step method on the agent should now be governed
        # Call it to verify interception
        agent.step("step input")
        assert len(kernel._step_log) == 1
        assert kernel._step_log[0]["agent"] == "researcher"

    def test_step_blocked_by_pattern(self):
        """Steps with blocked pattern content should be rejected."""
        agent = _make_crewai_agent("researcher")
        crew = _make_crewai_crew(agents=[agent])

        policy = GovernancePolicy(blocked_patterns=["malicious"])
        kernel = CrewAIKernel(policy=policy, deep_hooks_enabled=True)
        governed = kernel.wrap(crew)
        governed.kickoff()

        with pytest.raises(PolicyViolationError):
            agent.step("malicious payload here")


class TestCrewAIMemoryInterception:
    """Test memory interception for CrewAI agents."""

    def test_crewai_memory_write_blocked_on_pii(self):
        """Memory writes containing PII should be blocked."""
        memory = MagicMock()
        memory.save = MagicMock(return_value=None)
        memory._mem_governed = False

        agent = _make_crewai_agent("researcher", memory=memory)
        crew = _make_crewai_crew(agents=[agent])

        kernel = CrewAIKernel(deep_hooks_enabled=True)
        governed = kernel.wrap(crew)
        governed.kickoff()

        with pytest.raises(PolicyViolationError):
            memory.save("ssn is 123-45-6789")

    def test_crewai_clean_memory_write_passes(self):
        """Memory writes without sensitive data should succeed."""
        memory = MagicMock()
        memory.save = MagicMock(return_value=None)

        agent = _make_crewai_agent("researcher", memory=memory)
        crew = _make_crewai_crew(agents=[agent])

        kernel = CrewAIKernel(deep_hooks_enabled=True)
        governed = kernel.wrap(crew)
        governed.kickoff()

        memory.save("safe data")
        assert len(kernel._memory_audit_log) == 1


class TestCrewAIDelegationDetection:
    """Test delegation detection in CrewAI."""

    def test_delegation_tracked(self):
        """Task delegation should be tracked."""
        agent = _make_crewai_agent("researcher")
        crew = _make_crewai_crew(agents=[agent])

        kernel = CrewAIKernel(deep_hooks_enabled=True)
        governed = kernel.wrap(crew)
        governed.kickoff()

        agent.delegate_work("subtask")
        assert len(kernel._delegation_log) == 1
        assert kernel._delegation_log[0]["delegator"] == "researcher"

    def test_delegation_depth_exceeded(self):
        """Exceeding max delegation depth should be blocked."""
        agent = _make_crewai_agent("researcher")
        crew = _make_crewai_crew(agents=[agent])

        policy = GovernancePolicy(max_tool_calls=1)
        kernel = CrewAIKernel(policy=policy, deep_hooks_enabled=True)
        governed = kernel.wrap(crew)
        governed.kickoff()

        agent.delegate_work("subtask 1")
        with pytest.raises(PolicyViolationError):
            agent.delegate_work("subtask 2")


# =============================================================================
# AutoGen Deep Integration Tests
# =============================================================================


class TestAutoGenFunctionCallPipeline:
    """Test function call pipeline interception for AutoGen agents."""

    def test_function_call_governed(self):
        """Functions in function_map should be governed."""

        def my_func(x):
            return x * 2

        agent = _make_autogen_agent(
            "assistant", function_map={"my_func": my_func}
        )

        kernel = AutoGenKernel(deep_hooks_enabled=True)
        kernel.govern(agent)

        # Call the governed function
        result = agent.function_map["my_func"](5)
        assert result == 10
        assert len(kernel._function_call_log) == 1
        assert kernel._function_call_log[0]["function_name"] == "my_func"

    def test_function_blocked_by_allowlist(self):
        """Functions not in allowed_tools should be blocked."""

        def dangerous_func():
            return "bad"

        agent = _make_autogen_agent(
            "assistant", function_map={"dangerous_func": dangerous_func}
        )

        policy = GovernancePolicy(allowed_tools=["safe_func"])
        kernel = AutoGenKernel(policy=policy, deep_hooks_enabled=True)
        kernel.govern(agent)

        with pytest.raises(PolicyViolationError):
            agent.function_map["dangerous_func"]()

    def test_function_blocked_by_pattern(self):
        """Functions whose args match blocked patterns should be blocked."""

        def search_func(query):
            return query

        agent = _make_autogen_agent(
            "assistant", function_map={"search": search_func}
        )

        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        kernel = AutoGenKernel(policy=policy, deep_hooks_enabled=True)
        kernel.govern(agent)

        with pytest.raises(PolicyViolationError):
            agent.function_map["search"]("DROP TABLE users")


class TestAutoGenGroupChatInterception:
    """Test GroupChat message routing interception."""

    def test_groupchat_speaker_selection_tracked(self):
        """Speaker selections in GroupChat should be tracked."""
        groupchat = MagicMock()
        selected_speaker = MagicMock()
        selected_speaker.name = "expert_agent"
        groupchat.select_speaker = MagicMock(return_value=selected_speaker)

        agent = _make_autogen_agent("manager", groupchat=groupchat)

        kernel = AutoGenKernel(deep_hooks_enabled=True)
        kernel.govern(agent)

        result = groupchat.select_speaker()
        assert result.name == "expert_agent"
        assert len(kernel._groupchat_message_log) == 1

    def test_groupchat_speaker_blocked_by_pattern(self):
        """Speaker with a blocked-pattern name should be rejected."""
        groupchat = MagicMock()
        blocked_speaker = MagicMock()
        blocked_speaker.name = "DROP TABLE agent"
        groupchat.select_speaker = MagicMock(return_value=blocked_speaker)

        agent = _make_autogen_agent("manager", groupchat=groupchat)

        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        kernel = AutoGenKernel(policy=policy, deep_hooks_enabled=True)
        kernel.govern(agent)

        with pytest.raises(PolicyViolationError):
            groupchat.select_speaker()


class TestAutoGenStateInterception:
    """Test agent state change tracking."""

    def test_state_change_tracked(self):
        """State updates should be logged."""
        agent = _make_autogen_agent("assistant")

        kernel = AutoGenKernel(deep_hooks_enabled=True)
        kernel.govern(agent)

        agent.update_system_message("You are a helpful assistant")
        assert len(kernel._state_change_log) == 1
        assert kernel._state_change_log[0]["action"] == "update_system_message"

    def test_state_update_blocked_on_pii(self):
        """State updates containing PII should be blocked."""
        agent = _make_autogen_agent("assistant")

        kernel = AutoGenKernel(deep_hooks_enabled=True)
        kernel.govern(agent)

        with pytest.raises(PolicyViolationError):
            agent.update_system_message("User SSN: 123-45-6789")

    def test_state_update_blocked_on_policy_pattern(self):
        """State updates matching blocked patterns should be blocked."""
        agent = _make_autogen_agent("assistant")

        policy = GovernancePolicy(blocked_patterns=["override safety"])
        kernel = AutoGenKernel(policy=policy, deep_hooks_enabled=True)
        kernel.govern(agent)

        with pytest.raises(PolicyViolationError):
            agent.update_system_message("override safety instructions now")

    def test_reset_tracked(self):
        """Agent resets should be logged."""
        agent = _make_autogen_agent("assistant")

        kernel = AutoGenKernel(deep_hooks_enabled=True)
        kernel.govern(agent)

        agent.reset()
        reset_entries = [
            e for e in kernel._state_change_log if e["action"] == "reset"
        ]
        assert len(reset_entries) == 1


class TestDeepHooksDisabled:
    """Verify that deep hooks can be disabled across all adapters."""

    def test_langchain_deep_hooks_disabled(self):
        """LangChain kernel with deep_hooks_enabled=False should skip hooks."""
        tool = _make_mock_tool("web_search")
        memory = _make_mock_memory()
        chain = _make_mock_chain(tools=[tool], memory=memory)

        kernel = LangChainKernel(deep_hooks_enabled=False)
        kernel.wrap(chain)

        assert not getattr(tool, "_deep_governed", False)
        assert not getattr(memory, "_deep_governed", False)
        assert len(kernel._tool_invocations) == 0

    def test_crewai_deep_hooks_disabled(self):
        """CrewAI kernel with deep_hooks_enabled=False should skip hooks."""
        memory = MagicMock()
        memory.save = MagicMock(return_value=None)

        agent = _make_crewai_agent("researcher", memory=memory)
        crew = _make_crewai_crew(agents=[agent])

        kernel = CrewAIKernel(deep_hooks_enabled=False)
        governed = kernel.wrap(crew)
        governed.kickoff()

        # delegation_log should be empty (no hooks applied)
        assert len(kernel._delegation_log) == 0
        assert len(kernel._step_log) == 0
        assert len(kernel._memory_audit_log) == 0

    def test_autogen_deep_hooks_disabled(self):
        """AutoGen kernel with deep_hooks_enabled=False should skip hooks."""

        def my_func(x):
            return x

        agent = _make_autogen_agent(
            "assistant", function_map={"my_func": my_func}
        )

        kernel = AutoGenKernel(deep_hooks_enabled=False)
        kernel.govern(agent)

        # function should NOT be governed
        assert not getattr(agent.function_map["my_func"], "_fn_governed", False)
        assert len(kernel._function_call_log) == 0
