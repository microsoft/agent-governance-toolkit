# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for CrewAI adapter tool-level interception.

Verifies that individual tool calls within a CrewAI crew are validated
against governance policy (allowed_tools, blocked_patterns, max_tool_calls).
"""

import pytest
from unittest.mock import MagicMock

from agent_os.integrations.crewai_adapter import CrewAIKernel, wrap
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError


class TestCrewAIToolInterception:
    """Test per-tool-call governance in CrewAI adapter."""

    def _make_tool(self, name="web_search"):
        """Create a mock CrewAI tool."""
        tool = MagicMock()
        tool.name = name
        tool._run = MagicMock(return_value="tool result")
        tool._governed = False
        return tool

    def _make_agent(self, name="researcher", tools=None):
        """Create a mock CrewAI agent with tools."""
        agent = MagicMock()
        agent.name = name
        agent.tools = tools or []
        agent.execute_task = MagicMock(return_value="task done")
        return agent

    def _make_crew(self, agents=None):
        """Create a mock CrewAI crew."""
        crew = MagicMock()
        crew.name = "test-crew"
        crew.id = None
        crew.agents = agents or []
        crew.kickoff.return_value = "crew result"
        return crew

    def test_allowed_tool_passes(self):
        """Tool on the allowlist should execute normally."""
        tool = self._make_tool("web_search")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        policy = GovernancePolicy(allowed_tools=["web_search", "read_file"])
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()

        # Tool should be wrapped
        assert tool._governed is True
        # Call the wrapped tool to verify it passes
        tool._run(query="test")
        # Original _run should have been called (via governed wrapper)

    def test_blocked_tool_raises(self):
        """Tool NOT on the allowlist should be blocked."""
        tool = self._make_tool("execute_shell")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        policy = GovernancePolicy(allowed_tools=["web_search", "read_file"])
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()

        with pytest.raises(PolicyViolationError, match="not in allowed list"):
            tool._run(command="rm -rf /")

    def test_blocked_pattern_in_args(self):
        """Tool args matching blocked pattern should be rejected."""
        tool = self._make_tool("web_search")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        policy = GovernancePolicy(blocked_patterns=["password", "secret"])
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()

        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            tool._run(query="find the password for admin")

    def test_max_tool_calls_enforced(self):
        """Should block after max_tool_calls reached."""
        tool = self._make_tool("web_search")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        # post_execute in kickoff increments call_count by 1,
        # so effective tool budget = max_tool_calls - 1
        policy = GovernancePolicy(max_tool_calls=3)
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()  # call_count → 1 (from post_execute)

        # Two tool calls succeed (count 1→2, 2→3)
        tool._run(query="first")
        tool._run(query="second")

        # Third should be blocked (count=3 >= max=3)
        with pytest.raises(PolicyViolationError, match="Max tool calls exceeded"):
            tool._run(query="third")

    def test_multiple_tools_on_same_agent(self):
        """All tools on an agent should be wrapped."""
        search = self._make_tool("web_search")
        read = self._make_tool("read_file")
        shell = self._make_tool("execute_shell")
        agent = self._make_agent(tools=[search, read, shell])
        crew = self._make_crew(agents=[agent])

        policy = GovernancePolicy(allowed_tools=["web_search", "read_file"])
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()

        # Allowed tools work
        search._run(query="test")
        read._run(path="/tmp/file.txt")

        # Blocked tool raises
        with pytest.raises(PolicyViolationError):
            shell._run(command="whoami")

    def test_tools_across_multiple_agents(self):
        """Tools on all agents in a crew should be governed."""
        tool1 = self._make_tool("web_search")
        tool2 = self._make_tool("execute_shell")
        agent1 = self._make_agent("safe-agent", tools=[tool1])
        agent2 = self._make_agent("risky-agent", tools=[tool2])
        crew = self._make_crew(agents=[agent1, agent2])

        policy = GovernancePolicy(allowed_tools=["web_search"])
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()

        tool1._run(query="ok")
        with pytest.raises(PolicyViolationError):
            tool2._run(command="bad")

    def test_no_tools_no_error(self):
        """Agent with no tools should wrap without error."""
        agent = self._make_agent(tools=[])
        crew = self._make_crew(agents=[agent])

        kernel = CrewAIKernel(policy=GovernancePolicy())
        governed = kernel.wrap(crew)
        governed.kickoff()

    def test_no_policy_allows_all(self):
        """Default policy (no restrictions) should allow all tools."""
        tool = self._make_tool("dangerous_tool")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        kernel = CrewAIKernel()
        governed = kernel.wrap(crew)
        governed.kickoff()

        # Should not raise
        tool._run(arg="anything")

    def test_tool_not_double_wrapped(self):
        """Calling kickoff twice shouldn't double-wrap tools."""
        tool = self._make_tool("web_search")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        kernel = CrewAIKernel(policy=GovernancePolicy())
        governed = kernel.wrap(crew)
        governed.kickoff()
        governed.kickoff()

        assert tool._governed is True

    def test_human_approval_blocks_task(self):
        """require_human_approval should block execution at kickoff."""
        tool = self._make_tool("web_search")
        agent = self._make_agent(tools=[tool])
        crew = self._make_crew(agents=[agent])

        policy = GovernancePolicy(require_human_approval=True)
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)

        # With the base pre_execute check, kickoff is blocked immediately
        with pytest.raises(PolicyViolationError, match="requires human approval"):
            governed.kickoff()

    def test_call_count_tracks_across_tools(self):
        """Call count should track across all tools, not per tool."""
        tool_a = self._make_tool("tool_a")
        tool_b = self._make_tool("tool_b")
        agent = self._make_agent(tools=[tool_a, tool_b])
        crew = self._make_crew(agents=[agent])

        # post_execute in kickoff uses 1 call, so budget = 4 - 1 = 3 tool calls
        policy = GovernancePolicy(max_tool_calls=4)
        kernel = CrewAIKernel(policy=policy)
        governed = kernel.wrap(crew)
        governed.kickoff()  # call_count → 1

        tool_a._run(x=1)  # call_count → 2
        tool_b._run(x=2)  # call_count → 3
        tool_a._run(x=3)  # call_count → 4

        with pytest.raises(PolicyViolationError, match="Max tool calls"):
            tool_b._run(x=4)  # call_count=4 >= max=4, blocked
