# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for CrewAI adapter structured logging.

Verifies that governance operations emit structured log messages
with crew_name and task_id context as required by issue #184.
"""

import logging
import pytest
from unittest.mock import MagicMock, AsyncMock

from agent_os.integrations.crewai_adapter import CrewAIKernel, wrap
from agent_os.integrations.base import GovernancePolicy


LOGGER_NAME = "agent_os.integrations.crewai_adapter"


class TestCrewAILogging:
    """Test structured logging in CrewAI adapter."""

    def _make_mock_crew(self, name="test-crew"):
        """Create a mock CrewAI crew."""
        crew = MagicMock()
        crew.name = name
        crew.id = None
        crew.kickoff.return_value = "result"
        crew.agents = []
        return crew

    def test_logger_exists(self):
        """Module-level logger should be configured."""
        crewai_logger = logging.getLogger(LOGGER_NAME)
        assert crewai_logger is not None
        assert crewai_logger.name == LOGGER_NAME

    def test_wrap_logs_crew_name(self, caplog):
        """Wrapping a crew should log the crew name at INFO level."""
        kernel = CrewAIKernel()
        crew = self._make_mock_crew(name="research-crew")

        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            kernel.wrap(crew)

        assert any("research-crew" in record.message for record in caplog.records)
        assert any("Wrapping crew" in record.message for record in caplog.records)

    def test_kickoff_logs_execution_start(self, caplog):
        """Kickoff should log execution start."""
        kernel = CrewAIKernel()
        crew = self._make_mock_crew(name="data-crew")
        governed = kernel.wrap(crew)

        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            governed.kickoff()

        assert any(
            "Crew execution started" in record.message and "data-crew" in record.message
            for record in caplog.records
        )

    def test_kickoff_logs_execution_completed(self, caplog):
        """Kickoff should log execution completion."""
        kernel = CrewAIKernel()
        crew = self._make_mock_crew(name="analytics-crew")
        governed = kernel.wrap(crew)

        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            governed.kickoff()

        assert any(
            "Crew execution completed" in record.message and "analytics-crew" in record.message
            for record in caplog.records
        )

    def test_kickoff_logs_policy_violation(self, caplog):
        """Policy violations during kickoff should be logged at WARNING."""
        policy = GovernancePolicy(max_tool_calls=0)
        kernel = CrewAIKernel(policy=policy)
        crew = self._make_mock_crew(name="blocked-crew")
        governed = kernel.wrap(crew)

        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            with pytest.raises(Exception):
                governed.kickoff()

        assert any(
            "blocked by policy" in record.message and "blocked-crew" in record.message
            for record in caplog.records
        )

    @pytest.mark.asyncio
    async def test_async_kickoff_logs_execution(self, caplog):
        """Async kickoff should log execution start and completion."""
        kernel = CrewAIKernel()
        crew = self._make_mock_crew(name="async-crew")
        crew.kickoff_async = AsyncMock(return_value="async-result")
        governed = kernel.wrap(crew)

        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            await governed.kickoff_async()

        messages = [record.message for record in caplog.records]
        assert any("Async crew execution started" in m and "async-crew" in m for m in messages)
        assert any("Async crew execution completed" in m and "async-crew" in m for m in messages)

    def test_wrap_agent_logs_task_monitoring(self, caplog):
        """Wrapping individual agents should log with crew_name and task_id context."""
        kernel = CrewAIKernel()
        mock_task = MagicMock()
        mock_task.id = "task-42"

        mock_agent = MagicMock()
        mock_agent.name = "researcher"
        original_execute = MagicMock(return_value="task-result")
        mock_agent.execute_task = original_execute

        crew = self._make_mock_crew(name="agent-crew")
        crew.agents = [mock_agent]

        # Make kickoff call the agent's execute_task
        def kickoff_with_agents(inputs=None):
            for agent in crew.agents:
                agent.execute_task(mock_task)
            return "result"

        crew.kickoff = kickoff_with_agents

        governed = kernel.wrap(crew)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            governed.kickoff(inputs={"key": "value"})

        messages = [record.message for record in caplog.records]
        assert any("Wrapping individual agent" in m and "agent-crew" in m for m in messages)
        assert any("task_id=task-42" in m for m in messages)

    def test_convenience_wrap_function(self, caplog):
        """The convenience wrap() function should also produce logs."""
        crew = self._make_mock_crew(name="convenience-crew")

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            governed = wrap(crew)

        assert any("convenience-crew" in record.message for record in caplog.records)

    def test_unwrap_logs(self, caplog):
        """Unwrapping a governed crew should log at DEBUG."""
        kernel = CrewAIKernel()
        crew = self._make_mock_crew()
        governed = kernel.wrap(crew)

        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            kernel.unwrap(governed)

        assert any("Unwrapping" in record.message for record in caplog.records)

    def test_crew_without_name_uses_fallback(self, caplog):
        """Crews without a name attribute should use crew_id as fallback."""
        kernel = CrewAIKernel()
        crew = MagicMock(spec=[])  # No attributes at all
        crew.kickoff = MagicMock(return_value="result")

        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            governed = kernel.wrap(crew)

        assert any("crew-" in record.message for record in caplog.records)
