# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for multi-agent orchestration.
"""

import pytest
import asyncio
from src.agents.orchestrator import (
    Orchestrator,
    AgentSpec,
    AgentRole,
    TaskStatus,
    AgentMessage,
    MessageType
)


class TestOrchestrator:
    """Test orchestrator functionality."""
    
    def setup_method(self):
        """Set up test agents."""
        self.agents = [
            AgentSpec(
                agent_id="supervisor",
                role=AgentRole.SUPERVISOR,
                capabilities=["coordinate"],
                model="gpt-4o"
            ),
            AgentSpec(
                agent_id="analyst",
                role=AgentRole.ANALYST,
                capabilities=["analyze", "investigate"],
                model="gpt-4o"
            ),
            AgentSpec(
                agent_id="verifier",
                role=AgentRole.VERIFIER,
                capabilities=["verify", "validate"],
                model="gpt-4o"
            )
        ]
    
    def test_initialization(self):
        """Test orchestrator initialization."""
        orch = Orchestrator(self.agents)
        
        assert len(orch.agents) == 3
        assert "supervisor" in orch.agents
        assert "analyst" in orch.agents
        assert "verifier" in orch.agents
    
    def test_register_executor(self):
        """Test executor registration."""
        orch = Orchestrator(self.agents)
        
        async def mock_executor(task: str, context: dict) -> dict:
            return {"result": "done"}
        
        orch.register_executor("analyst", mock_executor)
        assert "analyst" in orch.agent_executors
    
    def test_register_executor_unknown_agent(self):
        """Test registering executor for unknown agent."""
        orch = Orchestrator(self.agents)
        
        async def mock_executor(task: str, context: dict) -> dict:
            return {"result": "done"}
        
        with pytest.raises(ValueError, match="Agent unknown not found"):
            orch.register_executor("unknown", mock_executor)
    
    @pytest.mark.asyncio
    async def test_submit_task(self):
        """Test task submission."""
        orch = Orchestrator(self.agents)
        
        # Register executor
        async def mock_executor(task: str, context: dict) -> dict:
            await asyncio.sleep(0.1)
            return {"result": "analysis complete"}
        
        orch.register_executor("analyst", mock_executor)
        
        # Submit task
        task_id = await orch.submit_task("Analyze data")
        
        assert task_id in orch.tasks
        task = orch.tasks[task_id]
        assert task.description == "Analyze data"
        assert task.status == TaskStatus.PENDING
    
    @pytest.mark.asyncio
    async def test_task_execution(self):
        """Test task execution."""
        orch = Orchestrator(self.agents)
        
        # Register executor
        async def mock_executor(task: str, context: dict) -> dict:
            return {"result": "done"}
        
        orch.register_executor("analyst", mock_executor)
        
        # Submit and wait
        task_id = await orch.submit_task("Analyze data")
        await asyncio.sleep(0.5)  # Wait for execution
        
        task = await orch.get_task_status(task_id)
        assert task is not None
        # Status might be IN_PROGRESS or COMPLETED depending on timing
        assert task.status in [TaskStatus.IN_PROGRESS, TaskStatus.COMPLETED]
    
    @pytest.mark.asyncio
    async def test_get_orchestrator_stats(self):
        """Test getting orchestrator statistics."""
        orch = Orchestrator(self.agents)
        
        stats = orch.get_orchestrator_stats()
        
        assert "total_tasks" in stats
        assert "by_status" in stats
        assert "agent_workloads" in stats
        assert stats["total_tasks"] == 0
    
    @pytest.mark.asyncio
    async def test_send_message(self):
        """Test message passing."""
        orch = Orchestrator(self.agents)
        
        message = AgentMessage(
            from_agent="analyst",
            to_agent="verifier",
            message_type=MessageType.REQUEST_ASSISTANCE,
            payload={"help_with": "verification"}
        )
        
        await orch.send_message(message)
        
        # Message should be in queue
        assert not orch.message_queue.empty()


class TestAgentMessage:
    """Test agent message model."""
    
    def test_message_creation(self):
        """Test creating an agent message."""
        message = AgentMessage(
            from_agent="agent1",
            to_agent="agent2",
            message_type=MessageType.TASK_ASSIGNMENT,
            payload={"task": "analyze"}
        )
        
        assert message.from_agent == "agent1"
        assert message.to_agent == "agent2"
        assert message.message_type == MessageType.TASK_ASSIGNMENT
        assert "task" in message.payload
        assert message.message_id is not None


class TestAgentSpec:
    """Test agent specification model."""
    
    def test_spec_creation(self):
        """Test creating agent spec."""
        spec = AgentSpec(
            agent_id="test-agent",
            role=AgentRole.ANALYST,
            capabilities=["analyze", "investigate"],
            model="gpt-4o"
        )
        
        assert spec.agent_id == "test-agent"
        assert spec.role == AgentRole.ANALYST
        assert len(spec.capabilities) == 2
        assert spec.model == "gpt-4o"
        assert spec.max_concurrent_tasks == 3  # default


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
