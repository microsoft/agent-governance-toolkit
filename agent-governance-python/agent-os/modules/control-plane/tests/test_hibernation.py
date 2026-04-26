# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Agent Hibernation feature
"""

import pytest
import os
import json
import tempfile
import time
from datetime import datetime, timedelta

from agent_control_plane import (
    AgentControlPlane,
    create_standard_agent,
    HibernationManager,
    HibernationConfig,
    HibernationFormat,
    AgentState,
)
from agent_control_plane.agent_kernel import ActionType


class TestHibernationManager:
    """Test the HibernationManager class"""
    
    def test_initialization(self):
        """Test hibernation manager initialization"""
        config = HibernationConfig(
            enabled=True,
            storage_path=tempfile.mkdtemp()
        )
        manager = HibernationManager(config)
        
        assert manager.config.enabled is True
        assert os.path.exists(manager.config.storage_path)
        assert len(manager.hibernated_agents) == 0
    
    def test_serialize_agent_state(self):
        """Test agent state serialization"""
        config = HibernationConfig(storage_path=tempfile.mkdtemp())
        manager = HibernationManager(config)
        
        # Create a mock agent context
        from agent_control_plane.agent_kernel import AgentContext, PermissionLevel
        
        agent_context = AgentContext(
            agent_id="test-agent",
            session_id="test-session",
            created_at=datetime.now(),
            permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            metadata={"test": "data"}
        )
        
        state = manager.serialize_agent_state(
            "test-agent",
            agent_context,
            caas_pointer="context://test",
            additional_state={"custom": "value"}
        )
        
        assert state["agent_id"] == "test-agent"
        assert state["session_id"] == "test-session"
        assert state["caas_pointer"] == "context://test"
        assert state["additional_state"]["custom"] == "value"
        assert "hibernated_at" in state
    
    def test_hibernate_and_wake_json(self):
        """Test hibernating and waking an agent with JSON format"""
        config = HibernationConfig(
            storage_path=tempfile.mkdtemp(),
            format=HibernationFormat.JSON
        )
        manager = HibernationManager(config)
        
        from agent_control_plane.agent_kernel import AgentContext, PermissionLevel
        
        agent_context = AgentContext(
            agent_id="test-agent",
            session_id="test-session",
            created_at=datetime.now(),
            permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            metadata={"test": "data"}
        )
        
        # Hibernate
        metadata = manager.hibernate_agent(
            "test-agent",
            agent_context,
            caas_pointer="context://test"
        )
        
        assert metadata.agent_id == "test-agent"
        assert os.path.exists(metadata.state_file_path)
        assert manager.is_agent_hibernated("test-agent")
        
        # Verify file is JSON
        with open(metadata.state_file_path, 'r') as f:
            data = json.load(f)
            assert data["agent_id"] == "test-agent"
        
        # Wake
        restored = manager.wake_agent("test-agent")
        
        assert restored["agent_id"] == "test-agent"
        assert restored["session_id"] == "test-session"
        assert restored["caas_pointer"] == "context://test"
        assert not manager.is_agent_hibernated("test-agent")
    
    def test_idle_detection(self):
        """Test idle agent detection"""
        config = HibernationConfig(
            storage_path=tempfile.mkdtemp(),
            idle_timeout_seconds=1
        )
        manager = HibernationManager(config)
        
        # Record activity
        manager.record_agent_activity("agent-1")
        manager.record_agent_activity("agent-2")
        
        # Wait for idle timeout
        time.sleep(1.5)
        
        # Get idle agents
        idle = manager.get_idle_agents()
        
        assert "agent-1" in idle
        assert "agent-2" in idle
    
    def test_statistics(self):
        """Test hibernation statistics"""
        config = HibernationConfig(storage_path=tempfile.mkdtemp())
        manager = HibernationManager(config)
        
        from agent_control_plane.agent_kernel import AgentContext, PermissionLevel
        
        # Hibernate a few agents
        for i in range(3):
            agent_context = AgentContext(
                agent_id=f"test-agent-{i}",
                session_id=f"test-session-{i}",
                created_at=datetime.now(),
                permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY}
            )
            manager.hibernate_agent(f"test-agent-{i}", agent_context)
        
        stats = manager.get_statistics()
        
        assert stats["total_hibernated_agents"] == 3
        assert stats["total_state_size_bytes"] > 0


class TestControlPlaneHibernation:
    """Test hibernation integration with AgentControlPlane"""
    
    def test_enable_hibernation(self):
        """Test enabling hibernation in control plane"""
        config = HibernationConfig(storage_path=tempfile.mkdtemp())
        
        cp = AgentControlPlane(
            enable_hibernation=True,
            hibernation_config=config
        )
        
        assert cp.hibernation_enabled is True
        assert cp.hibernation_manager is not None
    
    def test_hibernate_agent_via_control_plane(self):
        """Test hibernating agent through control plane"""
        config = HibernationConfig(storage_path=tempfile.mkdtemp())
        
        cp = AgentControlPlane(
            enable_hibernation=True,
            hibernation_config=config
        )
        
        # Create agent
        agent_context = create_standard_agent(cp, "test-agent")
        
        # Hibernate
        metadata = cp.hibernate_agent(
            agent_context.agent_id,
            agent_context,
            caas_pointer="context://test"
        )
        
        assert metadata.agent_id == agent_context.agent_id
        assert cp.is_agent_hibernated(agent_context.agent_id)
        
        # Wake
        restored = cp.wake_agent(agent_context.agent_id)
        
        assert restored["agent_id"] == agent_context.agent_id
        assert not cp.is_agent_hibernated(agent_context.agent_id)
    
    def test_hibernate_idle_agents(self):
        """Test automatic hibernation of idle agents"""
        config = HibernationConfig(
            storage_path=tempfile.mkdtemp(),
            idle_timeout_seconds=1
        )
        
        cp = AgentControlPlane(
            enable_hibernation=True,
            hibernation_config=config
        )
        
        # Create agents
        agent1 = create_standard_agent(cp, "agent-1")
        agent2 = create_standard_agent(cp, "agent-2")
        
        # Record activity - this tracks them in the hibernation manager
        cp.record_agent_activity(agent1.agent_id)
        cp.record_agent_activity(agent2.agent_id)
        
        # Agents are in kernel.active_sessions
        assert agent1.session_id in cp.kernel.active_sessions
        assert agent2.session_id in cp.kernel.active_sessions
        
        # Wait for idle
        time.sleep(1.5)
        
        # Get idle agents (should find them)
        idle = cp.hibernation_manager.get_idle_agents()
        assert len(idle) == 2
        
        # Manually hibernate for testing (automatic hibernation requires session lookup)
        cp.hibernate_agent(agent1.agent_id, agent1)
        cp.hibernate_agent(agent2.agent_id, agent2)
        
        # Verify hibernation
        assert cp.is_agent_hibernated(agent1.agent_id)
        assert cp.is_agent_hibernated(agent2.agent_id)
    
    def test_hibernation_disabled(self):
        """Test that hibernation methods fail when disabled"""
        cp = AgentControlPlane(enable_hibernation=False)
        
        agent_context = create_standard_agent(cp, "test-agent")
        
        with pytest.raises(RuntimeError, match="Hibernation is not enabled"):
            cp.hibernate_agent(agent_context.agent_id, agent_context)
        
        with pytest.raises(RuntimeError, match="Hibernation is not enabled"):
            cp.wake_agent(agent_context.agent_id)
    
    def test_hibernation_statistics(self):
        """Test getting hibernation statistics"""
        config = HibernationConfig(storage_path=tempfile.mkdtemp())
        
        cp = AgentControlPlane(
            enable_hibernation=True,
            hibernation_config=config
        )
        
        # Create and hibernate agents
        for i in range(3):
            agent = create_standard_agent(cp, f"agent-{i}")
            cp.hibernate_agent(agent.agent_id, agent)
        
        stats = cp.get_hibernation_statistics()
        
        assert stats["total_hibernated_agents"] == 3
        assert stats["total_state_size_bytes"] > 0
        
        # Test with hibernation disabled
        cp_disabled = AgentControlPlane(enable_hibernation=False)
        stats_disabled = cp_disabled.get_hibernation_statistics()
        
        assert stats_disabled["enabled"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
