# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Agent Hibernation - State-to-Disk Serialization

Feature: "Agent Hibernation (state-to-disk)"
Problem: Agents sitting idle in memory cost money (if hosted) or RAM.
Solution: Serialize the entire agent state (including caas pointer) to a JSON/Pickle file
         and kill the process. Wake it up only when amb receives a message for it.
Result: Scale by Subtraction - Removes the need for "always-on" servers. Serverless Agents.

This module provides the infrastructure to hibernate idle agents by serializing
their complete state to disk and restoring them when needed.
"""

from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import json
import pickle
import os
import logging
from pathlib import Path


class HibernationFormat(Enum):
    """Format for serializing agent state"""
    JSON = "json"
    PICKLE = "pickle"


class AgentState(Enum):
    """State of an agent in the hibernation lifecycle"""
    ACTIVE = "active"
    HIBERNATING = "hibernating"
    HIBERNATED = "hibernated"
    WAKING = "waking"


@dataclass
class HibernatedAgentMetadata:
    """Metadata about a hibernated agent"""
    agent_id: str
    session_id: str
    hibernated_at: datetime
    state_file_path: str
    format: HibernationFormat
    state_size_bytes: int
    last_activity: datetime
    context_pointer: Optional[str] = None  # caas pointer
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HibernationConfig:
    """Configuration for agent hibernation"""
    enabled: bool = True
    idle_timeout_seconds: int = 300  # 5 minutes default
    storage_path: str = "/tmp/agent_hibernation"
    format: HibernationFormat = HibernationFormat.JSON
    max_hibernated_agents: int = 1000
    auto_cleanup_days: int = 7  # Clean up hibernated agents after 7 days
    compress: bool = False


class HibernationManager:
    """
    Manages agent hibernation and wake-up operations.
    
    This class handles:
    - Serialization of complete agent state to disk
    - Deserialization and restoration of agent state
    - Tracking of hibernated agents
    - Automatic cleanup of old hibernated states
    """
    
    def __init__(self, config: Optional[HibernationConfig] = None):
        """
        Initialize the hibernation manager.
        
        Args:
            config: Configuration for hibernation behavior
        """
        self.config = config or HibernationConfig()
        self.logger = logging.getLogger("HibernationManager")
        
        # Create storage directory if it doesn't exist
        Path(self.config.storage_path).mkdir(parents=True, exist_ok=True)
        
        # Track hibernated agents
        self.hibernated_agents: Dict[str, HibernatedAgentMetadata] = {}
        
        # Track agent activity for idle detection
        self.agent_activity: Dict[str, datetime] = {}
        
        # Track agent states
        self.agent_states: Dict[str, AgentState] = {}
        
        self.logger.info(f"HibernationManager initialized with storage at {self.config.storage_path}")
    
    def serialize_agent_state(
        self,
        agent_id: str,
        agent_context: Any,
        caas_pointer: Optional[str] = None,
        additional_state: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Serialize agent state to a dictionary.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_context: AgentContext object containing agent session data
            caas_pointer: Optional pointer to context in caas (Context-as-a-Service)
            additional_state: Optional additional state to serialize
            
        Returns:
            Dictionary containing serialized agent state
        """
        state = {
            "agent_id": agent_id,
            "session_id": agent_context.session_id,
            "created_at": agent_context.created_at.isoformat(),
            "permissions": {
                str(k): v.value for k, v in agent_context.permissions.items()
            },
            "metadata": agent_context.metadata,
            "caas_pointer": caas_pointer,
            "hibernated_at": datetime.now().isoformat(),
            "additional_state": additional_state or {}
        }
        
        return state
    
    def deserialize_agent_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deserialize agent state from a dictionary.
        
        Args:
            state: Dictionary containing serialized agent state
            
        Returns:
            Dictionary with deserialized state components
        """
        # Convert ISO format strings back to datetime
        if "created_at" in state:
            state["created_at"] = datetime.fromisoformat(state["created_at"])
        if "hibernated_at" in state:
            state["hibernated_at"] = datetime.fromisoformat(state["hibernated_at"])
        
        return state
    
    def hibernate_agent(
        self,
        agent_id: str,
        agent_context: Any,
        caas_pointer: Optional[str] = None,
        additional_state: Optional[Dict[str, Any]] = None
    ) -> HibernatedAgentMetadata:
        """
        Hibernate an agent by saving its state to disk.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_context: AgentContext object to serialize
            caas_pointer: Optional pointer to context in caas
            additional_state: Optional additional state to save
            
        Returns:
            Metadata about the hibernated agent
        """
        self.logger.info(f"Hibernating agent {agent_id}")
        
        # Update agent state
        self.agent_states[agent_id] = AgentState.HIBERNATING
        
        # Serialize agent state
        state = self.serialize_agent_state(agent_id, agent_context, caas_pointer, additional_state)
        
        # Determine file path
        file_name = f"{agent_id}_{agent_context.session_id}.{self.config.format.value}"
        file_path = os.path.join(self.config.storage_path, file_name)
        
        # Save to disk
        try:
            if self.config.format == HibernationFormat.JSON:
                with open(file_path, 'w') as f:
                    json.dump(state, f, indent=2)
            else:  # PICKLE
                with open(file_path, 'wb') as f:
                    pickle.dump(state, f)
            
            # Get file size
            state_size = os.path.getsize(file_path)
            
            # Create metadata
            metadata = HibernatedAgentMetadata(
                agent_id=agent_id,
                session_id=agent_context.session_id,
                hibernated_at=datetime.now(),
                state_file_path=file_path,
                format=self.config.format,
                state_size_bytes=state_size,
                last_activity=self.agent_activity.get(agent_id, datetime.now()),
                context_pointer=caas_pointer
            )
            
            # Track hibernated agent
            self.hibernated_agents[agent_id] = metadata
            self.agent_states[agent_id] = AgentState.HIBERNATED
            
            self.logger.info(f"Agent {agent_id} hibernated successfully. State saved to {file_path} ({state_size} bytes)")
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Failed to hibernate agent {agent_id}: {e}")
            self.agent_states[agent_id] = AgentState.ACTIVE
            raise
    
    def wake_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Wake up a hibernated agent by restoring its state from disk.
        
        Args:
            agent_id: Unique identifier for the agent to wake
            
        Returns:
            Dictionary containing the restored agent state
        """
        if agent_id not in self.hibernated_agents:
            raise ValueError(f"Agent {agent_id} is not hibernated")
        
        self.logger.info(f"Waking agent {agent_id}")
        
        # Update state
        self.agent_states[agent_id] = AgentState.WAKING
        
        metadata = self.hibernated_agents[agent_id]
        
        try:
            # Load state from disk
            if metadata.format == HibernationFormat.JSON:
                with open(metadata.state_file_path, 'r') as f:
                    state = json.load(f)
            else:  # PICKLE
                with open(metadata.state_file_path, 'rb') as f:
                    state = pickle.load(f)
            
            # Deserialize state
            restored_state = self.deserialize_agent_state(state)
            
            # Update tracking
            self.agent_activity[agent_id] = datetime.now()
            self.agent_states[agent_id] = AgentState.ACTIVE
            
            # Remove from hibernated agents
            del self.hibernated_agents[agent_id]
            
            self.logger.info(f"Agent {agent_id} woken successfully")
            
            return restored_state
            
        except Exception as e:
            self.logger.error(f"Failed to wake agent {agent_id}: {e}")
            self.agent_states[agent_id] = AgentState.HIBERNATED
            raise
    
    def is_agent_hibernated(self, agent_id: str) -> bool:
        """Check if an agent is currently hibernated"""
        return agent_id in self.hibernated_agents
    
    def get_hibernated_agents(self) -> List[HibernatedAgentMetadata]:
        """Get list of all hibernated agents"""
        return list(self.hibernated_agents.values())
    
    def record_agent_activity(self, agent_id: str):
        """Record activity for an agent (resets idle timer)"""
        self.agent_activity[agent_id] = datetime.now()
        if agent_id not in self.agent_states or self.agent_states[agent_id] == AgentState.HIBERNATED:
            self.agent_states[agent_id] = AgentState.ACTIVE
    
    def get_idle_agents(self, min_idle_seconds: Optional[int] = None) -> List[str]:
        """
        Get list of agent IDs that have been idle for the specified duration.
        
        Args:
            min_idle_seconds: Minimum idle time in seconds (uses config default if None)
            
        Returns:
            List of agent IDs that are idle
        """
        idle_threshold = min_idle_seconds or self.config.idle_timeout_seconds
        now = datetime.now()
        idle_agents = []
        
        for agent_id, last_activity in self.agent_activity.items():
            # Skip already hibernated agents
            if self.is_agent_hibernated(agent_id):
                continue
            
            idle_time = (now - last_activity).total_seconds()
            if idle_time >= idle_threshold:
                idle_agents.append(agent_id)
        
        return idle_agents
    
    def cleanup_old_hibernated_agents(self, max_age_days: Optional[int] = None):
        """
        Clean up hibernated agents older than the specified age.
        
        Args:
            max_age_days: Maximum age in days (uses config default if None)
        """
        max_age = max_age_days or self.config.auto_cleanup_days
        now = datetime.now()
        cleanup_threshold = timedelta(days=max_age)
        
        agents_to_cleanup = []
        for agent_id, metadata in self.hibernated_agents.items():
            age = now - metadata.hibernated_at
            if age > cleanup_threshold:
                agents_to_cleanup.append(agent_id)
        
        for agent_id in agents_to_cleanup:
            self._cleanup_hibernated_agent(agent_id)
    
    def _cleanup_hibernated_agent(self, agent_id: str):
        """Remove hibernated agent and delete its state file"""
        if agent_id not in self.hibernated_agents:
            return
        
        metadata = self.hibernated_agents[agent_id]
        
        try:
            # Delete state file
            if os.path.exists(metadata.state_file_path):
                os.remove(metadata.state_file_path)
            
            # Remove from tracking
            del self.hibernated_agents[agent_id]
            if agent_id in self.agent_states:
                del self.agent_states[agent_id]
            if agent_id in self.agent_activity:
                del self.agent_activity[agent_id]
            
            self.logger.info(f"Cleaned up hibernated agent {agent_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup hibernated agent {agent_id}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about hibernation"""
        total_hibernated = len(self.hibernated_agents)
        total_size = sum(m.state_size_bytes for m in self.hibernated_agents.values())
        
        return {
            "total_hibernated_agents": total_hibernated,
            "total_state_size_bytes": total_size,
            "total_state_size_mb": total_size / (1024 * 1024),
            "active_agents": len([s for s in self.agent_states.values() if s == AgentState.ACTIVE]),
            "storage_path": self.config.storage_path,
            "format": self.config.format.value,
            "idle_timeout_seconds": self.config.idle_timeout_seconds
        }
