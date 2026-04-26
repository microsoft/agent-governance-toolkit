# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Control Plane Adapter - Base Orchestration Layer Integration

This adapter provides integration with the Agent Control Plane
for base orchestration operations.

In the Listener context, this adapter is used to:
1. Manage agent lifecycle
2. Coordinate action queues
3. Handle agent registration
4. Monitor agent health

The adapter delegates all orchestration to the control plane - no reimplementation.
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto

from .base_adapter import BaseLayerAdapter


class AgentLifecycleState(Enum):
    """States in the agent lifecycle."""
    
    UNREGISTERED = auto()
    REGISTERED = auto()
    INITIALIZING = auto()
    READY = auto()
    BUSY = auto()
    PAUSED = auto()
    ERROR = auto()
    TERMINATING = auto()
    TERMINATED = auto()


@dataclass
class AgentInfo:
    """Information about a registered agent."""
    
    agent_id: str
    agent_type: str
    state: AgentLifecycleState
    registered_at: datetime
    last_heartbeat: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    capabilities: List[str] = None


@dataclass
class ActionQueueStatus:
    """Status of an agent's action queue."""
    
    agent_id: str
    queue_depth: int
    oldest_action_age_ms: float
    processing_rate_per_second: float
    blocked_actions: int


class MockControlPlaneClient:
    """Mock Control Plane client for testing without the actual dependency."""
    
    def __init__(self):
        self._agents: Dict[str, AgentInfo] = {}
        self._queues: Dict[str, List[Dict]] = {}
    
    def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        metadata: Dict[str, Any]
    ) -> AgentInfo:
        """Mock agent registration."""
        info = AgentInfo(
            agent_id=agent_id,
            agent_type=agent_type,
            state=AgentLifecycleState.REGISTERED,
            registered_at=datetime.now(),
            metadata=metadata or {},
            capabilities=capabilities or [],
        )
        self._agents[agent_id] = info
        self._queues[agent_id] = []
        return info
    
    def unregister_agent(self, agent_id: str) -> bool:
        """Mock agent unregistration."""
        if agent_id in self._agents:
            del self._agents[agent_id]
            del self._queues[agent_id]
            return True
        return False
    
    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Mock agent retrieval."""
        return self._agents.get(agent_id)
    
    def list_agents(self, agent_type: Optional[str] = None) -> List[AgentInfo]:
        """Mock agent listing."""
        agents = list(self._agents.values())
        if agent_type:
            agents = [a for a in agents if a.agent_type == agent_type]
        return agents
    
    def update_agent_state(
        self,
        agent_id: str,
        state: AgentLifecycleState
    ) -> AgentInfo:
        """Mock state update."""
        if agent_id in self._agents:
            self._agents[agent_id].state = state
            return self._agents[agent_id]
        return None
    
    def heartbeat(self, agent_id: str) -> bool:
        """Mock heartbeat."""
        if agent_id in self._agents:
            self._agents[agent_id].last_heartbeat = datetime.now()
            return True
        return False
    
    def enqueue_action(
        self,
        agent_id: str,
        action: Dict[str, Any]
    ) -> str:
        """Mock action enqueueing."""
        if agent_id in self._queues:
            action_id = f"action_{len(self._queues[agent_id])}_{datetime.now().timestamp()}"
            action["action_id"] = action_id
            self._queues[agent_id].append(action)
            return action_id
        return None
    
    def get_queue_status(self, agent_id: str) -> ActionQueueStatus:
        """Mock queue status."""
        queue = self._queues.get(agent_id, [])
        return ActionQueueStatus(
            agent_id=agent_id,
            queue_depth=len(queue),
            oldest_action_age_ms=0.0,
            processing_rate_per_second=10.0,
            blocked_actions=0,
        )
    
    def clear_queue(self, agent_id: str) -> int:
        """Mock queue clearing."""
        if agent_id in self._queues:
            count = len(self._queues[agent_id])
            self._queues[agent_id] = []
            return count
        return 0
    
    def close(self) -> None:
        """Close mock client."""
        pass


class ControlPlaneAdapter(BaseLayerAdapter):
    """
    Adapter for Agent Control Plane (base orchestration) layer.
    
    Provides a clean interface for the Listener to access orchestration
    operations without reimplementing any control plane logic.
    
    Usage:
        ```python
        adapter = ControlPlaneAdapter(mock_mode=True)
        adapter.connect()
        
        # Register the listener as an agent
        agent_info = adapter.register_agent(
            agent_id="listener_1",
            agent_type="listener",
            capabilities=["observe", "intervene"]
        )
        
        # Monitor queue depth
        status = adapter.get_queue_status("execution_agent_1")
        if status.queue_depth > 100:
            print("Queue is backing up!")
        
        # Clear blocked actions during emergency
        adapter.clear_queue("execution_agent_1")
        ```
    """
    
    def get_layer_name(self) -> str:
        return "agent-control-plane"
    
    def _create_client(self) -> Any:
        """
        Create the Control Plane client.
        
        In production, this would import and instantiate the actual
        agent-control-plane library client. For now, returns mock.
        """
        try:
            # Attempt to import real Control Plane client
            # from agent_control_plane import Client as ControlPlaneClient
            # return ControlPlaneClient(self.config)
            
            # Fall back to mock if not available
            return self._mock_client()
        except ImportError:
            return self._mock_client()
    
    def _mock_client(self) -> Any:
        """Create mock client for testing."""
        return MockControlPlaneClient()
    
    def _health_ping(self) -> None:
        """Verify Control Plane connection."""
        if self._client:
            # In production: self._client.ping()
            pass
    
    def _get_version(self) -> Optional[str]:
        """Get Control Plane version."""
        if self._client and hasattr(self._client, 'version'):
            return self._client.version
        return "mock-1.0.0" if self.mock_mode else None
    
    # === Control Plane-specific operations ===
    
    def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AgentInfo:
        """
        Register an agent with the control plane.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_type: Type of agent (e.g., "listener", "executor")
            capabilities: List of capabilities
            metadata: Additional metadata
            
        Returns:
            AgentInfo for the registered agent
        """
        self.ensure_connected()
        return self._client.register_agent(
            agent_id, agent_type, capabilities or [], metadata or {}
        )
    
    def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister an agent from the control plane.
        
        Args:
            agent_id: Agent to unregister
            
        Returns:
            True if successfully unregistered
        """
        self.ensure_connected()
        return self._client.unregister_agent(agent_id)
    
    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """
        Get information about a registered agent.
        
        Args:
            agent_id: Agent to retrieve
            
        Returns:
            AgentInfo if found, None otherwise
        """
        self.ensure_connected()
        return self._client.get_agent(agent_id)
    
    def list_agents(
        self,
        agent_type: Optional[str] = None
    ) -> List[AgentInfo]:
        """
        List all registered agents.
        
        Args:
            agent_type: Optional filter by agent type
            
        Returns:
            List of AgentInfo for matching agents
        """
        self.ensure_connected()
        return self._client.list_agents(agent_type)
    
    def update_agent_state(
        self,
        agent_id: str,
        state: AgentLifecycleState
    ) -> AgentInfo:
        """
        Update an agent's lifecycle state.
        
        Args:
            agent_id: Agent to update
            state: New lifecycle state
            
        Returns:
            Updated AgentInfo
        """
        self.ensure_connected()
        return self._client.update_agent_state(agent_id, state)
    
    def heartbeat(self, agent_id: str) -> bool:
        """
        Send a heartbeat for an agent.
        
        Args:
            agent_id: Agent sending heartbeat
            
        Returns:
            True if heartbeat acknowledged
        """
        self.ensure_connected()
        return self._client.heartbeat(agent_id)
    
    def get_queue_status(self, agent_id: str) -> ActionQueueStatus:
        """
        Get status of an agent's action queue.
        
        Args:
            agent_id: Agent whose queue to check
            
        Returns:
            ActionQueueStatus with queue metrics
        """
        self.ensure_connected()
        return self._client.get_queue_status(agent_id)
    
    def clear_queue(self, agent_id: str) -> int:
        """
        Clear an agent's action queue.
        
        Used during emergency interventions to prevent pending
        actions from executing.
        
        Args:
            agent_id: Agent whose queue to clear
            
        Returns:
            Number of actions cleared
        """
        self.ensure_connected()
        return self._client.clear_queue(agent_id)
    
    def enqueue_action(
        self,
        agent_id: str,
        action_type: str,
        parameters: Dict[str, Any],
        priority: int = 0
    ) -> str:
        """
        Enqueue an action for an agent.
        
        Args:
            agent_id: Target agent
            action_type: Type of action
            parameters: Action parameters
            priority: Queue priority (higher = sooner)
            
        Returns:
            Action ID
        """
        self.ensure_connected()
        return self._client.enqueue_action(agent_id, {
            "type": action_type,
            "parameters": parameters,
            "priority": priority,
            "enqueued_at": datetime.now().isoformat(),
        })
    
    def is_agent_healthy(self, agent_id: str) -> bool:
        """
        Check if an agent is healthy.
        
        An agent is healthy if it's in READY or BUSY state and
        has sent a heartbeat recently.
        
        Args:
            agent_id: Agent to check
            
        Returns:
            True if agent is healthy
        """
        info = self.get_agent(agent_id)
        if not info:
            return False
        
        if info.state not in [AgentLifecycleState.READY, AgentLifecycleState.BUSY]:
            return False
        
        if info.last_heartbeat:
            age = (datetime.now() - info.last_heartbeat).total_seconds()
            if age > 30:  # Heartbeat timeout
                return False
        
        return True
    
    def pause_agent(self, agent_id: str) -> bool:
        """
        Pause an agent's execution.
        
        Args:
            agent_id: Agent to pause
            
        Returns:
            True if successfully paused
        """
        info = self.update_agent_state(agent_id, AgentLifecycleState.PAUSED)
        return info is not None and info.state == AgentLifecycleState.PAUSED
    
    def resume_agent(self, agent_id: str) -> bool:
        """
        Resume a paused agent.
        
        Args:
            agent_id: Agent to resume
            
        Returns:
            True if successfully resumed
        """
        info = self.update_agent_state(agent_id, AgentLifecycleState.READY)
        return info is not None and info.state == AgentLifecycleState.READY
