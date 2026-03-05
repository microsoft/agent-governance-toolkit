# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Base Agent Class

Foundation class for all agents in the Carbon Auditor Swarm.
Uses amb-core for message bus communication.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
import asyncio


class AgentState(Enum):
    """Agent lifecycle states."""
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class AgentMetrics:
    """Runtime metrics for an agent."""
    messages_received: int = 0
    messages_sent: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None
    last_activity: Optional[datetime] = None


class BaseAgent(ABC):
    """
    Base class for all agents in the swarm.
    
    Agents are autonomous workers that:
    - Subscribe to topics on the message bus (amb-core)
    - Process messages using their tools (atr)
    - Publish results back to the bus
    """

    def __init__(
        self,
        agent_id: str,
        name: Optional[str] = None,
    ):
        """
        Initialize an agent.
        
        Args:
            agent_id: Unique identifier for this agent
            name: Human-readable name (defaults to agent_id)
        """
        self.agent_id = agent_id
        self.name = name or agent_id
        
        self._state = AgentState.CREATED
        self._metrics = AgentMetrics()
        self._message_handlers: Dict[str, List[Callable]] = {}

    @property
    def state(self) -> AgentState:
        """Current agent state."""
        return self._state

    @property
    def metrics(self) -> AgentMetrics:
        """Agent metrics."""
        return self._metrics

    @property
    @abstractmethod
    def subscribed_topics(self) -> List[str]:
        """Topics this agent subscribes to."""
        pass

    def register_handler(self, topic: str, handler: Callable) -> None:
        """Register a message handler for a topic."""
        if topic not in self._message_handlers:
            self._message_handlers[topic] = []
        self._message_handlers[topic].append(handler)

    def start(self) -> None:
        """Start the agent."""
        if self._state != AgentState.CREATED:
            raise RuntimeError(f"Cannot start agent in state {self._state}")

        self._state = AgentState.STARTING
        self._metrics.start_time = datetime.now(timezone.utc)
        self._state = AgentState.RUNNING
        self._log(f"Agent started")

    def stop(self) -> None:
        """Stop the agent gracefully."""
        self._state = AgentState.STOPPING
        self._state = AgentState.STOPPED
        self._log("Agent stopped")

    def _log(self, message: str, level: str = "INFO") -> None:
        """Log a message with agent context."""
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] [{self.name}] {message}")
