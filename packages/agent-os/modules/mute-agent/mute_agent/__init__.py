# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mute Agent - Decoupling Reasoning from Execution

Layer 5 Reference Implementation: A Listener agent that monitors graph states
without interfering until configured thresholds are exceeded.

Consolidated Stack:
- agent-control-plane: Base orchestration
- scak: Intelligence/Knowledge layer
- iatp: Security/Trust layer  
- caas: Context-as-a-Service layer
"""

__version__ = "3.1.1"

# Core components
from .core.reasoning_agent import ReasoningAgent
from .core.execution_agent import ExecutionAgent
from .core.handshake_protocol import HandshakeProtocol
from .knowledge_graph.multidimensional_graph import MultidimensionalKnowledgeGraph
from .super_system.router import SuperSystemRouter

# Layer 5: Listener Agent
from .listener import (
    ListenerAgent,
    ListenerState,
    InterventionEvent,
    ThresholdConfig,
    ThresholdType,
    InterventionLevel,
    DEFAULT_THRESHOLDS,
    StateObserver,
    ObservationResult,
)

# Layer adapters
from .listener.adapters import (
    ControlPlaneAdapter,
    IntelligenceAdapter,
    SecurityAdapter,
    ContextAdapter,
)

__all__ = [
    # Core
    "ReasoningAgent",
    "ExecutionAgent",
    "HandshakeProtocol",
    "MultidimensionalKnowledgeGraph",
    "SuperSystemRouter",
    # Layer 5: Listener
    "ListenerAgent",
    "ListenerState",
    "InterventionEvent",
    "ThresholdConfig",
    "ThresholdType",
    "InterventionLevel",
    "DEFAULT_THRESHOLDS",
    "StateObserver",
    "ObservationResult",
    # Adapters
    "ControlPlaneAdapter",
    "IntelligenceAdapter",
    "SecurityAdapter",
    "ContextAdapter",
]
