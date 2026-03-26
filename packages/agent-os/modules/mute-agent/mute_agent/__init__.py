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

__version__ = "0.3.0"

# Core components
from .core.execution_agent import ExecutionAgent
from .core.handshake_protocol import HandshakeProtocol
from .core.reasoning_agent import ReasoningAgent
from .knowledge_graph.multidimensional_graph import MultidimensionalKnowledgeGraph

# Layer 5: Listener Agent
from .listener import (
    DEFAULT_THRESHOLDS,
    InterventionEvent,
    InterventionLevel,
    ListenerAgent,
    ListenerState,
    ObservationResult,
    StateObserver,
    ThresholdConfig,
    ThresholdType,
)

# Layer adapters
from .listener.adapters import (
    ContextAdapter,
    ControlPlaneAdapter,
    IntelligenceAdapter,
    SecurityAdapter,
)
from .super_system.router import SuperSystemRouter

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
