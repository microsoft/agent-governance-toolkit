# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Self-Evolving Agent Framework

A comprehensive framework for building self-improving AI agents with advanced features
including polymorphic output, universal signal bus, agent brokerage, orchestration,
constraint engineering, evaluation engineering, and more.
"""

__version__ = "1.0.0"

# Core agent modules
from .agent import AgentTools, DoerAgent, MemorySystem, SelfEvolvingAgent
from .observer import ObserverAgent

# Telemetry and monitoring
from .telemetry import EventStream, TelemetryEvent

# Advanced features - Import only what exists
try:
    from .polymorphic_output import (
        InputContext,
        PolymorphicOutputEngine,
    )
except ImportError:
    pass

try:
    from .universal_signal_bus import UniversalSignalBus
except ImportError:
    pass

try:
    from .agent_brokerage import (
        AgentBroker,
        AgentListing,
        AgentMarketplace,
        AgentPricing,
        PricingModel,
    )
except ImportError:
    pass

try:
    from .agent_metadata import AgentMetadata, AgentMetadataManager
except ImportError:
    pass

try:
    from .orchestrator import (
        Orchestrator,
        WorkerDefinition,
        WorkerType,
    )
except ImportError:
    pass

try:
    from .constraint_engine import ConstraintEngine
except ImportError:
    pass

try:
    from .evaluation_engineering import EvaluationDataset, EvaluationRunner, ScoringRubric
except ImportError:
    pass

try:
    from .wisdom_curator import DesignProposal, ReviewType, WisdomCurator
except ImportError:
    pass

try:
    from .circuit_breaker import CircuitBreakerConfig, CircuitBreakerController
except ImportError:
    pass

try:
    from .intent_detection import IntentDetector
except ImportError:
    pass

try:
    from .ghost_mode import BehaviorPattern, ContextShadow, GhostModeObserver, ObservationResult
except ImportError:
    pass

try:
    from .prioritization import PrioritizationFramework
except ImportError:
    pass

try:
    from .model_upgrade import ModelUpgradeManager
except ImportError:
    pass

try:
    from .generative_ui_engine import GenerativeUIEngine
except ImportError:
    pass

__all__ = [
    "DoerAgent",
    "SelfEvolvingAgent",
    "MemorySystem",
    "AgentTools",
    "ObserverAgent",
    "EventStream",
    "TelemetryEvent",
]
