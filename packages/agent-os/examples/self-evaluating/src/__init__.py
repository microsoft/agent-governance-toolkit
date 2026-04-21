# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Self-Evolving Agent Framework

A comprehensive framework for building self-improving AI agents with advanced features
including polymorphic output, universal signal bus, agent brokerage, orchestration,
constraint engineering, evaluation engineering, and more.
"""

__version__ = "3.1.1"

# Core agent modules
from .agent import (
    DoerAgent,
    SelfEvolvingAgent,
    MemorySystem,
    AgentTools
)

from .observer import ObserverAgent

# Telemetry and monitoring
from .telemetry import EventStream, TelemetryEvent

# Advanced features - Import only what exists
try:
    from .polymorphic_output import (
        PolymorphicOutputEngine,
        InputContext,
    )
except ImportError:
    pass

try:
    from .universal_signal_bus import UniversalSignalBus
except ImportError:
    pass

try:
    from .agent_brokerage import (
        AgentMarketplace,
        AgentBroker,
        AgentListing,
        AgentPricing,
        PricingModel,
    )
except ImportError:
    pass

try:
    from .agent_metadata import (
        AgentMetadata,
        AgentMetadataManager
    )
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
    from .evaluation_engineering import (
        EvaluationDataset,
        ScoringRubric,
        EvaluationRunner
    )
except ImportError:
    pass

try:
    from .wisdom_curator import (
        WisdomCurator,
        DesignProposal,
        ReviewType
    )
except ImportError:
    pass

try:
    from .circuit_breaker import (
        CircuitBreakerController,
        CircuitBreakerConfig
    )
except ImportError:
    pass

try:
    from .intent_detection import IntentDetector
except ImportError:
    pass

try:
    from .ghost_mode import (
        GhostModeObserver,
        ContextShadow,
        BehaviorPattern,
        ObservationResult
    )
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
    'DoerAgent',
    'SelfEvolvingAgent',
    'MemorySystem',
    'AgentTools',
    'ObserverAgent',
    'EventStream',
    'TelemetryEvent',
]

