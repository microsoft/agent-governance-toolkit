# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Hypervisor v2.0

Runtime supervisor for multi-agent Shared Sessions with execution rings,
liability tracking, saga orchestration, and audit trails.

Usage:
    >>> from hypervisor import Hypervisor, SessionConfig, ConsistencyMode
    >>> hv = Hypervisor()
    >>> session = await hv.create_session(
    ...     config=SessionConfig(consistency_mode=ConsistencyMode.EVENTUAL)
    ... )

Version: 2.0.0
"""

__version__ = "3.2.2"

# Centralized constants
from hypervisor import constants  # noqa: F401

# Core models
from hypervisor.audit.commitment import CommitmentEngine

# Audit
from hypervisor.audit.delta import DeltaEngine
from hypervisor.audit.gc import EphemeralGC

# Top-level orchestrator
from hypervisor.core import Hypervisor
from hypervisor.liability import LiabilityMatrix
from hypervisor.liability.attribution import AttributionResult, CausalAttributor
from hypervisor.liability.ledger import LedgerEntryType, LiabilityLedger
from hypervisor.liability.quarantine import QuarantineManager, QuarantineReason
from hypervisor.liability.slashing import SlashingEngine

# Liability engine
from hypervisor.liability.vouching import VouchingEngine, VouchRecord
from hypervisor.models import (
    ConsistencyMode,
    ExecutionRing,
    ReversibilityLevel,
    SessionConfig,
    SessionState,
)
from hypervisor.observability.causal_trace import CausalTraceId

# Observability
from hypervisor.observability.event_bus import EventType, HypervisorEvent, HypervisorEventBus

# Reversibility
from hypervisor.reversibility.registry import ReversibilityRegistry
from hypervisor.rings.breach_detector import BreachSeverity, RingBreachDetector
from hypervisor.rings.classifier import ActionClassifier
from hypervisor.rings.elevation import ElevationDenialReason, RingElevation, RingElevationManager

# Execution rings
from hypervisor.rings.enforcer import RingEnforcer
from hypervisor.saga.checkpoint import CheckpointManager, SemanticCheckpoint
from hypervisor.saga.dsl import SagaDefinition, SagaDSLParser
from hypervisor.saga.fan_out import FanOutOrchestrator, FanOutPolicy

# Saga
from hypervisor.saga.orchestrator import SagaOrchestrator, SagaTimeoutError
from hypervisor.saga.state_machine import SagaState, StepState
from hypervisor.security.kill_switch import KillResult, KillSwitch

# Security
from hypervisor.security.rate_limiter import AgentRateLimiter, RateLimitExceeded

# Session management
from hypervisor.session import SharedSessionObject
from hypervisor.session.intent_locks import (
    DeadlockError,
    IntentLockManager,
    LockContentionError,
    LockIntent,
)
from hypervisor.session.isolation import IsolationLevel
from hypervisor.session.sso import SessionVFS, VFSEdit, VFSPermissionError
from hypervisor.session.vector_clock import CausalViolationError, VectorClock, VectorClockManager

# Verification
from hypervisor.verification.history import TransactionHistoryVerifier

__all__ = [
    # Version
    "__version__",
    # Core
    "Hypervisor",
    # Models
    "ConsistencyMode",
    "ExecutionRing",
    "ReversibilityLevel",
    "SessionConfig",
    "SessionState",
    # Session
    "SharedSessionObject",
    "SessionVFS",
    "VFSEdit",
    "VFSPermissionError",
    "VectorClock",
    "VectorClockManager",
    "CausalViolationError",
    "IntentLockManager",
    "LockIntent",
    "LockContentionError",
    "DeadlockError",
    "IsolationLevel",
    # Liability
    "VouchRecord",
    "VouchingEngine",
    "SlashingEngine",
    "LiabilityMatrix",
    "CausalAttributor",
    "AttributionResult",
    "QuarantineManager",
    "QuarantineReason",
    "LiabilityLedger",
    "LedgerEntryType",
    # Rings
    "RingEnforcer",
    "ActionClassifier",
    "RingElevationManager",
    "RingElevation",
    "ElevationDenialReason",
    "RingBreachDetector",
    "BreachSeverity",
    # Reversibility
    "ReversibilityRegistry",
    # Saga
    "SagaOrchestrator",
    "SagaTimeoutError",
    "SagaState",
    "StepState",
    "FanOutOrchestrator",
    "FanOutPolicy",
    "CheckpointManager",
    "SemanticCheckpoint",
    "SagaDSLParser",
    "SagaDefinition",
    # Audit
    "DeltaEngine",
    "CommitmentEngine",
    "EphemeralGC",
    # Verification
    "TransactionHistoryVerifier",
    # Observability
    "HypervisorEventBus",
    "EventType",
    "HypervisorEvent",
    "CausalTraceId",
    # Security
    "AgentRateLimiter",
    "RateLimitExceeded",
    "KillSwitch",
    "KillResult",
]
