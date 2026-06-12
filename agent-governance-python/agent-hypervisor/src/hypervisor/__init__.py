# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Hypervisor - runtime supervisor for multi-agent Shared Sessions.

.. deprecated::
    ``agent-hypervisor`` is deprecated and will be removed in a future
    release. Use ``agent-governance-toolkit-core`` instead. See
    https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md
"""

import warnings

warnings.warn(
    "agent-hypervisor is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

# Keep in sync with the ``version`` field in pyproject.toml.
__version__ = "4.1.0"

# Centralized constants
from hypervisor import constants  # noqa: F401,E402

# Audit
from hypervisor.audit.commitment import CommitmentEngine  # noqa: E402
from hypervisor.audit.delta import DeltaEngine  # noqa: E402
from hypervisor.audit.gc import EphemeralGC  # noqa: E402

# Top-level orchestrator
from hypervisor.core import Hypervisor  # noqa: E402

# Liability
from hypervisor.liability import LiabilityMatrix  # noqa: E402
from hypervisor.liability.attribution import AttributionResult, CausalAttributor  # noqa: E402
from hypervisor.liability.ledger import LedgerEntryType, LiabilityLedger  # noqa: E402
from hypervisor.liability.quarantine import QuarantineManager, QuarantineReason  # noqa: E402
from hypervisor.liability.slashing import SlashingEngine  # noqa: E402
from hypervisor.liability.vouching import VouchingEngine, VouchRecord  # noqa: E402

# Core models
from hypervisor.models import (  # noqa: E402
    ConsistencyMode,
    ExecutionRing,
    ReversibilityLevel,
    SessionConfig,
    SessionState,
)

# Observability
from hypervisor.observability.causal_trace import CausalTraceId  # noqa: E402
from hypervisor.observability.event_bus import (  # noqa: E402
    EventType,
    HypervisorEvent,
    HypervisorEventBus,
)

# Reversibility
from hypervisor.reversibility.registry import ReversibilityRegistry  # noqa: E402

# Execution rings
from hypervisor.rings.breach_detector import BreachSeverity, RingBreachDetector  # noqa: E402
from hypervisor.rings.classifier import ActionClassifier  # noqa: E402
from hypervisor.rings.elevation import (  # noqa: E402
    ElevationDenialReason,
    RingElevation,
    RingElevationManager,
)
from hypervisor.rings.enforcer import RingEnforcer  # noqa: E402

# Saga
from hypervisor.saga.checkpoint import CheckpointManager, SemanticCheckpoint  # noqa: E402
from hypervisor.saga.dsl import SagaDefinition, SagaDSLParser  # noqa: E402
from hypervisor.saga.fan_out import FanOutOrchestrator, FanOutPolicy  # noqa: E402
from hypervisor.saga.orchestrator import SagaOrchestrator, SagaTimeoutError  # noqa: E402
from hypervisor.saga.state_machine import SagaState, StepState  # noqa: E402

# Security
from hypervisor.security.kill_switch import KillResult, KillSwitch  # noqa: E402
from hypervisor.security.rate_limiter import AgentRateLimiter, RateLimitExceeded  # noqa: E402

# Session management
from hypervisor.session import SharedSessionObject  # noqa: E402
from hypervisor.session.intent_locks import (  # noqa: E402
    DeadlockError,
    IntentLockManager,
    LockContentionError,
    LockIntent,
)
from hypervisor.session.isolation import IsolationLevel  # noqa: E402
from hypervisor.session.sso import SessionVFS, VFSEdit, VFSPermissionError  # noqa: E402
from hypervisor.session.vector_clock import (  # noqa: E402
    CausalViolationError,
    VectorClock,
    VectorClockManager,
)

# Verification
from hypervisor.verification.history import TransactionHistoryVerifier  # noqa: E402

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
