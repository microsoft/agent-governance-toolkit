# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Runtime — Execution supervisor for multi-agent sessions.

This package is the successor to ``agent-hypervisor``.  It re-exports the
full public API from ``hypervisor`` so that callers can migrate their imports
incrementally::

    # Old
    from hypervisor import Hypervisor, SessionConfig
    # New (equivalent)
    from agent_runtime import Hypervisor, SessionConfig

The ``agent-hypervisor`` package remains available for backward compatibility
and will be deprecated in a future release.
"""


import warnings as _warnings
_warnings.warn(
    "agentmesh-runtime is deprecated. Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)
del _warnings
from hypervisor import (  # noqa: F401
    __version__,
    # Core
    Hypervisor,
    # Models
    ConsistencyMode,
    ExecutionRing,
    ReversibilityLevel,
    SessionConfig,
    SessionState,
    # Session
    SharedSessionObject,
    SessionVFS,
    VFSEdit,
    VFSPermissionError,
    VectorClock,
    VectorClockManager,
    CausalViolationError,
    IntentLockManager,
    LockIntent,
    LockContentionError,
    DeadlockError,
    IsolationLevel,
    # Liability
    VouchRecord,
    VouchingEngine,
    SlashingEngine,
    LiabilityMatrix,
    CausalAttributor,
    AttributionResult,
    QuarantineManager,
    QuarantineReason,
    LiabilityLedger,
    LedgerEntryType,
    # Rings
    RingEnforcer,
    ActionClassifier,
    RingElevationManager,
    RingElevation,
    ElevationDenialReason,
    RingBreachDetector,
    BreachSeverity,
    # Reversibility
    ReversibilityRegistry,
    # Saga
    SagaOrchestrator,
    SagaTimeoutError,
    SagaState,
    StepState,
    FanOutOrchestrator,
    FanOutPolicy,
    CheckpointManager,
    SemanticCheckpoint,
    SagaDSLParser,
    SagaDefinition,
    # Audit
    DeltaEngine,
    CommitmentEngine,
    EphemeralGC,
    # Verification
    TransactionHistoryVerifier,
    # Observability
    HypervisorEventBus,
    EventType,
    HypervisorEvent,
    CausalTraceId,
    # Security
    AgentRateLimiter,
    RateLimitExceeded,
    KillSwitch,
    KillResult,
)

from agent_runtime.deploy import (  # noqa: E402
    DeploymentResult,
    DeploymentStatus,
    DeploymentTarget,
    DockerDeployer,
    GovernanceConfig,
    KubernetesDeployer,
)

__all__ = [
    "__version__",
    "Hypervisor",
    "ConsistencyMode",
    "ExecutionRing",
    "ReversibilityLevel",
    "SessionConfig",
    "SessionState",
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
    "RingEnforcer",
    "ActionClassifier",
    "RingElevationManager",
    "RingElevation",
    "ElevationDenialReason",
    "RingBreachDetector",
    "BreachSeverity",
    "ReversibilityRegistry",
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
    "DeltaEngine",
    "CommitmentEngine",
    "EphemeralGC",
    "TransactionHistoryVerifier",
    "HypervisorEventBus",
    "EventType",
    "HypervisorEvent",
    "CausalTraceId",
    "AgentRateLimiter",
    "RateLimitExceeded",
    "KillSwitch",
    "KillResult",
    "DeploymentResult",
    "DeploymentStatus",
    "DeploymentTarget",
    "DockerDeployer",
    "GovernanceConfig",
    "KubernetesDeployer",
]
