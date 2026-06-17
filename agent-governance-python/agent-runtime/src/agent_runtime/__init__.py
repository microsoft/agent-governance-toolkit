# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Runtime - execution supervisor for multi-agent sessions.

This package re-exports the full public API from ``hypervisor`` so that
callers can migrate their imports incrementally.

.. deprecated::
    ``agentmesh-runtime`` is deprecated and will be removed in a future
    release. Use ``agent-governance-toolkit-core`` instead. See
    https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md
"""

import warnings

warnings.warn(
    "agentmesh-runtime is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

# Keep in sync with the ``version`` field in pyproject.toml.
__version__ = "4.1.0"

from hypervisor import (  # noqa: E402,F401
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

# Deployment Runtime (v3.0.2+)
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
