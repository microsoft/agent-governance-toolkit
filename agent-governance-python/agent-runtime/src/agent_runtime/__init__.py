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
__version__ = "5.0.0"

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
    CausalViolationError,
    IsolationLevel,
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
    # Audit
    DeltaEngine,
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
    "CausalViolationError",
    "IsolationLevel",
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
    "DeltaEngine",
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
