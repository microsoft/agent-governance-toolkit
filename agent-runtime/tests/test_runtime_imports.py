# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the agent-runtime package (#493).

Verifies that all re-exported symbols from ``agent_runtime`` are importable,
key classes can be instantiated where feasible, and the version string exists.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# 1. All re-exported symbols are importable
# ---------------------------------------------------------------------------

ALL_EXPORTS = [
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
    # Deployment Runtime
    "DeploymentResult",
    "DeploymentStatus",
    "DeploymentTarget",
    "DockerDeployer",
    "GovernanceConfig",
    "KubernetesDeployer",
]


@pytest.mark.parametrize("symbol", ALL_EXPORTS)
def test_symbol_importable(symbol: str):
    """Every symbol listed in __all__ should be importable."""
    import agent_runtime

    obj = getattr(agent_runtime, symbol, None)
    assert obj is not None, f"{symbol} is not accessible on agent_runtime"


def test_all_list_matches_exports():
    """__all__ should contain exactly the expected symbols."""
    import agent_runtime

    assert set(agent_runtime.__all__) == set(ALL_EXPORTS)


# ---------------------------------------------------------------------------
# 2. Version string exists and is well-formed
# ---------------------------------------------------------------------------


def test_version_string_exists():
    """agent_runtime.__version__ should be a non-empty string."""
    import agent_runtime

    assert isinstance(agent_runtime.__version__, str)
    assert len(agent_runtime.__version__) > 0


def test_version_has_parts():
    """Version should have at least major.minor structure."""
    import agent_runtime

    parts = agent_runtime.__version__.split(".")
    assert len(parts) >= 2, f"Expected at least major.minor, got {agent_runtime.__version__}"


# ---------------------------------------------------------------------------
# 3. Key classes / enums can be instantiated or inspected
# ---------------------------------------------------------------------------


def test_instantiate_vector_clock():
    from agent_runtime import VectorClock

    vc = VectorClock()
    assert vc is not None


def test_instantiate_vector_clock_manager():
    from agent_runtime import VectorClockManager

    mgr = VectorClockManager()
    assert mgr is not None


def test_instantiate_intent_lock_manager():
    from agent_runtime import IntentLockManager

    mgr = IntentLockManager()
    assert mgr is not None


def test_enum_consistency_mode():
    from agent_runtime import ConsistencyMode

    assert hasattr(ConsistencyMode, "__members__")
    assert len(ConsistencyMode.__members__) > 0


def test_enum_execution_ring():
    from agent_runtime import ExecutionRing

    assert hasattr(ExecutionRing, "__members__")
    assert len(ExecutionRing.__members__) > 0


def test_enum_reversibility_level():
    from agent_runtime import ReversibilityLevel

    assert hasattr(ReversibilityLevel, "__members__")
    assert len(ReversibilityLevel.__members__) > 0


def test_enum_isolation_level():
    from agent_runtime import IsolationLevel

    assert hasattr(IsolationLevel, "__members__")
    assert len(IsolationLevel.__members__) > 0


def test_enum_quarantine_reason():
    from agent_runtime import QuarantineReason

    assert hasattr(QuarantineReason, "__members__")
    assert len(QuarantineReason.__members__) > 0


def test_enum_breach_severity():
    from agent_runtime import BreachSeverity

    assert hasattr(BreachSeverity, "__members__")
    assert len(BreachSeverity.__members__) > 0


def test_enum_event_type():
    from agent_runtime import EventType

    assert hasattr(EventType, "__members__")
    assert len(EventType.__members__) > 0


def test_enum_ledger_entry_type():
    from agent_runtime import LedgerEntryType

    assert hasattr(LedgerEntryType, "__members__")
    assert len(LedgerEntryType.__members__) > 0


def test_enum_saga_state():
    from agent_runtime import SagaState

    assert hasattr(SagaState, "__members__")
    assert len(SagaState.__members__) > 0


def test_enum_step_state():
    from agent_runtime import StepState

    assert hasattr(StepState, "__members__")
    assert len(StepState.__members__) > 0


def test_elevation_denial_reason_importable():
    from agent_runtime import ElevationDenialReason

    assert ElevationDenialReason is not None


def test_kill_result_importable():
    from agent_runtime import KillResult

    assert KillResult is not None


def test_exception_classes_are_exceptions():
    """Error / exception symbols should be subclasses of Exception."""
    from agent_runtime import (
        CausalViolationError,
        DeadlockError,
        LockContentionError,
        RateLimitExceeded,
        SagaTimeoutError,
        VFSPermissionError,
    )

    for exc_cls in [
        CausalViolationError,
        DeadlockError,
        LockContentionError,
        RateLimitExceeded,
        SagaTimeoutError,
        VFSPermissionError,
    ]:
        assert issubclass(exc_cls, Exception), f"{exc_cls.__name__} is not an Exception subclass"


def test_hypervisor_event_bus_instantiation():
    from agent_runtime import HypervisorEventBus

    bus = HypervisorEventBus()
    assert bus is not None


def test_session_config_instantiation():
    from agent_runtime import SessionConfig

    cfg = SessionConfig()
    assert cfg is not None


def test_causal_trace_id_instantiation():
    from agent_runtime import CausalTraceId

    tid = CausalTraceId()
    assert tid is not None
