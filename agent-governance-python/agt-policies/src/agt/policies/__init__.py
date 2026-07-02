# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Public AGT policy API (M3 surface).

This package exposes the AGT 5.0 user-facing policy primitives that host
code imports:

- :mod:`agt.policies.snapshot` builds the per-intervention-point snapshot
  documented in ``policy-engine/spec/agt/AGT-SNAPSHOT-1.0.md``. It
  replaces the v4 ``agent_os.integrations.base.ExecutionContext`` carrier;
  see :class:`SnapshotBuilder` for the long-lived host helper.
- :mod:`agt.policies.result` defines :class:`EvaluationResult`, the v5
  successor to ``agent_os.policies.decision.PolicyCheckResult``.
- :mod:`agt.policies.runtime` is the Python wrapper over the ACS Python
  SDK (:mod:`agent_control_specification`) that AGT host code calls.
- :mod:`agt.policies.bridge` translates a v4
  ``agent_os.integrations.base.GovernancePolicy`` into an AGT manifest
  so callers can ride the v4 dataclass into the v5 engine.
- :mod:`agt.policies.kernel` wires one ACS decision into the AGT kernel
  (trust, audit, rings) through :class:`KernelBridge`, a dependency
  injected fail closed governance gate.

The module is structured as a thin re-export layer so external callers
only need ``from agt.policies import ...``.
"""

from .kernel import (
    ActionClassifierLike,
    AuditEmissionResult,
    EmitEvent,
    GovernanceEventSpec,
    KernelBridge,
    KernelDecision,
    KernelOutcome,
    RingEnforcerLike,
    TrustTrackerLike,
)
from .result import EvaluationResult
from .snapshot import (
    SnapshotBuilder,
    agent_shutdown_snapshot,
    agent_startup_snapshot,
    input_snapshot,
    output_snapshot,
    post_model_call_snapshot,
    post_tool_call_snapshot,
    pre_model_call_snapshot,
    pre_tool_call_snapshot,
)

__all__ = [
    "ActionClassifierLike",
    "AuditEmissionResult",
    "EmitEvent",
    "EvaluationResult",
    "GovernanceEventSpec",
    "KernelBridge",
    "KernelDecision",
    "KernelOutcome",
    "RingEnforcerLike",
    "SnapshotBuilder",
    "TrustTrackerLike",
    "agent_shutdown_snapshot",
    "agent_startup_snapshot",
    "input_snapshot",
    "output_snapshot",
    "post_model_call_snapshot",
    "post_tool_call_snapshot",
    "pre_model_call_snapshot",
    "pre_tool_call_snapshot",
]
