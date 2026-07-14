# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Public AGT native policy API."""

from typing import TYPE_CHECKING

from .manifest import (
    AdapterManifestContract,
    AgtManifest,
    ManifestCompatibilityError,
    ManifestProvenance,
)
from .result import (
    EvidenceResult,
    PolicyAuditRecord,
    PolicyEvaluation,
    TransformResult,
)
from .session import AdapterRuntimeSession
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

if TYPE_CHECKING:
    from .runtime import AgtRuntime, ApprovalDecision


def __getattr__(name: str):
    if name in {"AgtRuntime", "ApprovalDecision"}:
        from .runtime import AgtRuntime, ApprovalDecision

        runtime_exports = {
            "AgtRuntime": AgtRuntime,
            "ApprovalDecision": ApprovalDecision,
        }
        globals().update(runtime_exports)
        return runtime_exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AdapterManifestContract",
    "AdapterRuntimeSession",
    "AgtRuntime",
    "AgtManifest",
    "EvidenceResult",
    "ManifestCompatibilityError",
    "ManifestProvenance",
    "PolicyAuditRecord",
    "PolicyEvaluation",
    "ApprovalDecision",
    "SnapshotBuilder",
    "TransformResult",
    "agent_shutdown_snapshot",
    "agent_startup_snapshot",
    "input_snapshot",
    "output_snapshot",
    "post_model_call_snapshot",
    "post_tool_call_snapshot",
    "pre_model_call_snapshot",
    "pre_tool_call_snapshot",
]
