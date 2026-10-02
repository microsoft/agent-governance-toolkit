# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh conflict resolution public exports."""

from __future__ import annotations

from agentmesh.governance._conflict_resolution_impl import (  # noqa: F401
    VALID_SCOPES,
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyScope,
    ResolutionResult,
)

__all__ = [
    "ConflictResolutionStrategy",
    "PolicyScope",
    "VALID_SCOPES",
    "CandidateDecision",
    "ResolutionResult",
    "PolicyConflictResolver",
]
