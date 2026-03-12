# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy Conflict Resolution — backward-compatibility shim.

The canonical implementation has moved to `agent_os.policies.conflict_resolution`.
This module re-exports all public symbols so existing imports continue to work.

.. deprecated::
    Import from `agent_os.policies` instead of
    `agentmesh.governance.conflict_resolution`.
"""

from agent_os.policies.conflict_resolution import (  # noqa: F401
    ConflictResolutionStrategy,
    PolicyScope,
    CandidateDecision,
    ResolutionResult,
    PolicyConflictResolver,
)

__all__ = [
    "ConflictResolutionStrategy",
    "PolicyScope",
    "CandidateDecision",
    "ResolutionResult",
    "PolicyConflictResolver",
]