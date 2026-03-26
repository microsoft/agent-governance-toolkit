# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy Conflict Resolution — backward-compatibility shim.

Attempts to import the canonical implementation from
``agent_os.policies.conflict_resolution``.  When ``agent_os`` is not
installed the standalone fallback in
``agentmesh.governance._conflict_resolution_impl`` is re-exported so
that ``agentmesh`` continues to work without requiring the optional
``agent-os`` package.

.. deprecated::
    Import from ``agent_os.policies`` instead of
    ``agentmesh.governance.conflict_resolution``.
"""

from __future__ import annotations

try:
    from agent_os.policies.conflict_resolution import (  # noqa: F401
        CandidateDecision,
        ConflictResolutionStrategy,
        PolicyConflictResolver,
        PolicyScope,
        ResolutionResult,
    )
except ImportError:
    from agentmesh.governance._conflict_resolution_impl import (  # noqa: F401
        CandidateDecision,
        ConflictResolutionStrategy,
        PolicyConflictResolver,
        PolicyScope,
        ResolutionResult,
    )

__all__ = [
    "ConflictResolutionStrategy",
    "PolicyScope",
    "CandidateDecision",
    "ResolutionResult",
    "PolicyConflictResolver",
]
