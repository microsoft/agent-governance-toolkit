# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""CrewAI integration with AgentMesh trust layer.

Provides trust-aware wrappers for CrewAI agents and crews that enforce
AgentMesh trust verification before inter-agent delegation.

CrewAI is an optional dependency — all trust operations work without it.
"""

from .agent import (
    InMemoryTrustStore,
    InteractionRecord,
    TrustAwareAgent,
    TrustStore,
)
from .crew import TrustAwareCrew

__all__ = [
    "InMemoryTrustStore",
    "InteractionRecord",
    "TrustAwareAgent",
    "TrustAwareCrew",
    "TrustStore",
]
