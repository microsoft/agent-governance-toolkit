# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""LangChain integration for AgentMesh trust layer.

Provides a callback handler for automatic trust verification before
tool execution, interaction recording, and trust-aware tool wrappers.

Features:
- Trust verification at tool and LLM call boundaries
- Interaction recording for trust score updates
- Trust-verified tool wrapper and subclass
- Graceful degradation when LangChain is not installed

Example::

    from agentmesh.integrations.langchain import AgentMeshTrustCallback

    callback = AgentMeshTrustCallback(
        agent_did="did:mesh:abc123",
        min_trust_score=500,
    )
    chain.invoke(input, config={"callbacks": [callback]})
"""

from .callback import (
    AgentMeshTrustCallback,
    InMemoryTrustStore,
    InteractionRecord,
    TrustStore,
)
from .tools import TrustVerifiedTool, trust_verified_tool

__all__ = [
    "AgentMeshTrustCallback",
    "InMemoryTrustStore",
    "InteractionRecord",
    "TrustStore",
    "TrustVerifiedTool",
    "trust_verified_tool",
]
