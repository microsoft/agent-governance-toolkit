# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AI Card Integration for AgentMesh
=================================

Implements the AI Card standard (https://github.com/agent-card/ai-card)
for cross-protocol agent identity and discovery.

AI Card provides a common format for:
- Agent metadata (name, description, version)
- Identity (DIDs, public keys)
- Verifiable metadata (trust scores, capability proofs, delegation)
- Protocol services (A2A skills, MCP tools, etc.)
- Static discovery via /.well-known/ai-card.json

This adapter bridges AgentMesh's CMVK identity primitives to the
AI Card format, enabling cross-protocol trust verification.

Example:
    >>> from agentmesh.identity import AgentIdentity
    >>> from agentmesh.integrations.ai_card import AICard
    >>>
    >>> identity = AgentIdentity.create(
    ...     name="sql-agent",
    ...     sponsor="human@example.com",
    ...     capabilities=["execute:sql", "read:database"],
    ... )
    >>> card = AICard.from_identity(identity)
    >>> card.to_json()  # Serve at /.well-known/ai-card.json
"""

from .schema import (
    AICard,
    AICardIdentity,
    AICardService,
    AICardVerifiable,
    CapabilityAttestation,
    DelegationRecord,
)
from .discovery import AICardDiscovery

__all__ = [
    "AICard",
    "AICardIdentity",
    "AICardService",
    "AICardVerifiable",
    "CapabilityAttestation",
    "DelegationRecord",
    "AICardDiscovery",
]
