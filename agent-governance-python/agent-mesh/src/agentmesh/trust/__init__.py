# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust & Protocol Bridge (Layer 2)

Implements IATP for agent-to-agent trust handshakes.
Native A2A and MCP support with transparent protocol translation.
"""

from .bridge import ProtocolBridge, TrustBridge
from .capability import CapabilityGrant, CapabilityRegistry, CapabilityScope
from .cards import CardRegistry, TrustedAgentCard
from .endorsement import Endorsement, EndorsementRegistry, EndorsementType
from .handshake import HandshakeResult, TrustHandshake
from .levels import trust_level_for_score

__all__ = [
    "TrustBridge",
    "ProtocolBridge",
    "Endorsement",
    "EndorsementRegistry",
    "EndorsementType",
    "TrustHandshake",
    "HandshakeResult",
    "CapabilityScope",
    "CapabilityGrant",
    "CapabilityRegistry",
    "TrustedAgentCard",
    "CardRegistry",
    "trust_level_for_score",
]
