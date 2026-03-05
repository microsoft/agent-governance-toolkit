# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust & Protocol Bridge (Layer 2)

Implements IATP for agent-to-agent trust handshakes.
Native A2A and MCP support with transparent protocol translation.
"""

from .bridge import TrustBridge, ProtocolBridge
from .handshake import TrustHandshake, HandshakeResult
from .capability import CapabilityScope, CapabilityGrant, CapabilityRegistry
from .cards import TrustedAgentCard, CardRegistry

__all__ = [
    "TrustBridge",
    "ProtocolBridge",
    "TrustHandshake",
    "HandshakeResult",
    "CapabilityScope",
    "CapabilityGrant",
    "CapabilityRegistry",
    "TrustedAgentCard",
    "CardRegistry",
]
