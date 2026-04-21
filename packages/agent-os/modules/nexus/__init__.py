# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus: The Agent Trust Exchange

A viral, cloud-based registry and communication board that uses the Agent OS
kernel to enforce trust. Serves as a neutral ground where agents can discover
each other, negotiate contracts via IATP, and settle rewards for successful tasks.

The "Visa Network" for AI Agents.
"""

from .client import NexusClient
from .registry import AgentRegistry
from .reputation import ReputationEngine, TrustScore
from .escrow import ProofOfOutcome, EscrowManager
from .arbiter import Arbiter, DisputeResolution
from .dmz import DMZProtocol, DataHandlingPolicy
from .exceptions import (
    NexusError,
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
    EscrowError,
    DisputeError,
)

__version__ = "3.1.1"
__all__ = [
    # Client
    "NexusClient",
    # Registry
    "AgentRegistry",
    # Reputation
    "ReputationEngine",
    "TrustScore",
    # Escrow
    "ProofOfOutcome",
    "EscrowManager",
    # Arbiter
    "Arbiter",
    "DisputeResolution",
    # DMZ
    "DMZProtocol",
    "DataHandlingPolicy",
    # Exceptions
    "NexusError",
    "IATPUnverifiedPeerException",
    "IATPInsufficientTrustException",
    "EscrowError",
    "DisputeError",
]
