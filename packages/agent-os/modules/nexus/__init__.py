# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus: The Agent Trust Exchange

A viral, cloud-based registry and communication board that uses the Agent OS
kernel to enforce trust. Serves as a neutral ground where agents can discover
each other, negotiate contracts via IATP, and settle rewards for successful tasks.

The "Visa Network" for AI Agents.
"""

from .arbiter import Arbiter, DisputeResolution
from .client import NexusClient
from .dmz import DataHandlingPolicy, DMZProtocol
from .escrow import EscrowManager, ProofOfOutcome
from .exceptions import (
    DisputeError,
    EscrowError,
    IATPInsufficientTrustException,
    IATPUnverifiedPeerException,
    NexusError,
)
from .registry import AgentRegistry
from .reputation import ReputationEngine, TrustScore

__version__ = "0.1.0"
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
