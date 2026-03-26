# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
langchain-agentmesh: Trust layer integration for LangChain.

Provides cryptographic identity and trust verification for AI agents.
"""

from langchain_agentmesh.callbacks import TrustCallbackHandler
from langchain_agentmesh.identity import CMVKIdentity, CMVKSignature
from langchain_agentmesh.tools import TrustedToolExecutor, TrustGatedTool
from langchain_agentmesh.trust import TrustHandshake, TrustVerificationResult

__version__ = "0.1.0"

__all__ = [
    # Identity
    "CMVKIdentity",
    "CMVKSignature",
    # Trust
    "TrustHandshake",
    "TrustVerificationResult",
    # Tools
    "TrustGatedTool",
    "TrustedToolExecutor",
    # Callbacks
    "TrustCallbackHandler",
]
