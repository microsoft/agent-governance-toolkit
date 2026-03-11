"""AgentMesh trust layer integration for LangChain.

This package provides cryptographic identity verification and trust-gated
tool execution for LangChain agents.
"""

from langchain_agentmesh.identity import VerificationIdentity, VerificationSignature, UserContext
from langchain_agentmesh.trust import (
    TrustedAgentCard,
    TrustHandshake,
    TrustVerificationResult,
    TrustPolicy,
    DelegationChain,
    Delegation,
    AgentDirectory,
)
from langchain_agentmesh.tools import TrustGatedTool, TrustedToolExecutor
from langchain_agentmesh.callbacks import TrustCallbackHandler

__all__ = [
    # Identity
    "VerificationIdentity",
    "VerificationSignature",
    "UserContext",
    # Trust
    "TrustedAgentCard",
    "TrustHandshake",
    "TrustVerificationResult",
    "TrustPolicy",
    "DelegationChain",
    "Delegation",
    "AgentDirectory",
    # Tools
    "TrustGatedTool",
    "TrustedToolExecutor",
    # Callbacks
    "TrustCallbackHandler",
]

__version__ = "0.1.0"
