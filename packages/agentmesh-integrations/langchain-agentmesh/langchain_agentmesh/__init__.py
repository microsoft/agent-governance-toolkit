"""AgentMesh trust layer integration for LangChain.

This package provides cryptographic identity verification and trust-gated
tool execution for LangChain agents.
"""

from langchain_agentmesh.callbacks import TrustCallbackHandler
from langchain_agentmesh.identity import UserContext, VerificationIdentity, VerificationSignature
from langchain_agentmesh.tools import TrustedToolExecutor, TrustGatedTool
from langchain_agentmesh.trust import (
    AgentDirectory,
    Delegation,
    DelegationChain,
    TrustedAgentCard,
    TrustHandshake,
    TrustPolicy,
    TrustVerificationResult,
)

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
