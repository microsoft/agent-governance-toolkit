"""AgentMesh trust layer integration for LlamaIndex.

This package provides cryptographic identity verification and trust-gated
agent workflows for LlamaIndex.
"""

from llama_index.agent.agentmesh.identity import (
    VerificationIdentity,
    VerificationSignature,
)
from llama_index.agent.agentmesh.trust import (
    TrustedAgentCard,
    TrustHandshake,
    TrustVerificationResult,
    TrustPolicy,
    DelegationChain,
)
from llama_index.agent.agentmesh.worker import TrustedAgentWorker
from llama_index.agent.agentmesh.query_engine import (
    TrustGatedQueryEngine,
    DataAccessPolicy,
)

__all__ = [
    # Identity
    "VerificationIdentity",
    "VerificationSignature",
    # Trust
    "TrustedAgentCard",
    "TrustHandshake",
    "TrustVerificationResult",
    "TrustPolicy",
    "DelegationChain",
    # Agent
    "TrustedAgentWorker",
    # Query Engine
    "TrustGatedQueryEngine",
    "DataAccessPolicy",
]

__version__ = "3.2.2"