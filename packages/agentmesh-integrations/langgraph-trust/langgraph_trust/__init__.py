"""langgraph-trust: Trust-gated checkpoint nodes for LangGraph.

Provides TrustGate, PolicyCheckpoint, and trust-aware edge conditions
for building governed multi-agent graphs with cryptographic identity
and dynamic trust scoring.
"""

from langgraph_trust.gate import TrustGate
from langgraph_trust.policy import PolicyCheckpoint
from langgraph_trust.edges import trust_edge, trust_router
from langgraph_trust.state import TrustState, TrustVerdict
from langgraph_trust.identity import AgentIdentityManager

__all__ = [
    "TrustGate",
    "PolicyCheckpoint",
    "trust_edge",
    "trust_router",
    "TrustState",
    "TrustVerdict",
    "AgentIdentityManager",
]

__version__ = "0.1.0"
