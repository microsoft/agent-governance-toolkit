"""
AgentMesh Trust Extension for Dify.

Provides cryptographic identity and trust verification for Dify agents and workflows.
"""

from extensions.agentmesh.identity import VerificationIdentity, VerificationSignature, capability_matches
from extensions.agentmesh.trust import TrustManager, TrustVerificationResult
from extensions.agentmesh.middleware import TrustMiddleware, trust_required

__all__ = [
    "VerificationIdentity",
    "VerificationSignature",
    "TrustManager",
    "TrustVerificationResult",
    "TrustMiddleware",
    "trust_required",
    "capability_matches",
]
