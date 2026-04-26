"""
APS-AgentMesh Integration — Structural authorization for AgentMesh agents.

The Agent Passport System (APS) provides cryptographic identity, scoped delegation
chains with monotonic narrowing, and signed policy decisions. This adapter makes
APS artifacts consumable by AGT's PolicyEngine as external trust signals.

Architecture:
  APS governs BETWEEN processes (cryptographic proof of authorization scope).
  AGT governs INSIDE the process (policy evaluation, trust scoring, execution rings).
  Together: APS structural authorization is a hard gate, AGT behavioral trust is a soft signal.

Provides:
  - APSPolicyGate: Injects APS PolicyDecision into AGT evaluation context
  - APSTrustBridge: Maps APS passport grades (0-3) to AGT trust scores (0-1000)
  - APSScopeVerifier: Validates APS delegation scope chains
  - verify_aps_signature: Ed25519 signature verification for APS artifacts
"""

from .adapter import (
    APSPolicyGate,
    APSTrustBridge,
    APSScopeVerifier,
    aps_context,
    verify_aps_signature,
    GRADE_TO_TRUST_SCORE,
)

__all__ = [
    "APSPolicyGate",
    "APSTrustBridge",
    "APSScopeVerifier",
    "aps_context",
    "verify_aps_signature",
    "GRADE_TO_TRUST_SCORE",
]
