# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
ScopeBlind protect-mcp integration for AgentMesh.

Bridges protect-mcp's Cedar policy enforcement and Ed25519 decision receipts
into AGT's PolicyEngine as verifiable trust signals.

protect-mcp provides runtime enforcement (evaluate Cedar policies on every
MCP tool call). AGT provides governance infrastructure (trust scoring,
identity, SLOs). This adapter connects them:

- CedarPolicyBridge: maps Cedar allow/deny decisions into AGT evaluate()
- ReceiptVerifier: validates Ed25519-signed decision receipts offline
- SpendingGate: enforces issuer-blind spending authority checks
- scopeblind_context(): builds AGT-compatible context from protect-mcp artifacts
"""

from .adapter import (
    CedarDecision,
    CedarPolicyBridge,
    ReceiptVerifier,
    SpendingGate,
    scopeblind_context,
)

__all__ = [
    "CedarDecision",
    "CedarPolicyBridge",
    "ReceiptVerifier",
    "SpendingGate",
    "scopeblind_context",
]
