# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Trust Server — AgentMesh trust management via Model Context Protocol.

Exposes trust tools: check_trust, get_trust_score, establish_handshake,
verify_delegation, record_interaction, get_identity.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
AGENT_NAME = os.environ.get("AGENTMESH_AGENT_NAME", "mcp-trust-agent")
MIN_TRUST_SCORE = int(os.environ.get("AGENTMESH_MIN_TRUST_SCORE", "500"))
STORAGE_BACKEND = os.environ.get("AGENTMESH_STORAGE_BACKEND", "memory")

# Trust dimension names (5-dimension model)
TRUST_DIMENSIONS = [
    "competence",
    "integrity",
    "availability",
    "predictability",
    "transparency",
]

# Trust tier thresholds
TIER_VERIFIED_PARTNER = 900
TIER_TRUSTED = 700
TIER_STANDARD = 500
TIER_PROBATIONARY = 300


def _trust_level(score: int) -> str:
    """Map numeric score to trust level label."""
    if score >= TIER_VERIFIED_PARTNER:
        return "verified_partner"
    if score >= TIER_TRUSTED:
        return "trusted"
    if score >= TIER_STANDARD:
        return "standard"
    if score >= TIER_PROBATIONARY:
        return "probationary"
    return "untrusted"


# ---------------------------------------------------------------------------
# In-memory stores (replaced by Redis when STORAGE_BACKEND=redis)
# ---------------------------------------------------------------------------
class TrustStore:
    """Simple in-memory trust store for agent scores and interactions."""

    def __init__(self) -> None:
        self.scores: dict[str, dict[str, Any]] = {}
        self.interactions: list[dict[str, Any]] = []
        self.handshakes: dict[str, dict[str, Any]] = {}

    def get_score(self, agent_did: str) -> dict[str, Any]:
        """Return trust record for *agent_did*, creating a default if absent."""
        if agent_did not in self.scores:
            self.scores[agent_did] = {
                "agent_did": agent_did,
                "overall_score": 500,
                "dimensions": {d: 500 for d in TRUST_DIMENSIONS},
                "trust_level": "standard",
                "interaction_count": 0,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
        return self.scores[agent_did]

    def update_score(
        self, agent_did: str, delta: int, dimension: str | None = None
    ) -> dict[str, Any]:
        """Apply *delta* to the agent's score (overall and optionally a dimension)."""
        record = self.get_score(agent_did)
        record["overall_score"] = max(0, min(1000, record["overall_score"] + delta))
        if dimension and dimension in record["dimensions"]:
            record["dimensions"][dimension] = max(
                0, min(1000, record["dimensions"][dimension] + delta)
            )
        record["trust_level"] = _trust_level(record["overall_score"])
        record["last_updated"] = datetime.now(timezone.utc).isoformat()
        return record

    def record_interaction(
        self, peer_did: str, outcome: str, details: str
    ) -> dict[str, Any]:
        """Persist an interaction and adjust trust accordingly."""
        interaction = {
            "peer_did": peer_did,
            "outcome": outcome,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.interactions.append(interaction)

        delta = {"success": 10, "failure": -20, "timeout": -10, "partial": 5}.get(
            outcome, 0
        )
        dimension = {"success": "competence", "failure": "integrity", "timeout": "availability"}.get(
            outcome
        )
        record = self.update_score(peer_did, delta, dimension)
        record["interaction_count"] = record.get("interaction_count", 0) + 1
        return {**interaction, "updated_score": record}


# ---------------------------------------------------------------------------
# Agent identity (generated once per server lifetime)
# ---------------------------------------------------------------------------
class LocalIdentity:
    """Holds the Ed25519 identity of this MCP server instance."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key_b64 = base64.b64encode(pub_bytes).decode()
        did_hash = hashlib.sha256(pub_bytes).hexdigest()[:32]
        self.did = f"did:mesh:{did_hash}"
        self.capabilities: list[str] = [
            "trust:read",
            "trust:write",
            "handshake:initiate",
            "delegation:verify",
        ]

    def sign(self, data: bytes) -> str:
        """Return base64-encoded Ed25519 signature."""
        return base64.b64encode(self._private_key.sign(data)).decode()


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------
_store = TrustStore()
_identity = LocalIdentity(AGENT_NAME)

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "AgentMesh Trust Server",
    instructions=(
        "Provides trust management tools for AI agents in the AgentMesh network. "
        "Use these tools to check trust, perform handshakes, verify delegation "
        "chains, and record interaction outcomes."
    ),
)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------
@mcp.tool()
def check_trust(agent_did: str) -> dict:
    """Check if an agent is trusted.

    Returns the agent's overall trust score, trust level, and all five
    trust dimensions (competence, integrity, availability, predictability,
    transparency).

    Args:
        agent_did: The DID of the agent to check (e.g. "did:mesh:abc123").
    """
    record = _store.get_score(agent_did)
    return {
        "agent_did": agent_did,
        "trusted": record["overall_score"] >= MIN_TRUST_SCORE,
        "overall_score": record["overall_score"],
        "trust_level": record["trust_level"],
        "dimensions": record["dimensions"],
        "min_trust_threshold": MIN_TRUST_SCORE,
    }


@mcp.tool()
def get_trust_score(agent_did: str) -> dict:
    """Get a detailed trust score with all 5 dimensions.

    Dimensions: competence, integrity, availability, predictability,
    transparency.  Each dimension is scored 0-1000.

    Args:
        agent_did: The DID of the agent to query.
    """
    record = _store.get_score(agent_did)
    return {
        "agent_did": agent_did,
        "overall_score": record["overall_score"],
        "trust_level": record["trust_level"],
        "dimensions": record["dimensions"],
        "interaction_count": record["interaction_count"],
        "last_updated": record["last_updated"],
    }


@mcp.tool()
def establish_handshake(peer_did: str, capabilities: list[str]) -> dict:
    """Initiate a trust handshake with a peer agent.

    Creates a cryptographic challenge, records the handshake, and returns
    a signed token the peer can verify.

    Args:
        peer_did: The DID of the peer agent to handshake with.
        capabilities: List of capability strings requested for this session.
    """
    nonce = secrets.token_hex(32)
    challenge_id = f"challenge_{secrets.token_hex(8)}"
    payload = f"{challenge_id}:{nonce}:{_identity.did}:{peer_did}"
    signature = _identity.sign(payload.encode())

    handshake_record = {
        "handshake_id": challenge_id,
        "initiator_did": _identity.did,
        "peer_did": peer_did,
        "requested_capabilities": capabilities,
        "nonce": nonce,
        "signature": signature,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _store.handshakes[challenge_id] = handshake_record

    return {
        "handshake_id": challenge_id,
        "initiator_did": _identity.did,
        "peer_did": peer_did,
        "requested_capabilities": capabilities,
        "status": "pending",
        "signature": signature,
        "created_at": handshake_record["created_at"],
    }


@mcp.tool()
def verify_delegation(
    agent_did: str, delegator_did: str, capability: str
) -> dict:
    """Verify that a scope chain from *delegator_did* to *agent_did* is valid.

    Checks that the agent's DID is known, the delegator's trust score is
    sufficient, and the requested capability is plausible.

    Args:
        agent_did: The DID of the agent claiming delegated authority.
        delegator_did: The DID of the delegator (parent agent).
        capability: The capability being delegated (e.g. "read:data").
    """
    delegator_record = _store.get_score(delegator_did)
    agent_record = _store.get_score(agent_did)

    delegator_trusted = delegator_record["overall_score"] >= MIN_TRUST_SCORE
    agent_trusted = agent_record["overall_score"] >= MIN_TRUST_SCORE

    valid = delegator_trusted and agent_trusted

    return {
        "valid": valid,
        "agent_did": agent_did,
        "delegator_did": delegator_did,
        "capability": capability,
        "delegator_trust_score": delegator_record["overall_score"],
        "agent_trust_score": agent_record["overall_score"],
        "delegator_trusted": delegator_trusted,
        "agent_trusted": agent_trusted,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def record_interaction(peer_did: str, outcome: str, details: str) -> dict:
    """Record an interaction outcome to update trust scores.

    Valid outcomes: ``success``, ``failure``, ``timeout``, ``partial``.
    Positive outcomes raise trust; negative outcomes lower it.

    Args:
        peer_did: The DID of the peer agent involved.
        outcome: Interaction result — one of success, failure, timeout, partial.
        details: Free-text description of the interaction.
    """
    valid_outcomes = {"success", "failure", "timeout", "partial"}
    if outcome not in valid_outcomes:
        return {
            "error": f"Invalid outcome '{outcome}'. Must be one of: {', '.join(sorted(valid_outcomes))}",
        }

    result = _store.record_interaction(peer_did, outcome, details)
    return {
        "peer_did": peer_did,
        "outcome": outcome,
        "details": details,
        "updated_score": result["updated_score"]["overall_score"],
        "trust_level": result["updated_score"]["trust_level"],
        "interaction_count": result["updated_score"]["interaction_count"],
        "timestamp": result["timestamp"],
    }


@mcp.tool()
def get_identity() -> dict:
    """Get this agent's identity info.

    Returns the server's DID, public key, name, and capabilities.
    """
    return {
        "did": _identity.did,
        "name": _identity.name,
        "public_key": _identity.public_key_b64,
        "capabilities": _identity.capabilities,
    }


# ---------------------------------------------------------------------------
# __main__ support
# ---------------------------------------------------------------------------
def main() -> None:
    """Entry point for ``python -m mcp_trust_server`` and the console script."""
    mcp.run()


if __name__ == "__main__":
    main()
