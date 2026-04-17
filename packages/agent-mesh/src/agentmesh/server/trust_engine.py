# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Engine Server

Validates agent identity and issues trust tokens via IATP handshakes.
Wraps agentmesh.trust (TrustHandshake, TrustBridge, CapabilityRegistry).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

from agentmesh.identity.agent_id import AgentIdentity, AgentDID, IdentityRegistry
from agentmesh.trust.handshake import TrustHandshake, HandshakeChallenge, HandshakeResponse
from agentmesh.trust.capability import CapabilityRegistry, CapabilityGrant
from agentmesh.server import create_base_app, run_server

logger = logging.getLogger(__name__)

app = create_base_app(
    "trust-engine",
    "Validates agent identity and issues trust tokens via IATP handshakes.",
)

# Shared state — initialised at startup
registry = IdentityRegistry()
capability_registry = CapabilityRegistry()
# Map challenge_id → (TrustHandshake, HandshakeChallenge)
_pending_challenges: dict[str, tuple[TrustHandshake, HandshakeChallenge]] = {}


# ── Request / Response models ────────────────────────────────────────


class ChallengeRequest(BaseModel):
    agent_did: str = Field(..., description="DID of the agent requesting a challenge (did:mesh:...)")


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_in_seconds: int


class VerifyRequest(BaseModel):
    challenge_id: str = Field(..., description="ID of the challenge to verify against")
    agent_did: str
    response_nonce: str
    signature: str = Field(..., description="Hex-encoded Ed25519 signature of the nonce")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key")
    capabilities: list[str] = Field(default_factory=list)
    trust_score: int = Field(default=0, ge=0, le=1000)


class VerifyResponse(BaseModel):
    verified: bool
    trust_score: int = 0
    trust_level: str = ""
    peer_did: str = ""
    rejection_reason: Optional[str] = None


class RegisterAgentRequest(BaseModel):
    name: str = Field(..., description="Human-readable agent name")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key")
    sponsor_email: str = Field(..., description="Human sponsor email")
    description: Optional[str] = None
    did_unique_id: Optional[str] = Field(None, description="Custom unique ID; auto-generated if omitted")


class GrantCapabilityRequest(BaseModel):
    capability: str = Field(..., description="Capability string (e.g., 'read:data')")
    to_agent: str = Field(..., description="DID of grantee")
    from_agent: str = Field(..., description="DID of grantor")


# ── Endpoints ────────────────────────────────────────────────────────


@app.post("/api/v1/agents/register", tags=["identity"])
async def register_agent(req: RegisterAgentRequest) -> dict[str, str]:
    """Register an agent identity with its public key."""
    agent_did = AgentDID.generate(req.name)
    identity = AgentIdentity(
        did=agent_did,
        name=req.name,
        description=req.description or "",
        public_key=req.public_key,
        verification_key_id=f"{agent_did}#key-1",
        sponsor_email=req.sponsor_email,
    )
    registry.register(identity)
    return {"status": "registered", "agent_did": str(agent_did)}


@app.post("/api/v1/handshake/challenge", tags=["trust"], response_model=ChallengeResponse)
async def issue_challenge(req: ChallengeRequest) -> ChallengeResponse:
    """Issue a cryptographic challenge for an agent to prove identity."""
    identity = registry.get(req.agent_did)
    if identity is None:
        raise HTTPException(404, f"Agent {req.agent_did} not registered")

    handshake = TrustHandshake(
        agent_did=req.agent_did,
        identity=identity,
        registry=registry,
    )
    challenge = HandshakeChallenge.generate()
    _pending_challenges[challenge.challenge_id] = (handshake, challenge)

    return ChallengeResponse(
        challenge_id=challenge.challenge_id,
        nonce=challenge.nonce,
        expires_in_seconds=challenge.expires_in_seconds,
    )


@app.post("/api/v1/handshake/verify", tags=["trust"], response_model=VerifyResponse)
async def verify_handshake(req: VerifyRequest) -> VerifyResponse:
    """Verify a signed challenge response from an agent."""
    entry = _pending_challenges.pop(req.challenge_id, None)
    if entry is None:
        raise HTTPException(404, "Challenge not found or expired")

    handshake, challenge = entry

    if challenge.is_expired():
        return VerifyResponse(verified=False, rejection_reason="Challenge expired")

    try:
        response = HandshakeResponse(
            challenge_id=req.challenge_id,
            response_nonce=req.response_nonce,
            agent_did=req.agent_did,
            signature=req.signature,
            public_key=req.public_key,
            capabilities=req.capabilities,
            trust_score=req.trust_score,
        )
        result = await handshake._verify_response(
            response=response,
            challenge=challenge,
            required_score=0,
            required_capabilities=None,
        )
        return VerifyResponse(
            verified=result.get("verified", False),
            trust_score=result.get("trust_score", 0),
            trust_level=result.get("trust_level", ""),
            peer_did=result.get("peer_did", req.agent_did),
        )
    except Exception as exc:
        logger.warning("Handshake verification failed: %s", exc)
        return VerifyResponse(verified=False, rejection_reason=str(exc))


@app.post("/api/v1/capabilities/grant", tags=["capabilities"])
async def grant_capability(req: GrantCapabilityRequest) -> dict[str, Any]:
    """Grant a capability to an agent."""
    grant = capability_registry.grant(
        capability=req.capability,
        to_agent=req.to_agent,
        from_agent=req.from_agent,
    )
    return {"status": "granted", "grant_id": grant.grant_id, "capability": req.capability}


@app.get("/api/v1/capabilities/{agent_did:path}", tags=["capabilities"])
async def list_capabilities(agent_did: str) -> dict[str, Any]:
    """List capabilities granted to an agent."""
    scope = capability_registry.get_scope(agent_did)
    return {
        "agent_did": agent_did,
        "capabilities": [
            {"capability": g.capability, "active": g.is_valid()}
            for g in scope.grants
        ],
    }


def main() -> None:
    run_server(app, default_port=8443)


if __name__ == "__main__":
    main()
