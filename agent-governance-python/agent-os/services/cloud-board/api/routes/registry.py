# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Registry Routes

API endpoints for agent registration and discovery.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

# Would import from modules.nexus in production
# For now, define inline models

router = APIRouter()


class AgentIdentityRequest(BaseModel):
    did: str
    verification_key: str
    owner_id: str
    display_name: Optional[str] = None
    contact: Optional[str] = None


class AgentCapabilitiesRequest(BaseModel):
    domains: list[str] = []
    tools: list[str] = []
    max_concurrency: int = 10
    sla_latency_ms: int = 5000
    reversibility: str = "partial"


class AgentPrivacyRequest(BaseModel):
    retention_policy: str = "ephemeral"
    pii_handling: str = "reject"
    training_consent: bool = False


class RegisterAgentRequest(BaseModel):
    identity: AgentIdentityRequest
    capabilities: AgentCapabilitiesRequest = None
    privacy: AgentPrivacyRequest = None
    signature: str


class RegisterAgentResponse(BaseModel):
    success: bool
    agent_did: str
    manifest_hash: str
    trust_score: int
    registered_at: str
    nexus_signature: Optional[str] = None


class AgentManifestResponse(BaseModel):
    identity: dict
    capabilities: dict
    privacy: dict
    verification_level: str
    trust_score: int
    registered_at: Optional[str] = None
    last_seen: Optional[str] = None


class VerifyPeerResponse(BaseModel):
    verified: bool
    peer_did: str
    trust_score: int
    trust_tier: str
    capabilities: list[str] = []
    privacy_policy: Optional[str] = None
    attestation_valid: bool = False
    rejection_reason: Optional[str] = None


# In-memory storage (would be database in production)
_agents: dict[str, dict] = {}


@router.post("", response_model=RegisterAgentResponse)
async def register_agent(request: RegisterAgentRequest):
    """
    Register a new agent on Nexus.
    
    This is the entry point for the viral loop - agents must register
    to communicate with other agents on the network.
    """
    agent_did = request.identity.did
    
    # Check if already registered
    if agent_did in _agents:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "AGENT_ALREADY_REGISTERED",
                "message": f"Agent {agent_did} is already registered",
            }
        )
    
    # Validate DID format
    if not agent_did.startswith("did:nexus:"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INVALID_DID",
                "message": "DID must start with 'did:nexus:'",
            }
        )
    
    # Calculate initial trust score
    trust_score = 400  # Base score for new registrations
    
    if request.capabilities:
        if request.capabilities.reversibility == "full":
            trust_score += 50
    
    if request.privacy:
        if request.privacy.retention_policy == "ephemeral":
            trust_score += 30
        if request.privacy.pii_handling == "reject":
            trust_score += 20
    
    # Store agent
    now = datetime.now(timezone.utc).isoformat()
    _agents[agent_did] = {
        "identity": request.identity.model_dump(),
        "capabilities": request.capabilities.model_dump() if request.capabilities else {},
        "privacy": request.privacy.model_dump() if request.privacy else {},
        "verification_level": "registered",
        "trust_score": trust_score,
        "registered_at": now,
        "last_seen": now,
    }
    
    # Generate manifest hash
    import hashlib
    import json
    manifest_hash = hashlib.sha256(
        json.dumps(_agents[agent_did], sort_keys=True).encode()
    ).hexdigest()
    
    return RegisterAgentResponse(
        success=True,
        agent_did=agent_did,
        manifest_hash=manifest_hash,
        trust_score=trust_score,
        registered_at=now,
        nexus_signature=f"nexus_sig_{manifest_hash[:32]}",
    )


@router.get("/{agent_did}", response_model=AgentManifestResponse)
async def get_agent(agent_did: str):
    """Get an agent's manifest by DID."""
    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "AGENT_NOT_FOUND",
                "message": f"Agent {agent_did} not found in registry",
            }
        )
    
    agent = _agents[agent_did]
    return AgentManifestResponse(**agent)


@router.put("/{agent_did}", response_model=RegisterAgentResponse)
async def update_agent(agent_did: str, request: RegisterAgentRequest):
    """Update an agent's manifest."""
    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "AGENT_NOT_FOUND",
                "message": f"Agent {agent_did} not found",
            }
        )
    
    if request.identity.did != agent_did:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "DID_MISMATCH",
                "message": "DID in request does not match URL",
            }
        )
    
    # Preserve registration time
    registered_at = _agents[agent_did]["registered_at"]
    
    # Update agent
    now = datetime.now(timezone.utc).isoformat()
    _agents[agent_did].update({
        "identity": request.identity.model_dump(),
        "capabilities": request.capabilities.model_dump() if request.capabilities else {},
        "privacy": request.privacy.model_dump() if request.privacy else {},
        "last_seen": now,
    })
    
    import hashlib
    import json
    manifest_hash = hashlib.sha256(
        json.dumps(_agents[agent_did], sort_keys=True).encode()
    ).hexdigest()
    
    return RegisterAgentResponse(
        success=True,
        agent_did=agent_did,
        manifest_hash=manifest_hash,
        trust_score=_agents[agent_did]["trust_score"],
        registered_at=registered_at,
        nexus_signature=f"nexus_sig_{manifest_hash[:32]}",
    )


@router.delete("/{agent_did}")
async def deregister_agent(agent_did: str):
    """Remove an agent from the registry."""
    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "AGENT_NOT_FOUND",
                "message": f"Agent {agent_did} not found",
            }
        )
    
    del _agents[agent_did]
    return {"success": True, "message": f"Agent {agent_did} deregistered"}


@router.get("/{agent_did}/verify", response_model=VerifyPeerResponse)
async def verify_peer(
    agent_did: str,
    min_score: int = Query(default=700, ge=0, le=1000),
    capabilities: Optional[str] = Query(default=None),
):
    """
    Verify a peer agent before IATP handshake.
    
    This is the core viral mechanism - returns error with registration
    URL for unregistered agents.
    """
    # Check if registered
    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "IATP_UNVERIFIED_PEER",
                "message": f"Agent '{agent_did}' not found in Nexus registry",
                "peer_id": agent_did,
                "registration_url": f"https://nexus.agent-os.dev/register?agent={agent_did}",
                "action_required": "Register the agent on Nexus to enable communication",
            }
        )
    
    agent = _agents[agent_did]
    trust_score = agent["trust_score"]
    
    # Check trust threshold
    if trust_score < min_score:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "IATP_INSUFFICIENT_TRUST",
                "message": f"Trust score {trust_score} below required {min_score}",
                "peer_did": agent_did,
                "current_score": trust_score,
                "required_score": min_score,
                "score_gap": min_score - trust_score,
                "improvement_url": f"https://nexus.agent-os.dev/reputation/{agent_did}",
            }
        )
    
    # Check capabilities if required
    required_caps = capabilities.split(",") if capabilities else []
    agent_caps = agent.get("capabilities", {}).get("domains", [])
    
    if required_caps:
        missing = set(required_caps) - set(agent_caps)
        if missing:
            return VerifyPeerResponse(
                verified=False,
                peer_did=agent_did,
                trust_score=trust_score,
                trust_tier=_get_tier(trust_score),
                capabilities=agent_caps,
                rejection_reason=f"Missing capabilities: {missing}",
            )
    
    # Update last seen
    agent["last_seen"] = datetime.now(timezone.utc).isoformat()
    
    return VerifyPeerResponse(
        verified=True,
        peer_did=agent_did,
        trust_score=trust_score,
        trust_tier=_get_tier(trust_score),
        capabilities=agent_caps,
        privacy_policy=agent.get("privacy", {}).get("retention_policy"),
        attestation_valid=True,  # Would check actual attestation
    )


@router.get("/discover", response_model=list[AgentManifestResponse])
async def discover_agents(
    capabilities: Optional[str] = Query(default=None),
    min_score: int = Query(default=500, ge=0, le=1000),
    privacy_policy: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Discover agents matching criteria."""
    results = []
    
    required_caps = capabilities.split(",") if capabilities else []
    
    for agent_did, agent in _agents.items():
        # Filter by score
        if agent["trust_score"] < min_score:
            continue
        
        # Filter by capabilities
        if required_caps:
            agent_caps = agent.get("capabilities", {}).get("domains", [])
            if not all(c in agent_caps for c in required_caps):
                continue
        
        # Filter by privacy policy
        if privacy_policy:
            if agent.get("privacy", {}).get("retention_policy") != privacy_policy:
                continue
        
        results.append(AgentManifestResponse(**agent))
        
        if len(results) >= limit:
            break
    
    # Sort by trust score
    results.sort(key=lambda a: a.trust_score, reverse=True)
    
    return results


def _get_tier(score: int) -> str:
    """Get trust tier from score."""
    if score >= 900:
        return "verified_partner"
    elif score >= 700:
        return "trusted"
    elif score >= 500:
        return "standard"
    elif score >= 300:
        return "probationary"
    else:
        return "untrusted"
