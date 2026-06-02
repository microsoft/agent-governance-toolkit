# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Registry Routes

API endpoints for agent registration and discovery.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256 as _sha256
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from ..auth import AGENT_AUTH, BEARER_AUTH, AuthPrincipal, authorize_agent, try_authenticate

# Would import from modules.nexus in production
# For now, define inline models

router = APIRouter()

REPLAY_WINDOW = timedelta(minutes=5)


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
    proof: str  # Ed25519 signature over (verification_key || proof_timestamp)
    proof_timestamp: str  # ISO 8601 UTC timestamp


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

    Requires proof-of-possession: the caller must sign
    (verification_key || proof_timestamp) with the private key
    corresponding to the submitted verification_key.
    """
    import base64
    import json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    # Decode and validate the verification key
    try:
        key_bytes = base64.urlsafe_b64decode(request.identity.verification_key + "==")
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"error": "INVALID_KEY", "message": "Invalid verification_key encoding"},
        ) from None
    if len(key_bytes) != 32:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INVALID_KEY",
                "message": "verification_key must be 32 bytes (Ed25519)",
            },
        )

    # Verify proof timestamp is within replay window
    try:
        ts = datetime.fromisoformat(request.proof_timestamp)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail={"error": "INVALID_TIMESTAMP", "message": "Invalid proof_timestamp format"},
        ) from None
    if ts.tzinfo is None:
        # A naive timestamp is ambiguous (which timezone?) and previously caused
        # an uncaught ``TypeError`` when subtracted from the aware UTC ``now``,
        # producing a 500 on every unauth call. Require explicit UTC offset.
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INVALID_TIMESTAMP",
                "message": "proof_timestamp must include a timezone offset (e.g. '+00:00' or 'Z')",
            },
        )
    now = datetime.now(timezone.utc)
    if abs((now - ts).total_seconds()) > REPLAY_WINDOW.total_seconds():
        raise HTTPException(
            status_code=401,
            detail={"error": "EXPIRED_PROOF", "message": "Proof timestamp outside replay window"},
        )

    # Verify proof-of-possession
    try:
        proof_bytes = base64.urlsafe_b64decode(request.proof + "==")
        message = request.identity.verification_key.encode() + request.proof_timestamp.encode()
        VerifyKey(key_bytes).verify(message, proof_bytes)
    except BadSignatureError:
        raise HTTPException(
            status_code=401,
            detail={"error": "INVALID_PROOF", "message": "Invalid proof-of-possession"},
        ) from None
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"error": "MALFORMED_PROOF", "message": "Malformed proof"},
        ) from None

    # Derive DID deterministically from full public key hash. We use the full
    # 256-bit (64 hex char) SHA-256 to avoid 64-bit collision resistance on a
    # truncated hash — keys are public, so collision search is feasible at
    # ~2^64 with 128-bit truncation.
    key_hash = _sha256(key_bytes).hexdigest()
    agent_did = f"did:nexus:{key_hash}"
    if request.identity.did != agent_did:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "DID_MISMATCH",
                "message": "Submitted DID does not match verification_key",
            },
        )

    # Check if already registered
    if agent_did in _agents:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "AGENT_ALREADY_REGISTERED",
                "message": f"Agent {agent_did} is already registered",
            },
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
    manifest_hash = _sha256(
        json.dumps(_agents[agent_did], sort_keys=True).encode()).hexdigest()

    return RegisterAgentResponse(
        success=True,
        agent_did=agent_did,
        manifest_hash=manifest_hash,
        trust_score=trust_score,
        registered_at=now,
        nexus_signature=f"nexus_sig_{manifest_hash[:32]}",
    )


@router.get("/discover", response_model=list[AgentManifestResponse])
async def discover_agents(
    capabilities: Optional[str] = Query(default=None),
    min_score: int = Query(default=500, ge=0, le=1000),
    privacy_policy: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    credentials: HTTPAuthorizationCredentials | None = BEARER_AUTH,
):
    """Discover agents matching criteria.

    Owner and contact identity fields are redacted for unauthenticated
    callers.
    """
    results = []
    principal = try_authenticate(credentials)

    required_caps = capabilities.split(",") if capabilities else []

    for _agent_did, agent in _agents.items():
        if agent["trust_score"] < min_score:
            continue

        if required_caps:
            agent_caps = agent.get("capabilities", {}).get("domains", [])
            if not all(c in agent_caps for c in required_caps):
                continue

        if privacy_policy:
            if agent.get("privacy", {}).get("retention_policy") != privacy_policy:
                continue

        results.append(AgentManifestResponse(**_view_manifest(agent, principal)))

        if len(results) >= limit:
            break

    results.sort(key=lambda a: a.trust_score, reverse=True)

    return results


@router.get("/{agent_did}", response_model=AgentManifestResponse)
async def get_agent(
    agent_did: str,
    credentials: HTTPAuthorizationCredentials | None = BEARER_AUTH,
):
    """Get an agent's manifest by DID.

    Unauthenticated callers receive a sanitized manifest with owner/contact
    PII redacted. Authenticated callers see the full manifest.
    """
    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "AGENT_NOT_FOUND",
                "message": f"Agent {agent_did} not found in registry",
            },
        )

    principal = try_authenticate(credentials)
    return AgentManifestResponse(**_view_manifest(_agents[agent_did], principal))


@router.put("/{agent_did}", response_model=RegisterAgentResponse)
async def update_agent(
    agent_did: str,
    request: RegisterAgentRequest,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Update an agent's manifest. Requires scoped auth and proof-of-possession."""
    import base64
    import json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "AGENT_NOT_FOUND",
                "message": f"Agent {agent_did} not found",
            },
        )
    authorize_agent(agent_did, principal)

    # Verify proof-of-possession
    try:
        key_bytes = base64.urlsafe_b64decode(request.identity.verification_key + "==")
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"error": "INVALID_KEY", "message": "Invalid verification_key encoding"},
        ) from None
    if len(key_bytes) != 32:
        raise HTTPException(
            status_code=400,
            detail={"error": "INVALID_KEY", "message": "verification_key must be 32 bytes"},
        )

    try:
        ts = datetime.fromisoformat(request.proof_timestamp)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail={"error": "INVALID_TIMESTAMP", "message": "Invalid proof_timestamp"},
        ) from None
    if ts.tzinfo is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INVALID_TIMESTAMP",
                "message": "proof_timestamp must include a timezone offset (e.g. '+00:00' or 'Z')",
            },
        )
    now = datetime.now(timezone.utc)
    if abs((now - ts).total_seconds()) > REPLAY_WINDOW.total_seconds():
        raise HTTPException(
            status_code=401,
            detail={"error": "EXPIRED_PROOF", "message": "Proof timestamp outside replay window"},
        )

    try:
        proof_bytes = base64.urlsafe_b64decode(request.proof + "==")
        message = request.identity.verification_key.encode() + request.proof_timestamp.encode()
        VerifyKey(key_bytes).verify(message, proof_bytes)
    except BadSignatureError:
        raise HTTPException(
            status_code=401,
            detail={"error": "INVALID_PROOF", "message": "Invalid proof-of-possession"},
        ) from None
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"error": "MALFORMED_PROOF", "message": "Malformed proof"},
        ) from None

    # Verify the derived DID matches the URL (full 256-bit SHA-256 hex).
    derived_did = f"did:nexus:{_sha256(key_bytes).hexdigest()}"
    if derived_did != agent_did or request.identity.did != agent_did:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "DID_MISMATCH",
                "message": "Proof key does not match the agent DID",
            },
        )

    # Preserve registration time
    registered_at = _agents[agent_did]["registered_at"]

    # Update agent
    now = datetime.now(timezone.utc).isoformat()
    _agents[agent_did].update(
        {
            "identity": request.identity.model_dump(),
            "capabilities": request.capabilities.model_dump() if request.capabilities else {},
            "privacy": request.privacy.model_dump() if request.privacy else {},
            "last_seen": now,
        }
    )

    manifest_hash = _sha256(
        json.dumps(_agents[agent_did], sort_keys=True).encode()).hexdigest()

    return RegisterAgentResponse(
        success=True,
        agent_did=agent_did,
        manifest_hash=manifest_hash,
        trust_score=_agents[agent_did]["trust_score"],
        registered_at=registered_at,
        nexus_signature=f"nexus_sig_{manifest_hash[:32]}",
    )


@router.delete("/{agent_did}")
async def deregister_agent(
    agent_did: str,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Remove an agent from the registry."""
    if agent_did not in _agents:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "AGENT_NOT_FOUND",
                "message": f"Agent {agent_did} not found",
            },
        )
    authorize_agent(agent_did, principal)

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
            },
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
            },
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


def _view_manifest(
    agent: dict, principal: AuthPrincipal | None
) -> dict:
    """Return a manifest copy with PII fields redacted by allowlist.

    Only the agent's owner (DID-matched authenticated caller) or an
    administrator may see the unredacted ``identity`` block. Anonymous
    callers and other authenticated agents receive only an explicit
    allowlist of public identity fields, so that a future field added to
    ``AgentIdentityRequest`` does not silently leak to every caller.
    """
    agent_did = agent.get("identity", {}).get("did")
    is_owner = (
        principal is not None
        and not principal.is_admin
        and principal.agent_did == agent_did
    )
    if principal is not None and (principal.is_admin or is_owner):
        return agent

    public = dict(agent)
    raw_identity = agent.get("identity", {})
    # Allowlist: only these identity fields are exposed to non-owners.
    # owner_id and contact are PII and MUST NOT appear here. Any new
    # identity field defaults to redacted unless added intentionally.
    _PUBLIC_IDENTITY_FIELDS = ("did", "verification_key", "display_name")
    public["identity"] = {
        field: raw_identity[field]
        for field in _PUBLIC_IDENTITY_FIELDS
        if field in raw_identity
    }
    return public


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


