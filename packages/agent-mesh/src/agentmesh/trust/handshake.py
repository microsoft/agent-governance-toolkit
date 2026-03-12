# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Handshake

Simple nonce-based challenge/response handshake.
"""

from datetime import datetime, timedelta
from typing import Any, Optional, Literal
from pydantic import BaseModel, Field
import hashlib
import secrets
import asyncio
from agentmesh.constants import TIER_TRUSTED_THRESHOLD, TIER_VERIFIED_PARTNER_THRESHOLD
from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.identity.delegation import UserContext
from agentmesh.exceptions import HandshakeError, HandshakeTimeoutError


class HandshakeChallenge(BaseModel):
    """Challenge issued during a trust handshake."""

    challenge_id: str
    nonce: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    expires_in_seconds: int = 30

    @classmethod
    def generate(cls) -> "HandshakeChallenge":
        """Generate a new challenge with a random nonce."""
        return cls(
            challenge_id=f"challenge_{secrets.token_hex(8)}",
            nonce=secrets.token_hex(32),
        )

    def is_expired(self) -> bool:
        """Check if the challenge has exceeded its time-to-live."""
        elapsed = (datetime.utcnow() - self.timestamp).total_seconds()
        return elapsed > self.expires_in_seconds


class HandshakeResponse(BaseModel):
    """Response to a handshake challenge."""

    challenge_id: str
    response_nonce: str

    # Agent attestation
    agent_did: str
    capabilities: list[str] = Field(default_factory=list)
    trust_score: int = Field(default=0, ge=0, le=1000)

    # Simple proof (SHA-256 hash of challenge + response)
    signature: str
    public_key: str

    # User context for OBO flows
    user_context: Optional[dict] = Field(None, description="End-user context for OBO flows")

    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HandshakeResult(BaseModel):
    """Result of a trust handshake."""

    verified: bool
    peer_did: str
    peer_name: Optional[str] = None

    # Trust details
    trust_score: int = Field(default=0, ge=0, le=1000)
    trust_level: Literal["verified_partner", "trusted", "standard", "untrusted"] = "untrusted"

    # Capabilities
    capabilities: list[str] = Field(default_factory=list)

    # User context (propagated from OBO flow)
    user_context: Optional[UserContext] = Field(None, description="End-user context if acting on behalf of a user")

    # Timing
    handshake_started: datetime = Field(default_factory=datetime.utcnow)
    handshake_completed: Optional[datetime] = None
    latency_ms: Optional[int] = None

    # Rejection reason (if not verified)
    rejection_reason: Optional[str] = None

    @classmethod
    def success(
        cls,
        peer_did: str,
        trust_score: int,
        capabilities: list[str],
        peer_name: Optional[str] = None,
        started: Optional[datetime] = None,
        user_context: Optional[UserContext] = None,
    ) -> "HandshakeResult":
        """Create a successful handshake result."""
        now = datetime.utcnow()
        start = started or now
        latency = int((now - start).total_seconds() * 1000)

        if trust_score >= TIER_VERIFIED_PARTNER_THRESHOLD:
            level = "verified_partner"
        elif trust_score >= TIER_TRUSTED_THRESHOLD:
            level = "trusted"
        elif trust_score >= 400:
            level = "standard"
        else:
            level = "untrusted"

        return cls(
            verified=True,
            peer_did=peer_did,
            peer_name=peer_name,
            trust_score=trust_score,
            trust_level=level,
            capabilities=capabilities,
            user_context=user_context,
            handshake_started=start,
            handshake_completed=now,
            latency_ms=latency,
        )

    @classmethod
    def failure(
        cls,
        peer_did: str,
        reason: str,
        started: Optional[datetime] = None,
    ) -> "HandshakeResult":
        """Create a failed handshake result."""
        now = datetime.utcnow()
        start = started or now
        latency = int((now - start).total_seconds() * 1000)

        return cls(
            verified=False,
            peer_did=peer_did,
            trust_score=0,
            handshake_started=start,
            handshake_completed=now,
            latency_ms=latency,
            rejection_reason=reason,
        )


class TrustHandshake:
    """
    Simple nonce-based trust handshake.

    Verifies:
    1. Agent identity (via nonce echo)
    2. Trust score (threshold check)
    3. Capabilities (attestation)
    """

    MAX_HANDSHAKE_MS = 200
    DEFAULT_CACHE_TTL_SECONDS = 900  # 15 minutes
    DEFAULT_TIMEOUT_SECONDS = 30.0

    def __init__(
        self,
        agent_did: str,
        identity: Optional[AgentIdentity] = None,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        if not agent_did or not agent_did.strip():
            raise HandshakeError("agent_did must not be empty")
        if not agent_did.startswith("did:mesh:"):
            raise HandshakeError(
                f"agent_did must match 'did:mesh:' pattern, got: {agent_did}"
            )
        if cache_ttl_seconds < 0:
            raise HandshakeError(
                f"cache_ttl_seconds must be non-negative, got: {cache_ttl_seconds}"
            )
        if timeout_seconds <= 0:
            raise ValueError(
                f"timeout_seconds must be positive, got: {timeout_seconds}"
            )
        self.agent_did = agent_did
        self.identity = identity
        self.timeout_seconds = timeout_seconds
        self._pending_challenges: dict[str, HandshakeChallenge] = {}
        self._verified_peers: dict[str, tuple[HandshakeResult, datetime]] = {}
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)

    def _get_cached_result(self, peer_did: str) -> Optional[HandshakeResult]:
        """Get cached verification result if still valid."""
        if peer_did in self._verified_peers:
            result, timestamp = self._verified_peers[peer_did]
            if datetime.utcnow() - timestamp < self._cache_ttl:
                return result
            del self._verified_peers[peer_did]
        return None

    def _cache_result(self, peer_did: str, result: HandshakeResult) -> None:
        """Cache a verification result with timestamp."""
        self._verified_peers[peer_did] = (result, datetime.utcnow())

    def clear_cache(self) -> None:
        """Clear all cached peer verification results."""
        self._verified_peers.clear()

    async def initiate(
        self,
        peer_did: str,
        protocol: str = "iatp",
        required_trust_score: int = 700,
        required_capabilities: Optional[list[str]] = None,
        use_cache: bool = True,
    ) -> HandshakeResult:
        """
        Initiate a simple nonce-based handshake with a peer.
        """
        if use_cache:
            cached = self._get_cached_result(peer_did)
            if cached:
                return cached

        start = datetime.utcnow()

        try:
            result = await asyncio.wait_for(
                self._do_initiate(peer_did, required_trust_score, required_capabilities, start),
                timeout=self.timeout_seconds,
            )
            return result
        except asyncio.TimeoutError:
            raise HandshakeTimeoutError(
                f"Handshake with {peer_did} exceeded {self.timeout_seconds}s timeout"
            )
        except HandshakeTimeoutError:
            raise
        except Exception as e:
            return HandshakeResult.failure(
                peer_did, f"Handshake error: {str(e)}", start
            )

    async def _do_initiate(
        self,
        peer_did: str,
        required_trust_score: int,
        required_capabilities: Optional[list[str]],
        start: datetime,
    ) -> HandshakeResult:
        """Execute the core handshake: generate nonce, verify it comes back."""
        challenge: Optional[HandshakeChallenge] = None
        try:
            # Generate nonce challenge
            challenge = HandshakeChallenge.generate()
            self._pending_challenges[challenge.challenge_id] = challenge

            # Get peer response
            response = await self._get_peer_response(peer_did, challenge)

            if not response:
                return HandshakeResult.failure(
                    peer_did, "No response from peer", start
                )

            # Verify nonce and basic checks
            verification = await self._verify_response(
                response, challenge, required_trust_score, required_capabilities
            )

            if not verification["valid"]:
                return HandshakeResult.failure(
                    peer_did, verification["reason"], start
                )

            response_user_ctx = None
            if response.user_context:
                response_user_ctx = UserContext(**response.user_context)

            result = HandshakeResult.success(
                peer_did=peer_did,
                trust_score=response.trust_score,
                capabilities=response.capabilities,
                started=start,
                user_context=response_user_ctx,
            )

            self._cache_result(peer_did, result)
            return result
        finally:
            if challenge and challenge.challenge_id in self._pending_challenges:
                del self._pending_challenges[challenge.challenge_id]

    async def respond(
        self,
        challenge: HandshakeChallenge,
        my_capabilities: list[str],
        my_trust_score: int,
        private_key: Any = None,
        identity: Optional[AgentIdentity] = None,
        user_context: Optional[UserContext] = None,
    ) -> HandshakeResponse:
        """Respond to a trust handshake challenge with a simple hash proof."""
        if challenge.is_expired():
            raise ValueError("Challenge expired")

        response_nonce = secrets.token_hex(16)

        # Simple SHA-256 proof binding challenge to response
        payload = f"{challenge.challenge_id}:{challenge.nonce}:{response_nonce}:{self.agent_did}"
        signature = hashlib.sha256(payload.encode()).hexdigest()
        pub_key = hashlib.sha256(self.agent_did.encode()).hexdigest()

        return HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=response_nonce,
            agent_did=self.agent_did,
            capabilities=my_capabilities,
            trust_score=my_trust_score,
            signature=signature,
            public_key=pub_key,
            user_context=user_context.model_dump() if user_context else None,
        )

    async def _get_peer_response(
        self,
        peer_did: str,
        challenge: HandshakeChallenge,
    ) -> Optional[HandshakeResponse]:
        """Simulate peer response for now."""
        await asyncio.sleep(0.05)

        response_nonce = secrets.token_hex(16)
        sim_payload = f"{challenge.challenge_id}:{challenge.nonce}:{response_nonce}:{peer_did}"

        return HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=response_nonce,
            agent_did=peer_did,
            capabilities=["read:data", "write:reports"],
            trust_score=750,
            signature=hashlib.sha256(sim_payload.encode()).hexdigest(),
            public_key=hashlib.sha256(peer_did.encode()).hexdigest(),
        )

    async def _verify_response(
        self,
        response: HandshakeResponse,
        challenge: HandshakeChallenge,
        required_score: int,
        required_capabilities: Optional[list[str]],
    ) -> dict:
        """Verify handshake response: challenge ID, nonce hash, score, capabilities."""
        if response.challenge_id != challenge.challenge_id:
            return {"valid": False, "reason": "Challenge ID mismatch"}

        if challenge.is_expired():
            return {"valid": False, "reason": "Challenge expired"}

        # Verify SHA-256 nonce proof
        payload = f"{response.challenge_id}:{challenge.nonce}:{response.response_nonce}:{response.agent_did}"
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if response.signature != expected:
            return {"valid": False, "reason": "Signature verification failed"}

        if response.trust_score < required_score:
            return {
                "valid": False,
                "reason": f"Trust score {response.trust_score} below required {required_score}"
            }

        if required_capabilities:
            missing = set(required_capabilities) - set(response.capabilities)
            if missing:
                return {
                    "valid": False,
                    "reason": f"Missing capabilities: {missing}"
                }

        return {"valid": True, "reason": None}

    def create_challenge(self) -> HandshakeChallenge:
        """Create and register a new challenge."""
        challenge = HandshakeChallenge.generate()
        self._pending_challenges[challenge.challenge_id] = challenge
        return challenge

    def validate_challenge(self, challenge_id: str) -> bool:
        """Check if a challenge ID is valid and has not expired."""
        challenge = self._pending_challenges.get(challenge_id)
        if not challenge:
            return False
        return not challenge.is_expired()
