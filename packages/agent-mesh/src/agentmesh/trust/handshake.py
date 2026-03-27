# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Handshake

Ed25519 challenge/response handshake with registry-backed identity verification.
"""

from datetime import datetime, timedelta
from typing import Any, Optional, Literal
from pydantic import BaseModel, Field
import logging
import secrets
import asyncio
from agentmesh.constants import (
    TIER_TRUSTED_THRESHOLD,
    TIER_VERIFIED_PARTNER_THRESHOLD,
    TRUST_SCORE_DEFAULT,
)
from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.identity.delegation import UserContext
from agentmesh.exceptions import HandshakeError, HandshakeTimeoutError

logger = logging.getLogger(__name__)


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

    # Ed25519 signature and public key
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
    Ed25519 challenge/response trust handshake.

    Verifies:
    1. Agent identity (Ed25519 signature over challenge nonce)
    2. Registry membership (peer must be registered and active)
    3. Trust score (threshold check)
    4. Capabilities (attestation)

    Requires an ``IdentityRegistry`` to resolve peer DIDs to their
    cryptographic identities.  Without a registry, all peers are rejected.
    """

    MAX_HANDSHAKE_MS = 200
    DEFAULT_CACHE_TTL_SECONDS = 900  # 15 minutes
    DEFAULT_TIMEOUT_SECONDS = 30.0

    def __init__(
        self,
        agent_did: str,
        identity: Optional[AgentIdentity] = None,
        registry: Optional[IdentityRegistry] = None,
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
        self.registry = registry
        self.timeout_seconds = timeout_seconds
        self._pending_challenges: dict[str, HandshakeChallenge] = {}
        self._verified_peers: dict[str, tuple[HandshakeResult, datetime]] = {}
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)
        # V10: Limit pending challenges to prevent DoS accumulation
        self._max_pending_challenges = 1000

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

    def _purge_expired_challenges(self) -> None:
        """Remove expired challenges to prevent unbounded growth."""
        expired = [
            cid for cid, ch in self._pending_challenges.items()
            if ch.is_expired()
        ]
        for cid in expired:
            del self._pending_challenges[cid]

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
            # V10: Purge expired challenges and enforce limit
            self._purge_expired_challenges()
            if len(self._pending_challenges) >= self._max_pending_challenges:
                return HandshakeResult.failure(
                    peer_did, "Too many pending challenges — try again later", start
                )

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
                trust_score=verification.get("registry_trust_score", response.trust_score),
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
        """Respond to a trust handshake challenge with an Ed25519 signature.

        The response payload is signed with the agent's Ed25519 private key.
        The verifier checks the signature against the agent's registered
        public key, preventing DID fabrication.
        """
        if challenge.is_expired():
            raise ValueError("Challenge expired")

        agent_identity = identity or self.identity
        if not agent_identity:
            raise HandshakeError(
                "Identity required for handshake response — "
                "cannot sign without Ed25519 private key"
            )

        response_nonce = secrets.token_hex(16)

        # Sign the challenge+response payload with Ed25519
        payload = f"{challenge.challenge_id}:{challenge.nonce}:{response_nonce}:{self.agent_did}"
        signature = agent_identity.sign(payload.encode())

        return HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=response_nonce,
            agent_did=self.agent_did,
            capabilities=my_capabilities,
            trust_score=my_trust_score,
            signature=signature,
            public_key=agent_identity.public_key,
            user_context=user_context.model_dump() if user_context else None,
        )

    async def _get_peer_response(
        self,
        peer_did: str,
        challenge: HandshakeChallenge,
    ) -> Optional[HandshakeResponse]:
        """Resolve peer identity from registry and produce a signed response.

        Returns ``None`` (causing handshake failure) when:
        - No registry is configured
        - The peer DID is not registered
        - The peer identity is not active (revoked/suspended/expired)
        """
        if not self.registry:
            logger.warning("Handshake rejected: no IdentityRegistry configured")
            return None

        peer_identity = self.registry.get(peer_did)
        if not peer_identity:
            logger.warning("Handshake rejected: unknown peer DID %s", peer_did)
            return None

        if not peer_identity.is_active():
            logger.warning(
                "Handshake rejected: peer %s has status '%s'",
                peer_did,
                peer_identity.status,
            )
            return None

        # Build the peer's handshake instance with their real identity
        peer_handshake = TrustHandshake(
            agent_did=peer_did,
            identity=peer_identity,
            registry=self.registry,
        )

        return await peer_handshake.respond(
            challenge=challenge,
            my_capabilities=peer_identity.capabilities,
            my_trust_score=TRUST_SCORE_DEFAULT,
            identity=peer_identity,
        )

    async def _verify_response(
        self,
        response: HandshakeResponse,
        challenge: HandshakeChallenge,
        required_score: int,
        required_capabilities: Optional[list[str]],
    ) -> dict:
        """Verify handshake response with Ed25519 signature verification.

        Checks performed in order:
        1. Challenge ID matches
        2. Challenge not expired
        3. Peer DID is registered and active
        4. Ed25519 signature is valid
        5. Public key matches registered identity
        6. Trust score meets threshold
        7. Required capabilities are present
        """
        if response.challenge_id != challenge.challenge_id:
            return {"valid": False, "reason": "Challenge ID mismatch"}

        if challenge.is_expired():
            return {"valid": False, "reason": "Challenge expired"}

        # Look up peer identity for public-key verification
        if not self.registry:
            return {"valid": False, "reason": "No identity registry configured"}

        peer_identity = self.registry.get(response.agent_did)
        if not peer_identity:
            return {
                "valid": False,
                "reason": f"Unknown peer: {response.agent_did}",
            }

        if not peer_identity.is_active():
            return {
                "valid": False,
                "reason": f"Peer identity is {peer_identity.status}",
            }

        if not self.registry.is_trusted(response.agent_did):
            raise HandshakeError(f"Agent {response.agent_did} is not trusted in registry")

        # Verify Ed25519 signature over the challenge payload
        payload = f"{response.challenge_id}:{challenge.nonce}:{response.response_nonce}:{response.agent_did}"
        if not peer_identity.verify_signature(payload.encode(), response.signature):
            return {"valid": False, "reason": "Ed25519 signature verification failed"}

        # Verify public key matches the registered identity
        if response.public_key != peer_identity.public_key:
            return {"valid": False, "reason": "Public key mismatch with registered identity"}

        if response.trust_score < required_score:
            return {
                "valid": False,
                "reason": f"Trust score {response.trust_score} below required {required_score}"
            }

        # V06: Prefer registry trust score over self-reported value
        registry_trust_score = response.trust_score
        if self.registry and hasattr(peer_identity, "trust_score"):
            registry_trust_score = getattr(peer_identity, "trust_score", response.trust_score)

        if required_capabilities:
            missing = set(required_capabilities) - set(response.capabilities)
            if missing:
                return {
                    "valid": False,
                    "reason": f"Missing capabilities: {missing}"
                }

        return {"valid": True, "reason": None, "registry_trust_score": registry_trust_score}

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
