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
    freshness_nonce: Optional[str] = Field(
        None,
        description="RFC 9334 freshness nonce for Evidence liveness proof",
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    expires_in_seconds: int = 30

    @classmethod
    def generate(cls, require_freshness: bool = False) -> "HandshakeChallenge":
        """Generate a new challenge with a random nonce.

        Args:
            require_freshness: If True, include an RFC 9334 freshness
                nonce that the responder must echo back in its signed
                payload, proving Evidence liveness.
        """
        return cls(
            challenge_id=f"challenge_{secrets.token_hex(8)}",
            nonce=secrets.token_hex(32),
            freshness_nonce=secrets.token_hex(16) if require_freshness else None,
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

    # RFC 9334: freshness nonce echoed back from challenge
    freshness_nonce: Optional[str] = None

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
        # Serialise mutations on _pending_challenges so concurrent
        # initiate() coroutines cannot all pass the size check and
        # then each insert past the cap, and so the finally-block
        # cleanup at the end of initiate() can't race a sibling's
        # insert/lookup.
        self._challenges_lock = asyncio.Lock()
        # Serialise mutations on _verified_peers so concurrent
        # _cache_result / _get_cached_result / clear_cache calls
        # cannot race the read+TTL-delete sequence. clear_cache()
        # remains sync-callable; concurrent sync+async mixing is
        # documented as out-of-scope (use async paths only).
        self._peers_lock = asyncio.Lock()

    async def _get_cached_result(self, peer_did: str) -> Optional[HandshakeResult]:
        """Get cached verification result if still valid.

        Locked so the read+TTL-delete sequence cannot race a sibling
        coroutine's _cache_result for the same DID.
        """
        async with self._peers_lock:
            if peer_did in self._verified_peers:
                result, timestamp = self._verified_peers[peer_did]
                if datetime.utcnow() - timestamp < self._cache_ttl:
                    return result
                del self._verified_peers[peer_did]
        return None

    async def _cache_result(self, peer_did: str, result: HandshakeResult) -> None:
        """Cache a verification result with timestamp."""
        async with self._peers_lock:
            self._verified_peers[peer_did] = (result, datetime.utcnow())

    def _purge_expired_challenges(self) -> None:
        """Remove expired challenges to prevent unbounded growth.

        Caller must hold self._challenges_lock — this method only
        runs from within initiate()'s locked section.
        """
        expired = [
            cid for cid, ch in self._pending_challenges.items()
            if ch.is_expired()
        ]
        for cid in expired:
            del self._pending_challenges[cid]

    def clear_cache(self) -> None:
        """Clear all cached peer verification results.

        Sync-callable for compatibility with non-async callers. Do
        not mix sync clear_cache() with concurrent async access to
        _verified_peers; if both code paths are in play, use the
        async _peers_lock manually.
        """
        self._verified_peers.clear()

    async def initiate(
        self,
        peer_did: str,
        protocol: str = "iatp",
        required_trust_score: int = 700,
        required_capabilities: Optional[list[str]] = None,
        use_cache: bool = True,
        require_freshness: bool = False,
    ) -> HandshakeResult:
        """
        Initiate a simple nonce-based handshake with a peer.

        Args:
            require_freshness: If True, include an RFC 9334 freshness
                nonce and bypass the handshake result cache so that every
                call produces a fresh Evidence verification.
        """
        if use_cache and not require_freshness:
            cached = await self._get_cached_result(peer_did)
            if cached:
                return cached

        start = datetime.utcnow()

        try:
            result = await asyncio.wait_for(
                self._do_initiate(peer_did, required_trust_score, required_capabilities, start, require_freshness),
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
        require_freshness: bool = False,
    ) -> HandshakeResult:
        """Execute the core handshake: generate nonce, verify it comes back."""
        challenge: Optional[HandshakeChallenge] = None
        try:
            # V10: Purge expired challenges and enforce limit. The purge,
            # size check, and insert MUST run as one atomic step under the
            # async lock — otherwise concurrent initiates can each pass
            # the size check and then each insert, blowing past the cap.
            async with self._challenges_lock:
                self._purge_expired_challenges()
                if len(self._pending_challenges) >= self._max_pending_challenges:
                    return HandshakeResult.failure(
                        peer_did, "Too many pending challenges — try again later", start
                    )

                # Generate nonce challenge (with optional RFC 9334 freshness nonce)
                challenge = HandshakeChallenge.generate(require_freshness=require_freshness)
                self._pending_challenges[challenge.challenge_id] = challenge

            # Get peer response
            response = await self._get_peer_response(peer_did, challenge)

            if not response:
                return HandshakeResult.failure(
                    peer_did, "No response from peer", start
                )

            # Verify nonce and basic checks
            verification = await self._verify_response(
                response, challenge, required_trust_score, required_capabilities,
                expected_peer_did=peer_did,
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
                capabilities=verification.get("registry_capabilities", response.capabilities),
                started=start,
                user_context=response_user_ctx,
            )

            await self._cache_result(peer_did, result)
            return result
        finally:
            # Cleanup must run under the challenges lock so a sibling
            # initiate() can't race on the same challenge_id during
            # its size check.
            if challenge:
                async with self._challenges_lock:
                    self._pending_challenges.pop(challenge.challenge_id, None)

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
        # RFC 9334: include freshness_nonce in signed payload when present
        payload = f"{challenge.challenge_id}:{challenge.nonce}:{response_nonce}:{self.agent_did}"
        if challenge.freshness_nonce:
            payload += f":{challenge.freshness_nonce}"
        signature = agent_identity.sign(payload.encode())

        return HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=response_nonce,
            agent_did=self.agent_did,
            capabilities=my_capabilities,
            trust_score=my_trust_score,
            signature=signature,
            public_key=agent_identity.public_key,
            freshness_nonce=challenge.freshness_nonce,
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
        expected_peer_did: Optional[str] = None,
    ) -> dict:
        """Verify handshake response with Ed25519 signature verification.

        Checks performed in order:
        1. Challenge ID matches
        2. Challenge not expired
        3. Response DID matches expected peer DID (if provided)
        4. Peer DID is registered and active
        5. Ed25519 signature is valid
        6. Public key matches registered identity
        7. Registry trust score meets threshold (never self-reported)
        8. Registry capabilities include all required capabilities
        """
        if response.challenge_id != challenge.challenge_id:
            return {"valid": False, "reason": "Challenge ID mismatch"}

        if challenge.is_expired():
            return {"valid": False, "reason": "Challenge expired"}

        # Bind response to the expected peer DID to prevent DID substitution
        if expected_peer_did and response.agent_did != expected_peer_did:
            return {
                "valid": False,
                "reason": f"Response DID {response.agent_did} does not match "
                          f"expected peer {expected_peer_did}",
            }

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
            return {
                "valid": False,
                "reason": f"Agent {response.agent_did} is not trusted in registry",
            }

        # Verify Ed25519 signature over the challenge payload
        payload = f"{response.challenge_id}:{challenge.nonce}:{response.response_nonce}:{response.agent_did}"
        # RFC 9334: verify freshness_nonce match and include in payload
        if challenge.freshness_nonce:
            if response.freshness_nonce != challenge.freshness_nonce:
                return {"valid": False, "reason": "Freshness nonce mismatch (RFC 9334)"}
            payload += f":{challenge.freshness_nonce}"
        if not peer_identity.verify_signature(payload.encode(), response.signature):
            return {"valid": False, "reason": "Ed25519 signature verification failed"}

        # Verify public key matches the registered identity
        if response.public_key != peer_identity.public_key:
            return {"valid": False, "reason": "Public key mismatch with registered identity"}

        # Use registry-authoritative trust score — never trust self-reported value
        registry_trust_score = getattr(peer_identity, "trust_score", TRUST_SCORE_DEFAULT)

        if registry_trust_score < required_score:
            return {
                "valid": False,
                "reason": f"Trust score {registry_trust_score} below required {required_score}"
            }

        # Use registry-authoritative capabilities — never trust self-reported value
        registry_capabilities = list(getattr(peer_identity, "capabilities", []))

        if required_capabilities:
            missing = set(required_capabilities) - set(registry_capabilities)
            if missing:
                return {
                    "valid": False,
                    "reason": f"Missing capabilities: {missing}"
                }

        return {
            "valid": True,
            "reason": None,
            "registry_trust_score": registry_trust_score,
            "registry_capabilities": registry_capabilities,
        }

    def create_challenge(self, require_freshness: bool = False) -> HandshakeChallenge:
        """Create and register a new challenge.

        Args:
            require_freshness: If True, include an RFC 9334 freshness
                nonce in the challenge.
        """
        challenge = HandshakeChallenge.generate(require_freshness=require_freshness)
        self._pending_challenges[challenge.challenge_id] = challenge
        return challenge

    def validate_challenge(self, challenge_id: str) -> bool:
        """Check if a challenge ID is valid and has not expired."""
        challenge = self._pending_challenges.get(challenge_id)
        if not challenge:
            return False
        return not challenge.is_expired()
