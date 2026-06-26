# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Handshake

Ed25519 challenge/response handshake with registry-backed identity verification.
"""

import asyncio
import base64
import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field

from agentmesh.constants import (
    TIER_TRUSTED_THRESHOLD,
    TIER_VERIFIED_PARTNER_THRESHOLD,
    TRUST_SCORE_DEFAULT,
)
from agentmesh.exceptions import (
    AttestationError,
    HandshakeError,
    HandshakeTimeoutError,
    KeyAcquisitionError,
)
from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.identity.attestation import (
    AttestationClaims,
    AttestationEvidence,
    KeyOrigin,
    ReferenceValues,
    compute_startup_binding_hash,
    public_key_hash_hex,
)
from agentmesh.identity.attestation_verifier import AttestationVerifier
from agentmesh.identity.delegation import UserContext
from agentmesh.identity.tee_keystore import TEEKeyStore, require_tee_bound_key

logger = logging.getLogger(__name__)
_last_handshake_completion: datetime | None = None


class HandshakeChallenge(BaseModel):
    """Challenge issued during a trust handshake."""

    challenge_id: str
    nonce: str
    freshness_nonce: str | None = Field(
        None,
        description="RFC 9334 freshness nonce for Evidence liveness proof",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
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
        elapsed = (datetime.now(UTC) - self.timestamp).total_seconds()
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
    freshness_nonce: str | None = None

    # Optional ADR 0010 confidential-computing attestation.
    attestation_evidence: AttestationEvidence | None = None
    attestation_signature: str | None = Field(
        None,
        description="Base64 Ed25519 signature over the Layer 2 attestation transcript",
    )
    attestation_public_key: str | None = Field(
        None,
        description="Base64 raw Ed25519 public key bound by attestation evidence",
    )
    attestation_key_origin: KeyOrigin | None = None

    # User context for OBO flows
    user_context: dict | None = Field(None, description="End-user context for OBO flows")

    # Metadata
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HandshakeResult(BaseModel):
    """Result of a trust handshake."""

    verified: bool
    peer_did: str
    peer_name: str | None = None

    # Trust details
    trust_score: int = Field(default=0, ge=0, le=1000)
    trust_level: Literal["verified_partner", "trusted", "standard", "untrusted"] = "untrusted"

    # Capabilities
    capabilities: list[str] = Field(default_factory=list)

    # Optional attestation details.
    attestation_verified: bool = False
    attestation_claims: AttestationClaims | None = None
    key_origin: KeyOrigin | None = None

    # User context (propagated from OBO flow)
    user_context: UserContext | None = Field(
        None, description="End-user context if acting on behalf of a user"
    )

    # Timing
    handshake_started: datetime = Field(default_factory=lambda: datetime.now(UTC))
    handshake_completed: datetime | None = None
    latency_ms: int | None = None

    # Rejection reason (if not verified)
    rejection_reason: str | None = None

    # External identity (ADR-0007: present only for cross-org agents)
    external_identity: Any | None = Field(
        None,
        description="ExternalIdentity from JWKS federation, set when peer was resolved via ExternalJWKSProvider",
    )

    @classmethod
    def success(
        cls,
        peer_did: str,
        trust_score: int,
        capabilities: list[str],
        peer_name: str | None = None,
        started: datetime | None = None,
        user_context: UserContext | None = None,
        attestation_claims: AttestationClaims | None = None,
        external_identity: Any | None = None,
    ) -> "HandshakeResult":
        """Create a successful handshake result."""
        now = _handshake_completion_now()
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
            attestation_verified=attestation_claims is not None,
            attestation_claims=attestation_claims,
            key_origin=attestation_claims.key_origin if attestation_claims else None,
            user_context=user_context,
            handshake_started=start,
            handshake_completed=now,
            latency_ms=latency,
            external_identity=external_identity,
        )

    @classmethod
    def failure(
        cls,
        peer_did: str,
        reason: str,
        started: datetime | None = None,
    ) -> "HandshakeResult":
        """Create a failed handshake result."""
        now = _handshake_completion_now()
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
        identity: AgentIdentity | None = None,
        registry: IdentityRegistry | None = None,
        attestation_verifier: AttestationVerifier | None = None,
        attestation_reference_values: ReferenceValues | None = None,
        tee_key_store: TEEKeyStore | None = None,
        tee_key_id: str | None = None,
        attestation_evidence: AttestationEvidence | None = None,
        require_attestation: bool = False,
        require_tee_bound_key: bool = False,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        if not agent_did or not agent_did.strip():
            raise HandshakeError("agent_did must not be empty")
        if not agent_did.startswith("did:mesh:"):
            raise HandshakeError(f"agent_did must match 'did:mesh:' pattern, got: {agent_did}")
        if cache_ttl_seconds < 0:
            raise HandshakeError(
                f"cache_ttl_seconds must be non-negative, got: {cache_ttl_seconds}"
            )
        if timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be positive, got: {timeout_seconds}")
        self.agent_did = agent_did
        self.identity = identity
        self.registry = registry
        self.attestation_verifier = attestation_verifier
        self.attestation_reference_values = attestation_reference_values or ReferenceValues()
        self.tee_key_store = tee_key_store
        self.tee_key_id = tee_key_id or agent_did
        self.attestation_evidence = attestation_evidence
        self.require_attestation = require_attestation
        self.require_tee_bound_key = require_tee_bound_key
        self.timeout_seconds = timeout_seconds
        self._pending_challenges: dict[str, HandshakeChallenge] = {}
        self._verified_peers: dict[Any, tuple[HandshakeResult, datetime]] = {}
        self._used_attestation_challenges: set[tuple[str, str, str]] = set()
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

    def _cache_key(
        self,
        peer_did: str,
        *,
        require_attestation: bool,
        require_tee_bound_key: bool,
    ) -> tuple[Any, ...]:
        reference_values_fingerprint = json.dumps(
            self.attestation_reference_values.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        verifier_identity = (
            f"{type(self.attestation_verifier).__module__}."
            f"{type(self.attestation_verifier).__qualname__}"
            if self.attestation_verifier
            else None
        )
        return (
            peer_did,
            require_attestation,
            require_tee_bound_key,
            verifier_identity,
            reference_values_fingerprint,
        )

    async def _get_cached_result(
        self,
        peer_did: str,
        *,
        require_attestation: bool = False,
        require_tee_bound_key: bool = False,
    ) -> HandshakeResult | None:
        """Get cached verification result if still valid.

        Locked so the read+TTL-delete sequence cannot race a sibling
        coroutine's _cache_result for the same DID.
        """
        async with self._peers_lock:
            cache_key = self._cache_key(
                peer_did,
                require_attestation=require_attestation,
                require_tee_bound_key=require_tee_bound_key,
            )
            lookup_keys: list[Any] = [cache_key]
            if not require_attestation and not require_tee_bound_key:
                lookup_keys.append(peer_did)
            for lookup_key in lookup_keys:
                if lookup_key not in self._verified_peers:
                    continue
                result, timestamp = self._verified_peers[lookup_key]
                if datetime.now(UTC) - timestamp < self._cache_ttl:
                    if result.attestation_claims and result.attestation_claims.is_expired():
                        del self._verified_peers[lookup_key]
                        return None
                    if require_attestation and not result.attestation_verified:
                        del self._verified_peers[lookup_key]
                        return None
                    if require_tee_bound_key and not (
                        result.key_origin and result.key_origin.is_tee_bound
                    ):
                        del self._verified_peers[lookup_key]
                        return None
                    return result
                del self._verified_peers[lookup_key]
        return None

    async def _cache_result(
        self,
        peer_did: str,
        result: HandshakeResult,
        *,
        require_attestation: bool,
        require_tee_bound_key: bool,
    ) -> None:
        """Cache a verification result with timestamp."""
        async with self._peers_lock:
            cache_key = self._cache_key(
                peer_did,
                require_attestation=require_attestation,
                require_tee_bound_key=require_tee_bound_key,
            )
            self._verified_peers[cache_key] = (result, datetime.now(UTC))

    def _purge_expired_challenges(self) -> None:
        """Remove expired challenges to prevent unbounded growth.

        Caller must hold self._challenges_lock — this method only
        runs from within initiate()'s locked section.
        """
        expired = [cid for cid, ch in self._pending_challenges.items() if ch.is_expired()]
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
        required_capabilities: list[str] | None = None,
        use_cache: bool = True,
        require_freshness: bool = False,
        require_attestation: bool | None = None,
        require_tee_bound_key: bool | None = None,
    ) -> HandshakeResult:
        """
        Initiate a simple nonce-based handshake with a peer.

        Args:
            require_freshness: If True, include an RFC 9334 freshness
                nonce and bypass the handshake result cache so that every
                call produces a fresh Evidence verification.
        """
        effective_require_attestation = (
            self.require_attestation if require_attestation is None else require_attestation
        )
        effective_require_tee_bound_key = (
            self.require_tee_bound_key if require_tee_bound_key is None else require_tee_bound_key
        )

        if use_cache and not require_freshness:
            cached = await self._get_cached_result(
                peer_did,
                require_attestation=effective_require_attestation,
                require_tee_bound_key=effective_require_tee_bound_key,
            )
            if cached:
                return cached

        start = datetime.now(UTC)

        try:
            result = await asyncio.wait_for(
                self._do_initiate(
                    peer_did,
                    required_trust_score,
                    required_capabilities,
                    start,
                    require_freshness,
                    require_attestation=effective_require_attestation,
                    require_tee_bound_key=effective_require_tee_bound_key,
                ),
                timeout=self.timeout_seconds,
            )
            return result
        except TimeoutError:
            raise HandshakeTimeoutError(
                f"Handshake with {peer_did} exceeded {self.timeout_seconds}s timeout"
            )
        except HandshakeTimeoutError:
            raise
        except Exception as e:
            return HandshakeResult.failure(peer_did, f"Handshake error: {str(e)}", start)

    async def _do_initiate(
        self,
        peer_did: str,
        required_trust_score: int,
        required_capabilities: list[str] | None,
        start: datetime,
        require_freshness: bool = False,
        require_attestation: bool | None = None,
        require_tee_bound_key: bool | None = None,
    ) -> HandshakeResult:
        """Execute the core handshake: generate nonce, verify it comes back."""
        effective_require_attestation = (
            self.require_attestation if require_attestation is None else require_attestation
        )
        effective_require_tee_bound_key = (
            self.require_tee_bound_key if require_tee_bound_key is None else require_tee_bound_key
        )
        challenge: HandshakeChallenge | None = None
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
                return HandshakeResult.failure(peer_did, "No response from peer", start)

            # Verify nonce and basic checks
            verification = await self._verify_response(
                response,
                challenge,
                required_trust_score,
                required_capabilities,
                expected_peer_did=peer_did,
                require_attestation=effective_require_attestation,
                require_tee_bound_key=effective_require_tee_bound_key,
            )

            if not verification["valid"]:
                return HandshakeResult.failure(peer_did, verification["reason"], start)

            response_user_ctx = None
            if response.user_context:
                response_user_ctx = UserContext(**response.user_context)

            result = HandshakeResult.success(
                peer_did=peer_did,
                trust_score=verification.get("registry_trust_score", response.trust_score),
                capabilities=verification.get("registry_capabilities", response.capabilities),
                started=start,
                user_context=response_user_ctx,
                attestation_claims=verification.get("attestation_claims"),
            )

            await self._cache_result(
                peer_did,
                result,
                require_attestation=effective_require_attestation,
                require_tee_bound_key=effective_require_tee_bound_key,
            )
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
        identity: AgentIdentity | None = None,
        user_context: UserContext | None = None,
        tee_key_store: TEEKeyStore | None = None,
        tee_key_id: str | None = None,
        attestation_evidence: AttestationEvidence | None = None,
        verifier_did: str | None = None,
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
                "Identity required for handshake response — cannot sign without Ed25519 private key"
            )

        response_nonce = secrets.token_hex(16)

        # Sign the challenge+response payload with Ed25519
        # RFC 9334: include freshness_nonce in signed payload when present
        payload = f"{challenge.challenge_id}:{challenge.nonce}:{response_nonce}:{self.agent_did}"
        if challenge.freshness_nonce:
            payload += f":{challenge.freshness_nonce}"
        signature = agent_identity.sign(payload.encode())

        evidence = attestation_evidence or self.attestation_evidence
        attestation_signature = None
        attestation_public_key = None
        attestation_key_origin = None
        effective_tee_key_store = tee_key_store or self.tee_key_store
        if evidence is not None:
            if effective_tee_key_store is None:
                raise HandshakeError("TEE key store required to sign attestation response")
            key_handle = await effective_tee_key_store.acquire_key(tee_key_id or self.tee_key_id)
            if self.require_tee_bound_key:
                require_tee_bound_key(
                    key_handle,
                    context="handshake response",
                )
            transcript = compute_layer2_signature_input(
                agent_did=self.agent_did,
                verifier_did=verifier_did or "",
                challenge_id=challenge.challenge_id,
                nonce=challenge.nonce,
                attestation_token=evidence.evidence.encode("utf-8"),
            )
            attestation_signature = base64.b64encode(await key_handle.sign(transcript)).decode()
            attestation_public_key = base64.b64encode(key_handle.public_key).decode()
            attestation_key_origin = key_handle.key_origin

        return HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=response_nonce,
            agent_did=self.agent_did,
            capabilities=my_capabilities,
            trust_score=my_trust_score,
            signature=signature,
            public_key=agent_identity.public_key,
            freshness_nonce=challenge.freshness_nonce,
            attestation_evidence=evidence,
            attestation_signature=attestation_signature,
            attestation_public_key=attestation_public_key,
            attestation_key_origin=attestation_key_origin,
            user_context=user_context.model_dump() if user_context else None,
        )

    async def _get_peer_response(
        self,
        peer_did: str,
        challenge: HandshakeChallenge,
    ) -> HandshakeResponse | None:
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
        peer_attestation_evidence = (
            self.attestation_evidence
            if self.attestation_evidence and self.attestation_evidence.agent_did == peer_did
            else None
        )
        peer_handshake = TrustHandshake(
            agent_did=peer_did,
            identity=peer_identity,
            registry=self.registry,
            attestation_verifier=self.attestation_verifier,
            attestation_reference_values=self.attestation_reference_values,
            tee_key_store=self.tee_key_store if peer_attestation_evidence else None,
            tee_key_id=self.tee_key_id if peer_attestation_evidence else None,
            attestation_evidence=peer_attestation_evidence,
        )

        return await peer_handshake.respond(
            challenge=challenge,
            my_capabilities=peer_identity.capabilities,
            my_trust_score=TRUST_SCORE_DEFAULT,
            identity=peer_identity,
            verifier_did=self.agent_did,
        )

    async def _verify_response(
        self,
        response: HandshakeResponse,
        challenge: HandshakeChallenge,
        required_score: int,
        required_capabilities: list[str] | None,
        expected_peer_did: str | None = None,
        require_attestation: bool | None = None,
        require_tee_bound_key: bool | None = None,
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
        payload = (
            f"{response.challenge_id}:{challenge.nonce}:"
            f"{response.response_nonce}:{response.agent_did}"
        )
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

        effective_require_attestation = (
            self.require_attestation if require_attestation is None else require_attestation
        )
        effective_require_tee_bound_key = (
            self.require_tee_bound_key if require_tee_bound_key is None else require_tee_bound_key
        )
        attestation_claims = await self._verify_attestation_response(
            response=response,
            challenge=challenge,
            require_attestation=effective_require_attestation,
            require_tee_bound_key=effective_require_tee_bound_key,
        )
        if isinstance(attestation_claims, str):
            return {"valid": False, "reason": attestation_claims}

        # Use registry-authoritative trust score — never trust self-reported value
        registry_trust_score = getattr(peer_identity, "trust_score", TRUST_SCORE_DEFAULT)

        if registry_trust_score < required_score:
            return {
                "valid": False,
                "reason": f"Trust score {registry_trust_score} below required {required_score}",
            }

        # Use registry-authoritative capabilities — never trust self-reported value
        registry_capabilities = list(getattr(peer_identity, "capabilities", []))

        if required_capabilities:
            missing = set(required_capabilities) - set(registry_capabilities)
            if missing:
                return {"valid": False, "reason": f"Missing capabilities: {missing}"}

        return {
            "valid": True,
            "reason": None,
            "registry_trust_score": registry_trust_score,
            "registry_capabilities": registry_capabilities,
            "attestation_claims": attestation_claims,
        }

    async def _verify_attestation_response(
        self,
        *,
        response: HandshakeResponse,
        challenge: HandshakeChallenge,
        require_attestation: bool,
        require_tee_bound_key: bool,
    ) -> AttestationClaims | None | str:
        """Verify optional ADR 0010 attestation evidence and Layer 2 signature."""
        evidence = response.attestation_evidence
        if evidence is None:
            if require_attestation or require_tee_bound_key:
                return "Attestation evidence required but missing"
            return None
        if self.attestation_verifier is None:
            if require_attestation or require_tee_bound_key:
                return "Attestation verifier required but not configured"
            return None
        if not response.attestation_signature:
            if require_attestation or require_tee_bound_key:
                return "Attestation signature required but missing"
            return None
        if not response.attestation_public_key:
            if require_attestation or require_tee_bound_key:
                return "Attestation public key required but missing"
            return None

        replay_key = (response.agent_did, challenge.challenge_id, challenge.nonce)
        if replay_key in self._used_attestation_challenges:
            return "Attestation challenge replay detected"

        try:
            public_key_bytes = base64.b64decode(response.attestation_public_key)
        except (ValueError, TypeError) as exc:
            return f"Malformed attestation public key: {exc}"
        if evidence.public_key_hash is None:
            return "Attestation public key hash missing"
        try:
            if public_key_hash_hex(public_key_bytes) != evidence.public_key_hash:
                return "Attestation public key hash mismatch"
        except ValueError as exc:
            return f"Malformed attestation public key: {exc}"
        if evidence.challenge_id is not None or evidence.nonce is not None:
            if not evidence.matches_binding(
                agent_did=response.agent_did,
                challenge_id=challenge.challenge_id,
                nonce=challenge.nonce,
                public_key_hash=evidence.public_key_hash,
            ):
                return "Attestation evidence binding mismatch"
        elif evidence.binding_hash is not None:
            startup_binding_hash = compute_startup_binding_hash(
                response.agent_did,
                evidence.public_key_hash,
            )
            if evidence.binding_hash != startup_binding_hash:
                return "Attestation startup binding mismatch"

        transcript = compute_layer2_signature_input(
            agent_did=response.agent_did,
            verifier_did=self.agent_did,
            challenge_id=challenge.challenge_id,
            nonce=challenge.nonce,
            attestation_token=evidence.evidence.encode("utf-8"),
        )
        try:
            signature = base64.b64decode(response.attestation_signature)
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, transcript)
        except (InvalidSignature, ValueError, TypeError) as exc:
            return f"Attestation signature verification failed: {exc}"

        try:
            claims = await self.attestation_verifier.verify(
                evidence,
                self.attestation_reference_values,
            )
        except (AttestationError, KeyAcquisitionError) as exc:
            return f"Attestation verification failed: {exc}"

        key_origin = response.attestation_key_origin or claims.key_origin
        if key_origin != claims.key_origin:
            return "Attestation key origin mismatch"
        if require_tee_bound_key and not claims.key_bound_to_tee:
            return f"TEE-bound key required but got key_origin={claims.key_origin.value}"

        self._used_attestation_challenges.add(replay_key)
        return claims

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


def compute_layer2_signature_input(
    *,
    agent_did: str,
    verifier_did: str,
    challenge_id: str,
    nonce: str,
    attestation_token: bytes,
) -> bytes:
    """Compute the ADR 0010 Layer 2 transcript hash for challenge signatures."""
    payload = b"".join(
        (
            b"agentmesh-layer2-v1",
            _length_prefixed_utf8(agent_did, field_name="agent_did"),
            _length_prefixed_utf8(verifier_did, field_name="verifier_did"),
            _length_prefixed_utf8(challenge_id, field_name="challenge_id"),
            _length_prefixed_utf8(nonce, field_name="nonce"),
            hashlib.sha256(attestation_token).digest(),
        )
    )
    return hashlib.sha256(payload).digest()


def _length_prefixed_utf8(value: str, *, field_name: str) -> bytes:
    if value is None:
        raise ValueError(f"{field_name} must not be None")
    encoded = value.encode("utf-8")
    if len(encoded) > 65535:
        raise ValueError(f"{field_name} must be at most 65535 bytes")
    return len(encoded).to_bytes(2, "big") + encoded


def _handshake_completion_now() -> datetime:
    """Return a UTC completion timestamp that is monotonic within this process."""
    global _last_handshake_completion
    now = datetime.now(UTC)
    if _last_handshake_completion is not None and now <= _last_handshake_completion:
        now = _last_handshake_completion + timedelta(microseconds=1)
    _last_handshake_completion = now
    return now
