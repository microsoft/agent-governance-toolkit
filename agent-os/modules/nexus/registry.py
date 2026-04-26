# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Registry

Manages agent registration, discovery, and manifest storage for the Nexus network.
"""

from datetime import datetime, timezone
from typing import Optional, AsyncIterator
from dataclasses import dataclass, field
import hashlib
import json
import asyncio

from .schemas.manifest import AgentManifest, AgentIdentity
from .reputation import ReputationEngine, TrustScore, ReputationHistory
from .exceptions import (
    AgentAlreadyRegisteredError,
    AgentNotFoundError,
    InvalidManifestError,
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
)


@dataclass
class RegistrationResult:
    """Result of agent registration."""
    
    success: bool
    agent_did: str
    manifest_hash: str
    trust_score: int
    registered_at: datetime
    
    # Nexus attestation
    nexus_signature: Optional[str] = None
    
    # Errors (if any)
    errors: list[str] = field(default_factory=list)


@dataclass
class PeerVerification:
    """Result of peer verification."""
    
    verified: bool
    peer_did: str
    trust_score: int
    trust_tier: str
    
    # Manifest summary
    capabilities: list[str] = field(default_factory=list)
    privacy_policy: Optional[str] = None
    
    # Attestation
    attestation_valid: bool = False
    attestation_expires: Optional[datetime] = None
    
    # Rejection reason (if not verified)
    rejection_reason: Optional[str] = None


class AgentRegistry:
    """
    Central registry for agent manifests on the Nexus network.
    
    Handles:
    - Agent registration and deregistration
    - Manifest storage and retrieval
    - Peer discovery and verification
    - Integration with reputation engine
    """
    
    def __init__(self, reputation_engine: Optional[ReputationEngine] = None):
        self.reputation_engine = reputation_engine or ReputationEngine()
        
        # In-memory storage (would be database in production)
        self._manifests: dict[str, AgentManifest] = {}
        self._manifest_hashes: dict[str, str] = {}
        self._did_to_owner: dict[str, str] = {}
        
    async def register(
        self,
        manifest: AgentManifest,
        signature: str,
    ) -> RegistrationResult:
        """
        Register a new agent on Nexus.
        
        Args:
            manifest: Complete agent manifest
            signature: Ed25519 signature from agent's verification key
            
        Returns:
            RegistrationResult with status and initial trust score
        """
        agent_did = manifest.identity.did
        
        # Check if already registered
        if agent_did in self._manifests:
            raise AgentAlreadyRegisteredError(agent_did)
        
        # Validate manifest
        validation_errors = self._validate_manifest(manifest)
        if validation_errors:
            raise InvalidManifestError(agent_did, validation_errors)
        
        # TODO: Verify signature against verification key
        # For now, trust the signature
        
        # Set registration timestamp
        manifest.registered_at = datetime.now(timezone.utc)
        manifest.last_seen = datetime.now(timezone.utc)
        
        # Calculate manifest hash
        manifest_hash = self._compute_manifest_hash(manifest)
        
        # Initialize reputation
        history = ReputationHistory(
            agent_did=agent_did,
            registered_at=manifest.registered_at,
        )
        
        trust_score = self.reputation_engine.calculate_trust_score(
            verification_level=manifest.verification_level,
            history=history,
            capabilities=manifest.capabilities.model_dump(),
            privacy=manifest.privacy.model_dump(),
        )
        
        manifest.trust_score = trust_score.total_score
        
        # Store manifest
        self._manifests[agent_did] = manifest
        self._manifest_hashes[agent_did] = manifest_hash
        self._did_to_owner[agent_did] = manifest.identity.owner_id
        
        # Generate Nexus attestation
        nexus_signature = self._sign_registration(agent_did, manifest_hash)
        
        return RegistrationResult(
            success=True,
            agent_did=agent_did,
            manifest_hash=manifest_hash,
            trust_score=trust_score.total_score,
            registered_at=manifest.registered_at,
            nexus_signature=nexus_signature,
        )
    
    async def update(
        self,
        agent_did: str,
        manifest: AgentManifest,
        signature: str,
    ) -> RegistrationResult:
        """Update an existing agent's manifest."""
        if agent_did not in self._manifests:
            raise AgentNotFoundError(agent_did)
        
        # Validate ownership (DID must match)
        if manifest.identity.did != agent_did:
            raise InvalidManifestError(agent_did, ["DID mismatch"])
        
        # Preserve registration time
        manifest.registered_at = self._manifests[agent_did].registered_at
        manifest.last_seen = datetime.now(timezone.utc)
        
        # Recalculate trust score
        history = self.reputation_engine._get_or_create_history(agent_did)
        trust_score = self.reputation_engine.calculate_trust_score(
            verification_level=manifest.verification_level,
            history=history,
            capabilities=manifest.capabilities.model_dump(),
            privacy=manifest.privacy.model_dump(),
        )
        manifest.trust_score = trust_score.total_score
        
        # Update storage
        manifest_hash = self._compute_manifest_hash(manifest)
        self._manifests[agent_did] = manifest
        self._manifest_hashes[agent_did] = manifest_hash
        
        return RegistrationResult(
            success=True,
            agent_did=agent_did,
            manifest_hash=manifest_hash,
            trust_score=trust_score.total_score,
            registered_at=manifest.registered_at,
            nexus_signature=self._sign_registration(agent_did, manifest_hash),
        )
    
    async def deregister(self, agent_did: str, signature: str) -> bool:
        """Remove an agent from the registry."""
        if agent_did not in self._manifests:
            raise AgentNotFoundError(agent_did)
        
        # TODO: Verify signature
        
        del self._manifests[agent_did]
        del self._manifest_hashes[agent_did]
        del self._did_to_owner[agent_did]
        
        return True
    
    async def get_manifest(self, agent_did: str) -> AgentManifest:
        """Get an agent's manifest by DID."""
        if agent_did not in self._manifests:
            raise AgentNotFoundError(agent_did)
        
        return self._manifests[agent_did]
    
    async def verify_peer(
        self,
        peer_did: str,
        min_score: int = 700,
        required_capabilities: Optional[list[str]] = None,
    ) -> PeerVerification:
        """
        Verify a peer agent before IATP handshake.
        
        This is the core viral mechanism - unverified peers get directed
        to register on Nexus.
        
        Args:
            peer_did: DID of the peer to verify
            min_score: Minimum required trust score
            required_capabilities: Capabilities the peer must have
            
        Returns:
            PeerVerification result
            
        Raises:
            IATPUnverifiedPeerException: If peer is not registered
            IATPInsufficientTrustException: If peer's score is below threshold
        """
        # Check if registered
        if peer_did not in self._manifests:
            raise IATPUnverifiedPeerException(peer_did)
        
        manifest = self._manifests[peer_did]
        
        # Update last seen
        manifest.last_seen = datetime.now(timezone.utc)
        
        # Get trust score
        meets_threshold, trust_score = self.reputation_engine.check_trust_threshold(
            peer_did, min_score
        )
        
        if not meets_threshold:
            raise IATPInsufficientTrustException(
                peer_did,
                current_score=trust_score.total_score,
                required_score=min_score,
            )
        
        # Check capabilities if required
        if required_capabilities:
            missing = set(required_capabilities) - set(manifest.capabilities.domains)
            if missing:
                return PeerVerification(
                    verified=False,
                    peer_did=peer_did,
                    trust_score=trust_score.total_score,
                    trust_tier=trust_score.tier.value,
                    capabilities=manifest.capabilities.domains,
                    rejection_reason=f"Missing capabilities: {missing}",
                )
        
        return PeerVerification(
            verified=True,
            peer_did=peer_did,
            trust_score=trust_score.total_score,
            trust_tier=trust_score.tier.value,
            capabilities=manifest.capabilities.domains,
            privacy_policy=manifest.privacy.retention_policy,
            attestation_valid=manifest.is_attestation_valid(),
            attestation_expires=manifest.attestation_expires,
        )
    
    async def discover_agents(
        self,
        capabilities: Optional[list[str]] = None,
        min_score: int = 500,
        privacy_policy: Optional[str] = None,
        limit: int = 100,
    ) -> list[AgentManifest]:
        """
        Discover agents matching criteria.
        
        Args:
            capabilities: Required capability domains
            min_score: Minimum trust score
            privacy_policy: Required privacy policy (e.g., "ephemeral")
            limit: Maximum results
            
        Returns:
            List of matching agent manifests
        """
        results = []
        
        for agent_did, manifest in self._manifests.items():
            # Filter by trust score
            if manifest.trust_score < min_score:
                continue
            
            # Filter by capabilities
            if capabilities:
                if not all(c in manifest.capabilities.domains for c in capabilities):
                    continue
            
            # Filter by privacy policy
            if privacy_policy:
                if manifest.privacy.retention_policy != privacy_policy:
                    continue
            
            results.append(manifest)
            
            if len(results) >= limit:
                break
        
        # Sort by trust score descending
        results.sort(key=lambda m: m.trust_score, reverse=True)
        
        return results
    
    async def get_reputation_sync(
        self,
        agent_dids: Optional[list[str]] = None,
    ) -> dict[str, int]:
        """
        Get reputation scores for syncing to local cache.
        
        Used by NexusClient.sync_reputation()
        """
        if agent_dids is None:
            return {did: m.trust_score for did, m in self._manifests.items()}
        
        return {
            did: self._manifests[did].trust_score
            for did in agent_dids
            if did in self._manifests
        }
    
    def is_registered(self, agent_did: str) -> bool:
        """Check if an agent is registered."""
        return agent_did in self._manifests
    
    def get_agent_count(self) -> int:
        """Get total number of registered agents."""
        return len(self._manifests)
    
    async def list_by_owner(self, owner_id: str) -> list[AgentManifest]:
        """List all agents owned by an organization."""
        return [
            manifest
            for did, manifest in self._manifests.items()
            if self._did_to_owner.get(did) == owner_id
        ]
    
    def _validate_manifest(self, manifest: AgentManifest) -> list[str]:
        """Validate a manifest and return list of errors."""
        errors = []
        
        # Validate DID format
        if not manifest.identity.did.startswith("did:nexus:"):
            errors.append("DID must start with 'did:nexus:'")
        
        # Validate verification key
        if not manifest.identity.verification_key.startswith("ed25519:"):
            errors.append("Verification key must be Ed25519 format")
        
        # Validate owner ID
        if not manifest.identity.owner_id:
            errors.append("Owner ID is required")
        
        return errors
    
    def _compute_manifest_hash(self, manifest: AgentManifest) -> str:
        """Compute deterministic hash of manifest."""
        # Exclude timestamps for deterministic hashing
        data = manifest.model_dump(exclude={"registered_at", "last_seen", "trust_score"})
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def _sign_registration(self, agent_did: str, manifest_hash: str) -> str:
        """Generate Nexus signature for registration."""
        # In production, this would use Nexus's private key
        # For now, generate a placeholder
        data = f"{agent_did}:{manifest_hash}:{datetime.now(timezone.utc).isoformat()}"
        return f"nexus_sig_{hashlib.sha256(data.encode()).hexdigest()[:32]}"
