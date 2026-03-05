# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus Client

Client for Agent OS agents to interact with Nexus.
Handles registration, peer verification, and reputation sync.
"""

from datetime import datetime, timezone
from typing import Optional, Literal
import asyncio
import aiohttp

from .schemas.manifest import AgentManifest
from .registry import AgentRegistry, RegistrationResult, PeerVerification
from .reputation import ReputationEngine, TrustScore
from .escrow import ProofOfOutcome, EscrowManager
from .arbiter import Arbiter
from .dmz import DMZProtocol, DataHandlingPolicy
from .exceptions import (
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
)


class NexusClient:
    """
    Client for Agent OS agents to interact with Nexus.
    
    Installed in: agent_os.kernel.network
    
    Provides:
    - Agent registration and updates
    - Peer verification before IATP handshake
    - Reputation sync for local cache
    - Escrow/reward management
    - DMZ data transfer
    """
    
    # Default API endpoints
    DEFAULT_API_URL = "https://api.nexus.agent-os.dev/v1"
    DEFAULT_TRUST_THRESHOLD = 700
    
    def __init__(
        self,
        agent_manifest: AgentManifest,
        api_key: str,
        api_url: Optional[str] = None,
        trust_threshold: int = DEFAULT_TRUST_THRESHOLD,
        # For local/testing - use in-memory components
        local_mode: bool = False,
    ):
        self.manifest = agent_manifest
        self.api_key = api_key
        self.base_url = api_url or self.DEFAULT_API_URL
        self.trust_threshold = trust_threshold
        self.local_mode = local_mode
        
        # Local cache of peer reputations
        self._known_peers: dict[str, int] = {}  # DID -> Trust Score
        self._last_sync: Optional[datetime] = None
        
        # For local mode testing
        if local_mode:
            self._local_registry = AgentRegistry()
            self._local_reputation = ReputationEngine()
            self._local_escrow = EscrowManager(self._local_reputation)
            self._local_arbiter = Arbiter(self._local_reputation)
            self._local_dmz = DMZProtocol()
    
    @property
    def agent_did(self) -> str:
        """Get this agent's DID."""
        return self.manifest.identity.did
    
    # ==================== Registration ====================
    
    async def register(self) -> RegistrationResult:
        """
        Register this agent on Nexus.
        
        Returns:
            RegistrationResult with status and initial trust score
        """
        if self.local_mode:
            signature = self._generate_signature(self.manifest.model_dump())
            return await self._local_registry.register(self.manifest, signature)
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/agents",
                json=self.manifest.model_dump(),
                headers=self._headers(),
            ) as resp:
                data = await resp.json()
                return RegistrationResult(**data)
    
    async def update_manifest(self, manifest: AgentManifest) -> RegistrationResult:
        """Update this agent's manifest."""
        self.manifest = manifest
        
        if self.local_mode:
            signature = self._generate_signature(manifest.model_dump())
            return await self._local_registry.update(self.agent_did, manifest, signature)
        
        async with aiohttp.ClientSession() as session:
            async with session.put(
                f"{self.base_url}/agents/{self.agent_did}",
                json=manifest.model_dump(),
                headers=self._headers(),
            ) as resp:
                data = await resp.json()
                return RegistrationResult(**data)
    
    async def deregister(self) -> bool:
        """Remove this agent from Nexus."""
        if self.local_mode:
            signature = self._generate_signature({"did": self.agent_did})
            return await self._local_registry.deregister(self.agent_did, signature)
        
        async with aiohttp.ClientSession() as session:
            async with session.delete(
                f"{self.base_url}/agents/{self.agent_did}",
                headers=self._headers(),
            ) as resp:
                return resp.status == 200
    
    # ==================== Peer Verification ====================
    
    async def verify_peer(
        self,
        peer_did: str,
        min_score: Optional[int] = None,
        required_capabilities: Optional[list[str]] = None,
    ) -> PeerVerification:
        """
        Verify a peer agent before IATP handshake.
        
        This is the core viral mechanism - unverified peers get
        directed to register on Nexus.
        
        Args:
            peer_did: DID of the peer to verify
            min_score: Minimum required trust score (default: trust_threshold)
            required_capabilities: Capabilities the peer must have
            
        Returns:
            PeerVerification result
            
        Raises:
            IATPUnverifiedPeerException: If peer is not registered
            IATPInsufficientTrustException: If peer's score is below threshold
        """
        threshold = min_score or self.trust_threshold
        
        if self.local_mode:
            return await self._local_registry.verify_peer(
                peer_did, threshold, required_capabilities
            )
        
        # Check local cache first
        if peer_did in self._known_peers:
            cached_score = self._known_peers[peer_did]
            if cached_score < threshold:
                raise IATPInsufficientTrustException(
                    peer_did, cached_score, threshold
                )
        
        # Verify with Nexus API
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/agents/{peer_did}/verify",
                params={
                    "min_score": threshold,
                    "capabilities": ",".join(required_capabilities or []),
                },
                headers=self._headers(),
            ) as resp:
                if resp.status == 404:
                    raise IATPUnverifiedPeerException(peer_did)
                
                data = await resp.json()
                
                if data.get("error") == "IATP_INSUFFICIENT_TRUST":
                    raise IATPInsufficientTrustException(
                        peer_did,
                        data["current_score"],
                        data["required_score"],
                    )
                
                # Update cache
                self._known_peers[peer_did] = data.get("trust_score", 0)
                
                return PeerVerification(**data)
    
    async def quick_verify(self, peer_did: str) -> bool:
        """
        Quick check if peer meets trust threshold.
        
        Uses local cache when possible for speed.
        """
        try:
            await self.verify_peer(peer_did)
            return True
        except (IATPUnverifiedPeerException, IATPInsufficientTrustException):
            return False
    
    # ==================== Reputation Sync ====================
    
    async def sync_reputation(
        self,
        force: bool = False,
    ) -> dict[str, int]:
        """
        Sync local known_peers cache with global reputation.
        
        Called periodically by the kernel to keep cache fresh.
        
        Args:
            force: Force sync even if recently synced
            
        Returns:
            Updated mapping of DID -> Trust Score
        """
        # Rate limit syncs (every 5 minutes unless forced)
        if not force and self._last_sync:
            elapsed = (datetime.now(timezone.utc) - self._last_sync).total_seconds()
            if elapsed < 300:  # 5 minutes
                return self._known_peers
        
        if self.local_mode:
            self._known_peers = await self._local_registry.get_reputation_sync()
        else:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/reputation/sync",
                    headers=self._headers(),
                ) as resp:
                    data = await resp.json()
                    self._known_peers = data.get("scores", {})
        
        self._last_sync = datetime.now(timezone.utc)
        return self._known_peers
    
    async def report_outcome(
        self,
        task_id: str,
        peer_did: str,
        outcome: Literal["success", "failure", "dispute"],
    ) -> None:
        """Report task outcome to update reputation."""
        if self.local_mode:
            self._local_reputation.record_task_outcome(peer_did, outcome)
            return
        
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{self.base_url}/reputation/{peer_did}/report",
                json={
                    "task_id": task_id,
                    "reporter_did": self.agent_did,
                    "outcome": outcome,
                },
                headers=self._headers(),
            )
    
    # ==================== Escrow / Proof of Outcome ====================
    
    async def create_escrow(
        self,
        provider_did: str,
        task_hash: str,
        credits: int,
        timeout_seconds: int = 3600,
    ) -> dict:
        """
        Create an escrow for a task.
        
        Args:
            provider_did: DID of the agent providing the service
            task_hash: SHA-256 hash of the task specification
            credits: Number of credits to escrow
            timeout_seconds: Timeout for task completion
        """
        if self.local_mode:
            poo = ProofOfOutcome(self._local_escrow)
            receipt = await poo.create_escrow(
                requester_did=self.agent_did,
                provider_did=provider_did,
                task_hash=task_hash,
                credits=credits,
                timeout_seconds=timeout_seconds,
            )
            return receipt.model_dump()
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/escrow",
                json={
                    "requester_did": self.agent_did,
                    "provider_did": provider_did,
                    "task_hash": task_hash,
                    "credits": credits,
                    "timeout_seconds": timeout_seconds,
                },
                headers=self._headers(),
            ) as resp:
                return await resp.json()
    
    async def release_escrow(
        self,
        escrow_id: str,
        outcome: Literal["success", "failure", "dispute"],
        output_hash: Optional[str] = None,
    ) -> dict:
        """Release an escrow based on outcome."""
        if self.local_mode:
            poo = ProofOfOutcome(self._local_escrow)
            resolution = await poo.release_escrow(
                escrow_id=escrow_id,
                outcome=outcome,
                output_hash=output_hash,
            )
            return {
                "escrow_id": resolution.escrow_id,
                "status": resolution.final_status.value,
                "credits_to_provider": resolution.credits_to_provider,
                "credits_to_requester": resolution.credits_to_requester,
            }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/escrow/{escrow_id}/release",
                json={
                    "outcome": outcome,
                    "output_hash": output_hash,
                },
                headers=self._headers(),
            ) as resp:
                return await resp.json()
    
    # ==================== DMZ Protocol ====================
    
    async def initiate_dmz_transfer(
        self,
        receiver_did: str,
        data: bytes,
        classification: Literal["public", "internal", "confidential", "pii"],
        policy: DataHandlingPolicy,
    ) -> dict:
        """Initiate a secure DMZ transfer."""
        if self.local_mode:
            request = await self._local_dmz.initiate_transfer(
                sender_did=self.agent_did,
                receiver_did=receiver_did,
                data=data,
                classification=classification,
                policy=policy,
            )
            return request.model_dump()
        
        # Would implement API call for remote mode
        raise NotImplementedError("Remote DMZ not yet implemented")
    
    async def sign_dmz_policy(
        self,
        transfer_id: str,
    ) -> dict:
        """Sign a DMZ data handling policy to receive access."""
        if self.local_mode:
            signature = self._generate_signature({"transfer_id": transfer_id})
            signed = await self._local_dmz.sign_policy(
                transfer_id, self.agent_did, signature
            )
            return {
                "policy_hash": signed.policy_hash,
                "signed_at": signed.signed_at.isoformat(),
            }
        
        raise NotImplementedError("Remote DMZ not yet implemented")
    
    async def get_dmz_key(self, transfer_id: str) -> bytes:
        """Get decryption key for a DMZ transfer."""
        if self.local_mode:
            return await self._local_dmz.release_key(transfer_id, self.agent_did)
        
        raise NotImplementedError("Remote DMZ not yet implemented")
    
    # ==================== Discovery ====================
    
    async def discover_agents(
        self,
        capabilities: Optional[list[str]] = None,
        min_score: int = 500,
        privacy_policy: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Discover agents matching criteria."""
        if self.local_mode:
            manifests = await self._local_registry.discover_agents(
                capabilities=capabilities,
                min_score=min_score,
                privacy_policy=privacy_policy,
                limit=limit,
            )
            return [m.model_dump() for m in manifests]
        
        async with aiohttp.ClientSession() as session:
            params = {"min_score": min_score, "limit": limit}
            if capabilities:
                params["capabilities"] = ",".join(capabilities)
            if privacy_policy:
                params["privacy_policy"] = privacy_policy
            
            async with session.get(
                f"{self.base_url}/agents/discover",
                params=params,
                headers=self._headers(),
            ) as resp:
                data = await resp.json()
                return data.get("agents", [])
    
    # ==================== Credits ====================
    
    async def get_credits(self) -> int:
        """Get credit balance."""
        if self.local_mode:
            return self._local_escrow.get_agent_credits(self.agent_did)
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/credits/{self.agent_did}",
                headers=self._headers(),
            ) as resp:
                data = await resp.json()
                return data.get("credits", 0)
    
    # ==================== Internal Helpers ====================
    
    def _headers(self) -> dict:
        """Get API request headers."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Agent-DID": self.agent_did,
            "Content-Type": "application/json",
        }
    
    def _generate_signature(self, data: dict) -> str:
        """Generate signature for data (placeholder)."""
        import hashlib
        import json
        canonical = json.dumps(data, sort_keys=True, default=str)
        return f"sig_{hashlib.sha256(canonical.encode()).hexdigest()[:32]}"
    
    # ==================== Context Manager ====================
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.register()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        # Don't deregister on exit - agent should persist
        pass
