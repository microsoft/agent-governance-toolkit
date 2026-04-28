# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Trust verification for LangChain agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from langchain_agentmesh.identity import CMVKIdentity


@dataclass
class TrustVerificationResult:
    """Result of a trust verification."""
    
    verified: bool
    trust_score: float = 0.0
    peer_did: str = ""
    reason: str = ""
    verified_capabilities: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "trust_score": self.trust_score,
            "peer_did": self.peer_did,
            "reason": self.reason,
            "verified_capabilities": self.verified_capabilities,
            "timestamp": self.timestamp.isoformat(),
        }


class TrustHandshake:
    """Performs trust verification handshakes between agents."""
    
    def __init__(
        self,
        identity: CMVKIdentity,
        cache_ttl_seconds: int = 900,  # 15 minutes default
    ):
        self.identity = identity
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self._verified_peers: Dict[str, Tuple[TrustVerificationResult, datetime]] = {}
    
    def verify_peer(
        self,
        peer_card: Dict[str, Any],
        required_capabilities: Optional[List[str]] = None,
        min_trust_score: float = 0.5,
    ) -> TrustVerificationResult:
        """Verify a peer agent's identity and capabilities."""
        peer_did = peer_card.get("did", "")
        
        # Check cache first
        cached = self._get_cached_result(peer_did)
        if cached is not None:
            return cached
        
        # Verify identity exists
        if not peer_did or not peer_card.get("public_key"):
            return TrustVerificationResult(
                verified=False,
                peer_did=peer_did,
                reason="Missing DID or public key",
            )
        
        # Check capabilities
        peer_capabilities = peer_card.get("capabilities", [])
        if required_capabilities:
            missing = [c for c in required_capabilities if c not in peer_capabilities]
            if missing:
                return TrustVerificationResult(
                    verified=False,
                    peer_did=peer_did,
                    reason=f"Missing capabilities: {missing}",
                )
        
        # Calculate trust score (simplified - in production, use behavioral data)
        trust_score = self._calculate_trust_score(peer_card)
        
        if trust_score < min_trust_score:
            return TrustVerificationResult(
                verified=False,
                trust_score=trust_score,
                peer_did=peer_did,
                reason=f"Trust score {trust_score:.2f} below minimum {min_trust_score}",
            )
        
        # Verification successful
        result = TrustVerificationResult(
            verified=True,
            trust_score=trust_score,
            peer_did=peer_did,
            reason="Verification successful",
            verified_capabilities=peer_capabilities,
        )
        
        # Cache the result
        self._cache_result(peer_did, result)
        
        return result
    
    def _calculate_trust_score(self, peer_card: Dict[str, Any]) -> float:
        """Calculate trust score for a peer (simplified)."""
        score = 0.5  # Base score
        
        # Bonus for having capabilities
        if peer_card.get("capabilities"):
            score += 0.1
        
        # Bonus for having signature
        if peer_card.get("card_signature"):
            score += 0.2
        
        # Bonus for metadata
        if peer_card.get("_agentmesh"):
            mesh_data = peer_card["_agentmesh"]
            if mesh_data.get("trust_score"):
                score = (score + mesh_data["trust_score"]) / 2
        
        return min(1.0, score)
    
    def _get_cached_result(self, peer_did: str) -> Optional[TrustVerificationResult]:
        """Get cached verification result if not expired."""
        if peer_did not in self._verified_peers:
            return None
        
        result, cached_at = self._verified_peers[peer_did]
        if datetime.now(timezone.utc) - cached_at > self.cache_ttl:
            del self._verified_peers[peer_did]
            return None
        
        return result
    
    def _cache_result(self, peer_did: str, result: TrustVerificationResult) -> None:
        """Cache a verification result."""
        self._verified_peers[peer_did] = (result, datetime.now(timezone.utc))
    
    def clear_cache(self) -> None:
        """Clear the verification cache."""
        self._verified_peers.clear()
