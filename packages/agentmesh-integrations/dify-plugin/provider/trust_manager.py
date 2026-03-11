"""Trust management for Dify plugin."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import threading
from typing import Any
import logging

from .identity import VerificationIdentity, capability_matches

logger = logging.getLogger(__name__)


@dataclass
class TrustVerificationResult:
    """Result of trust verification."""
    
    verified: bool
    trust_score: float = 0.0
    peer_did: str = ""
    reason: str = ""
    verified_capabilities: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "trust_score": self.trust_score,
            "peer_did": self.peer_did,
            "reason": self.reason,
            "verified_capabilities": self.verified_capabilities,
            "timestamp": self.timestamp.isoformat(),
        }


class TrustManager:
    """Manages trust verification. Thread-safe."""
    
    def __init__(
        self,
        identity: VerificationIdentity | None = None,
        cache_ttl_seconds: int = 900,
        min_trust_score: float = 0.5,
    ):
        self.identity = identity
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.min_trust_score = min_trust_score
        self._verified_peers: dict[str, tuple[TrustVerificationResult, datetime]] = {}
        self._trust_scores: dict[str, float] = {}
        self._lock = threading.Lock()
        self._audit_log: list[dict[str, Any]] = []
    
    def set_identity(self, identity: VerificationIdentity) -> None:
        """Set or update the local identity."""
        self.identity = identity
        logger.info("Trust identity set: %s", identity.did)
    
    def verify_peer(
        self,
        peer_did: str,
        peer_public_key: str,
        required_capabilities: list[str] | None = None,
        peer_capabilities: list[str] | None = None,
    ) -> TrustVerificationResult:
        """Verify a peer agent's identity and capabilities."""
        peer_caps = peer_capabilities or []
        if required_capabilities:
            missing = []
            for req_cap in required_capabilities:
                if not self._peer_has_capability(peer_caps, req_cap):
                    missing.append(req_cap)
            if missing:
                return self._fail("Missing capabilities: %s" % missing, peer_did)
        
        cached = self._get_cached(peer_did, peer_public_key)
        if cached is not None:
            return cached
        
        if not peer_did or not peer_public_key:
            return self._fail("Missing DID or public key", peer_did)
        
        trust_score = self._calculate_trust_score(peer_did, peer_public_key)
        
        if trust_score < self.min_trust_score:
            return self._fail(
                "Trust score %.2f below minimum %.2f" % (trust_score, self.min_trust_score),
                peer_did,
                trust_score=trust_score
            )
        
        result = TrustVerificationResult(
            verified=True,
            trust_score=trust_score,
            peer_did=peer_did,
            reason="Verification successful",
            verified_capabilities=peer_capabilities or [],
        )
        
        self._cache(peer_did, peer_public_key, result)
        self._log_audit("verify_peer", peer_did, True, trust_score)
        
        return result
    
    def verify_workflow_step(
        self,
        workflow_id: str,
        step_id: str,
        step_type: str,
        required_capability: str | None = None,
    ) -> TrustVerificationResult:
        """Verify trust for a workflow step execution."""
        if not self.identity:
            return self._fail("No identity configured", "%s:%s" % (workflow_id, step_id))
        
        capability = required_capability or "workflow:%s" % step_type
        if not self.identity.has_capability(capability) and not self.identity.has_capability("*"):
            return self._fail(
                "Missing capability: %s" % capability,
                "%s:%s" % (workflow_id, step_id)
            )
        
        with self._lock:
            trust_score = self._trust_scores.get(self.identity.did, 0.7)
        
        result = TrustVerificationResult(
            verified=True,
            trust_score=trust_score,
            peer_did=self.identity.did,
            reason="Step %s authorized" % step_type,
            verified_capabilities=[capability],
        )
        
        self._log_audit("verify_step", "%s:%s" % (workflow_id, step_id), True, trust_score)
        return result
    
    def record_success(self, did: str) -> None:
        """Record successful interaction, increasing trust."""
        with self._lock:
            current = self._trust_scores.get(did, 0.5)
            self._trust_scores[did] = min(1.0, current + 0.01)
            self._log_audit("record_success", did, True, self._trust_scores[did])
    
    def record_failure(self, did: str, severity: float = 0.1) -> None:
        """Record failed interaction, decreasing trust."""
        with self._lock:
            current = self._trust_scores.get(did, 0.5)
            self._trust_scores[did] = max(0.0, current - severity)
            self._log_audit("record_failure", did, False, self._trust_scores[did])
    
    def get_trust_score(self, did: str) -> float:
        """Get current trust score for a DID."""
        with self._lock:
            return self._trust_scores.get(did, 0.5)
    
    def get_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent audit log entries."""
        with self._lock:
            return self._audit_log[-limit:]
    
    def clear_cache(self) -> None:
        """Clear verification cache."""
        with self._lock:
            self._verified_peers.clear()
    
    def _peer_has_capability(self, peer_caps: list[str], required: str) -> bool:
        """Check if peer has a required capability (supports wildcards)."""
        for cap in peer_caps:
            if capability_matches(cap, required):
                return True
        return False
    
    def _calculate_trust_score(self, peer_did: str, peer_public_key: str) -> float:
        """Calculate trust score for a peer."""
        with self._lock:
            if peer_did in self._trust_scores:
                return self._trust_scores[peer_did]
            
            score = 0.5
            if peer_public_key:
                score += 0.1
            
            self._trust_scores[peer_did] = score
            return score
    
    def _get_cached(self, peer_did: str, peer_public_key: str) -> TrustVerificationResult | None:
        """Get cached result if valid."""
        cache_key = "%s:%s" % (peer_did, peer_public_key[:32] if peer_public_key else "")
        with self._lock:
            if cache_key not in self._verified_peers:
                return None
            
            result, cached_at = self._verified_peers[cache_key]
            if datetime.now(timezone.utc) - cached_at > self.cache_ttl:
                del self._verified_peers[cache_key]
                return None
            
            return result
    
    def _cache(self, peer_did: str, peer_public_key: str, result: TrustVerificationResult) -> None:
        """Cache a verification result."""
        cache_key = "%s:%s" % (peer_did, peer_public_key[:32] if peer_public_key else "")
        with self._lock:
            self._verified_peers[cache_key] = (result, datetime.now(timezone.utc))
    
    def _fail(
        self,
        reason: str,
        peer_did: str,
        trust_score: float = 0.0
    ) -> TrustVerificationResult:
        """Create a failed verification result."""
        result = TrustVerificationResult(
            verified=False,
            trust_score=trust_score,
            peer_did=peer_did,
            reason=reason,
        )
        self._log_audit("verify_fail", peer_did, False, trust_score, reason)
        return result
    
    def _log_audit(
        self,
        action: str,
        target: str,
        success: bool,
        trust_score: float,
        reason: str = ""
    ) -> None:
        """Log an audit entry (thread-safe)."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "success": success,
            "trust_score": trust_score,
            "reason": reason,
            "identity_did": self.identity.did if self.identity else None,
        }
        
        with self._lock:
            self._audit_log.append(entry)
            if len(self._audit_log) > 10000:
                self._audit_log = self._audit_log[-5000:]
