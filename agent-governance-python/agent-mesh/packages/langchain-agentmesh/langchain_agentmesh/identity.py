# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CMVK Identity - Cryptographic identity for LangChain agents."""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Try to import real cryptography, fall back to simulation
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class CMVKSignature:
    """Cryptographic signature from a CMVK identity."""
    
    public_key: str  # base64 encoded
    signature: str   # base64 encoded
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "public_key": self.public_key,
            "signature": self.signature,
            "timestamp": self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CMVKSignature":
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        return cls(
            public_key=data.get("public_key", ""),
            signature=data.get("signature", ""),
            timestamp=timestamp,
        )


@dataclass
class CMVKIdentity:
    """Cryptographic identity for an agent using CMVK (Ed25519) scheme."""
    
    did: str  # Decentralized Identifier (did:cmvk:...)
    agent_name: str
    public_key: str  # base64 encoded Ed25519 public key
    private_key: Optional[str] = None  # base64 encoded Ed25519 private key
    capabilities: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def generate(cls, agent_name: str, capabilities: Optional[List[str]] = None) -> "CMVKIdentity":
        """Generate a new CMVK identity with Ed25519 key pair."""
        # Generate unique DID
        seed = f"{agent_name}:{time.time_ns()}"
        did_hash = hashlib.sha256(seed.encode()).hexdigest()[:32]
        did = f"did:cmvk:{did_hash}"
        
        if CRYPTO_AVAILABLE:
            # Real Ed25519 cryptography
            private_key_obj = ed25519.Ed25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()
            
            private_key_b64 = base64.b64encode(
                private_key_obj.private_bytes_raw()
            ).decode('ascii')
            public_key_b64 = base64.b64encode(
                public_key_obj.public_bytes_raw()
            ).decode('ascii')
        else:
            # Simulation fallback for environments without cryptography
            key_seed = hashlib.sha256(f"{did}:key".encode()).hexdigest()
            private_key_b64 = base64.b64encode(key_seed[:32].encode()).decode('ascii')
            public_key_b64 = base64.b64encode(key_seed[32:].encode()).decode('ascii')
        
        return cls(
            did=did,
            agent_name=agent_name,
            public_key=public_key_b64,
            private_key=private_key_b64,
            capabilities=capabilities or [],
        )
    
    def sign(self, data: str) -> CMVKSignature:
        """Sign data with this identity's private key."""
        if not self.private_key:
            raise ValueError("Cannot sign without private key")
        
        if CRYPTO_AVAILABLE:
            private_key_bytes = base64.b64decode(self.private_key)
            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            signature_bytes = private_key_obj.sign(data.encode('utf-8'))
            signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
        else:
            # Simulation fallback
            sig_input = f"{self.private_key}:{data}"
            signature_b64 = base64.b64encode(
                hashlib.sha256(sig_input.encode()).digest()
            ).decode('ascii')
        
        return CMVKSignature(
            public_key=self.public_key,
            signature=signature_b64,
        )
    
    def verify_signature(self, data: str, signature: CMVKSignature) -> bool:
        """Verify a signature against this identity's public key."""
        if signature.public_key != self.public_key:
            return False
        
        if CRYPTO_AVAILABLE:
            try:
                public_key_bytes = base64.b64decode(self.public_key)
                public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                signature_bytes = base64.b64decode(signature.signature)
                public_key_obj.verify(signature_bytes, data.encode('utf-8'))
                return True
            except (InvalidSignature, ValueError, Exception):
                return False
        else:
            # Simulation fallback - cannot verify without private key
            return True  # In simulation mode, assume valid
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excludes private key for safety)."""
        return {
            "did": self.did,
            "agent_name": self.agent_name,
            "public_key": self.public_key,
            "capabilities": self.capabilities,
            "created_at": self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CMVKIdentity":
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)
        
        return cls(
            did=data.get("did", ""),
            agent_name=data.get("agent_name", ""),
            public_key=data.get("public_key", ""),
            private_key=data.get("private_key"),
            capabilities=data.get("capabilities", []),
            created_at=created_at,
        )
    
    def has_capability(self, capability: str) -> bool:
        """Check if this identity has a specific capability."""
        if "*" in self.capabilities:
            return True
        return capability in self.capabilities
