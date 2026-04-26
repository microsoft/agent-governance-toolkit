# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
DMZ Protocol

Extension of IATP for secure data handoff between agents.
Implements the REQUEST_ESCROW verb and data handling policies.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from pydantic import BaseModel, Field
import hashlib
import uuid
from dataclasses import dataclass, field


class DataHandlingPolicy(BaseModel):
    """
    Policy that receiving agent must sign before getting decryption key.
    
    Ensures data handling compliance between agents.
    """
    
    policy_id: str = Field(
        default_factory=lambda: f"policy_{uuid.uuid4().hex[:12]}"
    )
    
    # Retention
    max_retention_seconds: int = Field(
        default=3600,
        ge=0,
        le=2592000,  # 30 days max
        description="Maximum time to retain data (0 = process and delete)"
    )
    
    # Permissions
    allow_persistence: bool = Field(
        default=False,
        description="Whether data can be persisted to storage"
    )
    allow_training: bool = Field(
        default=False,
        description="Whether data can be used for model training"
    )
    allow_forwarding: bool = Field(
        default=False,
        description="Whether data can be forwarded to other agents"
    )
    allow_logging: bool = Field(
        default=True,
        description="Whether metadata can be logged (not content)"
    )
    
    # Audit
    audit_required: bool = Field(
        default=True,
        description="Whether all data access must be audited"
    )
    
    # Encryption
    require_encryption_at_rest: bool = Field(
        default=True,
        description="Whether data must be encrypted when stored"
    )
    
    def compute_hash(self) -> str:
        """Compute deterministic policy hash."""
        data = self.model_dump(exclude={"policy_id"})
        import json
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()


class DMZRequest(BaseModel):
    """Request to share data through the secure DMZ."""
    
    verb: Literal["REQUEST_ESCROW"] = "REQUEST_ESCROW"
    request_id: str = Field(
        default_factory=lambda: f"dmz_{uuid.uuid4().hex[:16]}"
    )
    
    # Parties
    sender_did: str
    receiver_did: str
    
    # Data (only hash, not actual content)
    data_hash: str = Field(
        ...,
        description="SHA-256 hash of the actual data"
    )
    data_size_bytes: int = Field(
        ...,
        ge=0,
        description="Size of the data in bytes"
    )
    data_classification: Literal["public", "internal", "confidential", "pii"] = Field(
        default="internal",
        description="Classification level of the data"
    )
    
    # Policy
    required_policy: DataHandlingPolicy
    
    # Encryption
    encrypted_data_location: Optional[str] = Field(
        default=None,
        description="URL/URI where encrypted data is stored"
    )
    encryption_algorithm: str = Field(
        default="AES-256-GCM",
        description="Encryption algorithm used"
    )
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(
        default=None,
        description="When this request expires"
    )


@dataclass
class SignedPolicy:
    """A policy that has been signed by the receiving agent."""
    
    policy: DataHandlingPolicy
    policy_hash: str
    
    # Signer
    signer_did: str
    signed_at: datetime = field(default_factory=datetime.utcnow)
    
    # Signature
    signature: str = ""
    
    # Verification
    verified: bool = False
    verified_at: Optional[datetime] = None


@dataclass
class DMZTransfer:
    """Record of a DMZ data transfer."""
    
    transfer_id: str
    request: DMZRequest
    
    # Policy signing
    policy_signed: bool = False
    signed_policy: Optional[SignedPolicy] = None
    
    # Key release
    key_released: bool = False
    key_released_at: Optional[datetime] = None
    
    # Data access
    data_accessed: bool = False
    data_accessed_at: Optional[datetime] = None
    
    # Completion
    completed: bool = False
    completed_at: Optional[datetime] = None
    
    # Audit
    audit_trail: list[dict] = field(default_factory=list)


class DMZProtocol:
    """
    Implements the DMZ (Demilitarized Zone) protocol for secure data sharing.
    
    Flow:
    1. Agent A sends REQUEST_ESCROW with data hash to Nexus
    2. Nexus holds the encrypted data reference
    3. Agent B signs the DataHandlingPolicy
    4. Nexus releases decryption key to Agent B
    5. All operations are logged for compliance
    """
    
    def __init__(self):
        # Storage
        self._transfers: dict[str, DMZTransfer] = {}
        self._signed_policies: dict[str, SignedPolicy] = {}
        self._encryption_keys: dict[str, bytes] = {}  # transfer_id -> key
    
    async def initiate_transfer(
        self,
        sender_did: str,
        receiver_did: str,
        data: bytes,
        classification: Literal["public", "internal", "confidential", "pii"],
        policy: DataHandlingPolicy,
        expiry_hours: int = 24,
    ) -> DMZRequest:
        """
        Initiate a secure data transfer through DMZ.
        
        Args:
            sender_did: DID of sending agent
            receiver_did: DID of receiving agent
            data: The actual data to transfer (will be encrypted)
            classification: Data classification level
            policy: Required data handling policy
            expiry_hours: Hours until request expires
        """
        # Compute data hash
        data_hash = hashlib.sha256(data).hexdigest()
        
        # Generate encryption key
        import secrets
        encryption_key = secrets.token_bytes(32)  # AES-256
        
        # Encrypt data (placeholder - would use proper encryption)
        encrypted_data = self._encrypt_data(data, encryption_key)
        
        # Create request
        request = DMZRequest(
            sender_did=sender_did,
            receiver_did=receiver_did,
            data_hash=data_hash,
            data_size_bytes=len(data),
            data_classification=classification,
            required_policy=policy,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
        )
        
        # Create transfer record
        transfer = DMZTransfer(
            transfer_id=request.request_id,
            request=request,
        )
        
        # Store
        self._transfers[request.request_id] = transfer
        self._encryption_keys[request.request_id] = encryption_key
        
        # Add audit entry
        transfer.audit_trail.append({
            "event": "transfer_initiated",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sender": sender_did,
            "receiver": receiver_did,
            "data_hash": data_hash,
        })
        
        return request
    
    async def sign_policy(
        self,
        transfer_id: str,
        signer_did: str,
        signature: str,
    ) -> SignedPolicy:
        """
        Sign a data handling policy to receive access.
        
        The receiving agent must sign the policy before getting
        the decryption key.
        """
        if transfer_id not in self._transfers:
            raise ValueError(f"Transfer not found: {transfer_id}")
        
        transfer = self._transfers[transfer_id]
        request = transfer.request
        
        # Verify signer is the intended receiver
        if signer_did != request.receiver_did:
            raise ValueError("Only intended receiver can sign policy")
        
        # Verify transfer hasn't expired
        if request.expires_at and datetime.now(timezone.utc) > request.expires_at:
            raise ValueError("Transfer has expired")
        
        # Create signed policy
        signed = SignedPolicy(
            policy=request.required_policy,
            policy_hash=request.required_policy.compute_hash(),
            signer_did=signer_did,
            signature=signature,
            verified=True,  # Would verify signature in production
            verified_at=datetime.now(timezone.utc),
        )
        
        # Update transfer
        transfer.policy_signed = True
        transfer.signed_policy = signed
        
        # Add audit entry
        transfer.audit_trail.append({
            "event": "policy_signed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signer": signer_did,
            "policy_hash": signed.policy_hash,
        })
        
        # Store signed policy
        self._signed_policies[f"{transfer_id}:{signer_did}"] = signed
        
        return signed
    
    async def release_key(
        self,
        transfer_id: str,
        requester_did: str,
    ) -> bytes:
        """
        Release decryption key after policy is signed.
        
        Only releases key if:
        1. Requester is the intended receiver
        2. Policy has been signed
        3. Transfer hasn't expired
        """
        if transfer_id not in self._transfers:
            raise ValueError(f"Transfer not found: {transfer_id}")
        
        transfer = self._transfers[transfer_id]
        request = transfer.request
        
        # Verify requester
        if requester_did != request.receiver_did:
            raise ValueError("Only intended receiver can get key")
        
        # Verify policy signed
        if not transfer.policy_signed:
            raise ValueError("Policy must be signed before key release")
        
        # Verify not expired
        if request.expires_at and datetime.now(timezone.utc) > request.expires_at:
            raise ValueError("Transfer has expired")
        
        # Get key
        if transfer_id not in self._encryption_keys:
            raise ValueError("Encryption key not found")
        
        key = self._encryption_keys[transfer_id]
        
        # Update transfer
        transfer.key_released = True
        transfer.key_released_at = datetime.now(timezone.utc)
        
        # Add audit entry
        transfer.audit_trail.append({
            "event": "key_released",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "recipient": requester_did,
        })
        
        return key
    
    async def record_data_access(
        self,
        transfer_id: str,
        accessor_did: str,
    ) -> None:
        """Record that data was accessed (for audit)."""
        if transfer_id not in self._transfers:
            raise ValueError(f"Transfer not found: {transfer_id}")
        
        transfer = self._transfers[transfer_id]
        transfer.data_accessed = True
        transfer.data_accessed_at = datetime.now(timezone.utc)
        
        transfer.audit_trail.append({
            "event": "data_accessed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "accessor": accessor_did,
        })
    
    async def complete_transfer(
        self,
        transfer_id: str,
    ) -> DMZTransfer:
        """Mark transfer as complete."""
        if transfer_id not in self._transfers:
            raise ValueError(f"Transfer not found: {transfer_id}")
        
        transfer = self._transfers[transfer_id]
        transfer.completed = True
        transfer.completed_at = datetime.now(timezone.utc)
        
        transfer.audit_trail.append({
            "event": "transfer_completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        
        # Clean up key (data should be deleted per policy)
        if transfer_id in self._encryption_keys:
            del self._encryption_keys[transfer_id]
        
        return transfer
    
    def get_transfer(self, transfer_id: str) -> DMZTransfer:
        """Get transfer by ID."""
        if transfer_id not in self._transfers:
            raise ValueError(f"Transfer not found: {transfer_id}")
        return self._transfers[transfer_id]
    
    def get_audit_trail(self, transfer_id: str) -> list[dict]:
        """Get audit trail for a transfer."""
        transfer = self.get_transfer(transfer_id)
        return transfer.audit_trail
    
    def has_signed_policy(self, transfer_id: str, agent_did: str) -> bool:
        """Check if agent has signed policy for a transfer."""
        key = f"{transfer_id}:{agent_did}"
        return key in self._signed_policies
    
    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data with AES-256-GCM.

        Requires the ``cryptography`` package (``pip install cryptography``).
        Falls back to a clearly-marked no-op if not installed.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "DMZ encryption requires the 'cryptography' package. "
                "Install with: pip install cryptography"
            )

        # Derive a 256-bit key via SHA-256 to ensure correct length
        derived = hashlib.sha256(key).digest()
        nonce = hashlib.sha256(data[:16] + key).digest()[:12]  # 96-bit nonce
        aesgcm = AESGCM(derived)
        return nonce + aesgcm.encrypt(nonce, data, None)

    def _decrypt_data(self, encrypted: bytes, key: bytes) -> bytes:
        """Decrypt data encrypted with AES-256-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "DMZ decryption requires the 'cryptography' package. "
                "Install with: pip install cryptography"
            )

        derived = hashlib.sha256(key).digest()
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        aesgcm = AESGCM(derived)
        return aesgcm.decrypt(nonce, ciphertext, None)
