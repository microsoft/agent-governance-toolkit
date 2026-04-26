# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Job Receipt Schemas

Defines receipts for job completion and outcome verification.
"""

from datetime import datetime
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field
import hashlib
import json


class JobReceipt(BaseModel):
    """Base receipt for a job/task between agents."""
    
    receipt_id: str = Field(
        ...,
        description="Unique receipt identifier"
    )
    task_id: str = Field(
        ...,
        description="ID of the task being receipted"
    )
    requester_did: str = Field(
        ...,
        description="DID of the requesting agent"
    )
    provider_did: str = Field(
        ...,
        description="DID of the providing agent"
    )
    task_hash: str = Field(
        ...,
        description="SHA-256 hash of the task specification"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the receipt was created"
    )
    
    def compute_hash(self) -> str:
        """Compute deterministic hash of receipt."""
        data = {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "requester_did": self.requester_did,
            "provider_did": self.provider_did,
            "task_hash": self.task_hash,
            "created_at": self.created_at.isoformat(),
        }
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()


class JobCompletionReceipt(JobReceipt):
    """Receipt issued when a job is completed."""
    
    outcome: Literal["success", "failure", "partial", "timeout"] = Field(
        ...,
        description="Outcome of the job"
    )
    completed_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the job completed"
    )
    duration_ms: int = Field(
        ...,
        ge=0,
        description="Duration of job execution in milliseconds"
    )
    output_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of the output (if any)"
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Error code if outcome is failure"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if outcome is failure"
    )
    
    # SCAK validation
    scak_validated: bool = Field(
        default=False,
        description="Whether output was validated by SCAK"
    )
    scak_drift_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="SCAK drift score (0=no drift, 1=complete drift)"
    )
    scak_threshold: Optional[float] = Field(
        default=None,
        description="Drift threshold used for validation"
    )


class SignedReceipt(BaseModel):
    """A receipt with cryptographic signatures from both parties."""
    
    receipt: JobCompletionReceipt
    receipt_hash: str = Field(
        ...,
        description="SHA-256 hash of the receipt"
    )
    
    # Signatures
    requester_signature: Optional[str] = Field(
        default=None,
        description="Ed25519 signature from requester"
    )
    requester_signed_at: Optional[datetime] = Field(
        default=None,
        description="When requester signed"
    )
    provider_signature: Optional[str] = Field(
        default=None,
        description="Ed25519 signature from provider"
    )
    provider_signed_at: Optional[datetime] = Field(
        default=None,
        description="When provider signed"
    )
    
    # Nexus attestation
    nexus_witnessed: bool = Field(
        default=False,
        description="Whether Nexus has witnessed this receipt"
    )
    nexus_signature: Optional[str] = Field(
        default=None,
        description="Nexus signature witnessing the receipt"
    )
    nexus_witnessed_at: Optional[datetime] = Field(
        default=None,
        description="When Nexus witnessed"
    )
    
    def is_fully_signed(self) -> bool:
        """Check if both parties have signed."""
        return bool(self.requester_signature and self.provider_signature)
    
    def is_nexus_witnessed(self) -> bool:
        """Check if Nexus has witnessed this receipt."""
        return self.nexus_witnessed and bool(self.nexus_signature)


class DisputeReceipt(BaseModel):
    """Receipt for a disputed job outcome."""
    
    dispute_id: str = Field(
        ...,
        description="Unique dispute identifier"
    )
    original_receipt: Optional[SignedReceipt] = None
    
    # Dispute details
    disputing_party: Literal["requester", "provider"] = Field(
        ...,
        description="Which party raised the dispute"
    )
    dispute_reason: str = Field(
        ...,
        description="Reason for the dispute"
    )
    claimed_outcome: Literal["success", "failure", "partial"] = Field(
        ...,
        description="Outcome claimed by disputing party"
    )
    
    # Evidence
    requester_logs_hash: Optional[str] = Field(
        default=None,
        description="Hash of requester's flight recorder logs"
    )
    provider_logs_hash: Optional[str] = Field(
        default=None,
        description="Hash of provider's flight recorder logs"
    )
    
    # Resolution
    resolved: bool = Field(
        default=False,
        description="Whether dispute has been resolved"
    )
    resolution_outcome: Optional[Literal["requester_wins", "provider_wins", "split"]] = Field(
        default=None,
        description="Resolution outcome"
    )
    arbiter_decision: Optional[str] = Field(
        default=None,
        description="Arbiter's decision explanation"
    )
    resolved_at: Optional[datetime] = Field(
        default=None,
        description="When dispute was resolved"
    )
    
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When dispute was raised"
    )
