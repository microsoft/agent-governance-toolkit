# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Escrow Schemas

Defines data structures for the Proof-of-Outcome escrow system.
"""

from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from pydantic import BaseModel, Field
from enum import Enum


class EscrowStatus(str, Enum):
    """Status of an escrow."""
    PENDING = "pending"           # Created, awaiting task start
    ACTIVE = "active"             # Task in progress
    AWAITING_VALIDATION = "awaiting_validation"  # Task done, awaiting SCAK
    RELEASED = "released"         # Credits released to provider
    REFUNDED = "refunded"         # Credits returned to requester
    DISPUTED = "disputed"         # Under dispute resolution
    EXPIRED = "expired"           # Timed out without completion
    CANCELLED = "cancelled"       # Cancelled by requester before start


class EscrowRequest(BaseModel):
    """Request to create an escrow for a task."""
    
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
    task_description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Brief description of the task (for logging only)"
    )
    credits: int = Field(
        ...,
        gt=0,
        le=10000,
        description="Number of credits to escrow"
    )
    timeout_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Timeout for task completion (1 min to 24 hours)"
    )
    
    # Validation requirements
    require_scak_validation: bool = Field(
        default=True,
        description="Whether SCAK validation is required for release"
    )
    scak_drift_threshold: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description="Maximum allowed SCAK drift score"
    )
    
    # Data handling
    data_classification: Literal["public", "internal", "confidential", "pii"] = Field(
        default="internal",
        description="Classification of data being shared"
    )


class EscrowReceipt(BaseModel):
    """Receipt confirming escrow creation."""
    
    escrow_id: str = Field(
        ...,
        description="Unique escrow identifier"
    )
    request: EscrowRequest
    status: EscrowStatus = Field(
        default=EscrowStatus.PENDING,
        description="Current escrow status"
    )
    
    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When escrow was created"
    )
    expires_at: datetime = Field(
        ...,
        description="When escrow expires if not completed"
    )
    activated_at: Optional[datetime] = Field(
        default=None,
        description="When task execution started"
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="When task was marked complete"
    )
    resolved_at: Optional[datetime] = Field(
        default=None,
        description="When escrow was resolved (released/refunded)"
    )
    
    # Signatures
    requester_signature: str = Field(
        ...,
        description="Requester's signature confirming escrow"
    )
    nexus_signature: Optional[str] = Field(
        default=None,
        description="Nexus signature confirming escrow hold"
    )
    
    def is_expired(self) -> bool:
        """Check if escrow has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_active(self) -> bool:
        """Check if escrow is in an active state."""
        return self.status in (EscrowStatus.PENDING, EscrowStatus.ACTIVE, EscrowStatus.AWAITING_VALIDATION)
    
    @classmethod
    def from_request(cls, escrow_id: str, request: EscrowRequest, requester_signature: str) -> "EscrowReceipt":
        """Create receipt from request."""
        now = datetime.now(timezone.utc)
        return cls(
            escrow_id=escrow_id,
            request=request,
            created_at=now,
            expires_at=now + timedelta(seconds=request.timeout_seconds),
            requester_signature=requester_signature,
        )


class EscrowRelease(BaseModel):
    """Request to release an escrow."""
    
    escrow_id: str = Field(
        ...,
        description="ID of the escrow to release"
    )
    outcome: Literal["success", "failure", "dispute"] = Field(
        ...,
        description="Outcome determining how to release"
    )
    
    # Completion details
    output_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of the task output"
    )
    duration_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="Task duration in milliseconds"
    )
    
    # SCAK validation results
    scak_validated: bool = Field(
        default=False,
        description="Whether SCAK validation was performed"
    )
    scak_drift_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="SCAK drift score"
    )
    scak_passed: Optional[bool] = Field(
        default=None,
        description="Whether SCAK validation passed"
    )
    
    # Signatures
    provider_signature: Optional[str] = Field(
        default=None,
        description="Provider's signature on completion"
    )
    requester_signature: Optional[str] = Field(
        default=None,
        description="Requester's signature accepting outcome"
    )
    
    # For disputes
    dispute_reason: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Reason for dispute (if outcome is dispute)"
    )
    flight_recorder_logs_hash: Optional[str] = Field(
        default=None,
        description="Hash of flight recorder logs for dispute"
    )


class EscrowResolution(BaseModel):
    """Final resolution of an escrow."""
    
    escrow_id: str
    final_status: EscrowStatus
    
    # Credit distribution
    credits_to_provider: int = Field(
        default=0,
        ge=0,
        description="Credits released to provider"
    )
    credits_to_requester: int = Field(
        default=0,
        ge=0,
        description="Credits refunded to requester"
    )
    
    # Reputation impact
    provider_reputation_change: int = Field(
        default=0,
        description="Change to provider's reputation score"
    )
    requester_reputation_change: int = Field(
        default=0,
        description="Change to requester's reputation score"
    )
    
    # Resolution details
    resolution_reason: str = Field(
        ...,
        description="Reason for this resolution"
    )
    resolved_by: Literal["automatic", "requester", "provider", "arbiter", "timeout"] = Field(
        ...,
        description="How resolution was triggered"
    )
    resolved_at: datetime = Field(
        default_factory=datetime.utcnow
    )
    
    # Nexus attestation
    nexus_signature: str = Field(
        ...,
        description="Nexus signature on resolution"
    )
