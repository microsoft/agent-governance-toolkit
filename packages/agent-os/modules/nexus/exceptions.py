# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus Exceptions

Custom exceptions for the Nexus Trust Exchange.
These exceptions drive the viral loop by directing unverified agents to register.
"""

from typing import Optional


class NexusError(Exception):
    """Base exception for all Nexus errors."""
    
    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code or "NEXUS_ERROR"
        super().__init__(f"[{self.code}] {message}")


class IATPUnverifiedPeerException(NexusError):
    """
    Raised when a peer agent is not registered on Nexus.
    
    This is THE viral mechanism - the error message includes a registration URL,
    driving unverified agents to register on Nexus to communicate.
    """
    
    REGISTRATION_BASE_URL = "https://nexus.agent-os.dev/register"
    
    def __init__(self, peer_id: str, peer_address: Optional[str] = None):
        self.peer_id = peer_id
        self.peer_address = peer_address
        self.registration_url = f"{self.REGISTRATION_BASE_URL}?agent={peer_id}"
        
        message = (
            f"Agent identity unknown: '{peer_id}' is not registered on Nexus. "
            f"To establish an IATP handshake, the agent must register at: {self.registration_url}"
        )
        super().__init__(message, code="IATP_UNVERIFIED_PEER")
    
    def to_iatp_error(self) -> dict:
        """Convert to IATP error response format."""
        return {
            "error": "IATP_UNVERIFIED_PEER",
            "message": self.message,
            "peer_id": self.peer_id,
            "registration_url": self.registration_url,
            "action_required": "Register the agent on Nexus to enable communication",
        }


class IATPInsufficientTrustException(NexusError):
    """
    Raised when a peer's trust score is below the required threshold.
    
    Drives agents to improve their reputation through successful task completion.
    """
    
    def __init__(
        self, 
        peer_did: str, 
        current_score: int, 
        required_score: int,
        improvement_url: Optional[str] = None
    ):
        self.peer_did = peer_did
        self.current_score = current_score
        self.required_score = required_score
        self.improvement_url = improvement_url or f"https://nexus.agent-os.dev/reputation/{peer_did}"
        self.score_gap = required_score - current_score
        
        message = (
            f"Insufficient trust score for agent '{peer_did}': "
            f"current={current_score}, required={required_score} (gap: {self.score_gap}). "
            f"Improve reputation at: {self.improvement_url}"
        )
        super().__init__(message, code="IATP_INSUFFICIENT_TRUST")
    
    def to_iatp_error(self) -> dict:
        """Convert to IATP error response format."""
        return {
            "error": "IATP_INSUFFICIENT_TRUST",
            "message": self.message,
            "peer_did": self.peer_did,
            "current_score": self.current_score,
            "required_score": self.required_score,
            "score_gap": self.score_gap,
            "improvement_url": self.improvement_url,
            "action_required": "Complete tasks successfully to improve reputation",
        }


class IATPAttestationExpiredException(NexusError):
    """Raised when a peer's attestation has expired."""
    
    def __init__(self, peer_did: str, expired_at: str):
        self.peer_did = peer_did
        self.expired_at = expired_at
        
        message = (
            f"Attestation expired for agent '{peer_did}' at {expired_at}. "
            f"Agent must renew attestation with Control Plane."
        )
        super().__init__(message, code="IATP_ATTESTATION_EXPIRED")


class IATPPolicyViolationException(NexusError):
    """Raised when a peer's policies don't meet requirements."""
    
    def __init__(self, peer_did: str, violation: str, required_policy: str):
        self.peer_did = peer_did
        self.violation = violation
        self.required_policy = required_policy
        
        message = (
            f"Policy violation for agent '{peer_did}': {violation}. "
            f"Required policy: {required_policy}"
        )
        super().__init__(message, code="IATP_POLICY_VIOLATION")


class EscrowError(NexusError):
    """Base exception for escrow-related errors."""
    
    def __init__(self, message: str, escrow_id: Optional[str] = None):
        self.escrow_id = escrow_id
        super().__init__(message, code="ESCROW_ERROR")


class EscrowNotFoundError(EscrowError):
    """Raised when an escrow cannot be found."""
    
    def __init__(self, escrow_id: str):
        super().__init__(f"Escrow not found: {escrow_id}", escrow_id=escrow_id)
        self.code = "ESCROW_NOT_FOUND"


class EscrowExpiredError(EscrowError):
    """Raised when attempting to operate on an expired escrow."""
    
    def __init__(self, escrow_id: str, expired_at: str):
        self.expired_at = expired_at
        super().__init__(
            f"Escrow {escrow_id} expired at {expired_at}",
            escrow_id=escrow_id
        )
        self.code = "ESCROW_EXPIRED"


class EscrowAlreadyResolvedError(EscrowError):
    """Raised when attempting to modify an already-resolved escrow."""
    
    def __init__(self, escrow_id: str, resolution_status: str):
        self.resolution_status = resolution_status
        super().__init__(
            f"Escrow {escrow_id} already resolved with status: {resolution_status}",
            escrow_id=escrow_id
        )
        self.code = "ESCROW_ALREADY_RESOLVED"


class InsufficientCreditsError(EscrowError):
    """Raised when an agent doesn't have enough credits for escrow."""
    
    def __init__(self, agent_did: str, required: int, available: int):
        self.agent_did = agent_did
        self.required = required
        self.available = available
        super().__init__(
            f"Agent {agent_did} has insufficient credits: required={required}, available={available}"
        )
        self.code = "INSUFFICIENT_CREDITS"


class DisputeError(NexusError):
    """Base exception for dispute-related errors."""
    
    def __init__(self, message: str, dispute_id: Optional[str] = None):
        self.dispute_id = dispute_id
        super().__init__(message, code="DISPUTE_ERROR")


class DisputeNotFoundError(DisputeError):
    """Raised when a dispute cannot be found."""
    
    def __init__(self, dispute_id: str):
        super().__init__(f"Dispute not found: {dispute_id}", dispute_id=dispute_id)
        self.code = "DISPUTE_NOT_FOUND"


class DisputeAlreadyResolvedError(DisputeError):
    """Raised when attempting to modify a resolved dispute."""
    
    def __init__(self, dispute_id: str):
        super().__init__(
            f"Dispute {dispute_id} has already been resolved",
            dispute_id=dispute_id
        )
        self.code = "DISPUTE_ALREADY_RESOLVED"


class DisputeEvidenceError(DisputeError):
    """Raised when there's an issue with dispute evidence."""
    
    def __init__(self, dispute_id: str, issue: str):
        self.issue = issue
        super().__init__(
            f"Evidence issue for dispute {dispute_id}: {issue}",
            dispute_id=dispute_id
        )
        self.code = "DISPUTE_EVIDENCE_ERROR"


class RegistryError(NexusError):
    """Base exception for registry-related errors."""
    
    def __init__(self, message: str, agent_did: Optional[str] = None):
        self.agent_did = agent_did
        super().__init__(message, code="REGISTRY_ERROR")


class AgentAlreadyRegisteredError(RegistryError):
    """Raised when attempting to register an already-registered agent."""
    
    def __init__(self, agent_did: str):
        super().__init__(
            f"Agent already registered: {agent_did}",
            agent_did=agent_did
        )
        self.code = "AGENT_ALREADY_REGISTERED"


class AgentNotFoundError(RegistryError):
    """Raised when an agent cannot be found in the registry."""
    
    def __init__(self, agent_did: str):
        super().__init__(
            f"Agent not found in registry: {agent_did}",
            agent_did=agent_did
        )
        self.code = "AGENT_NOT_FOUND"


class InvalidManifestError(RegistryError):
    """Raised when an agent manifest is invalid."""
    
    def __init__(self, agent_did: str, validation_errors: list[str]):
        self.validation_errors = validation_errors
        super().__init__(
            f"Invalid manifest for {agent_did}: {', '.join(validation_errors)}",
            agent_did=agent_did
        )
        self.code = "INVALID_MANIFEST"


class DMZError(NexusError):
    """Base exception for DMZ protocol errors."""
    
    def __init__(self, message: str):
        super().__init__(message, code="DMZ_ERROR")


class PolicyNotSignedError(DMZError):
    """Raised when data handling policy hasn't been signed."""
    
    def __init__(self, agent_did: str, policy_hash: str):
        self.agent_did = agent_did
        self.policy_hash = policy_hash
        super().__init__(
            f"Agent {agent_did} has not signed policy {policy_hash}"
        )
        self.code = "POLICY_NOT_SIGNED"


class DataClassificationError(DMZError):
    """Raised when data classification prevents operation."""
    
    def __init__(self, classification: str, reason: str):
        self.classification = classification
        self.reason = reason
        super().__init__(
            f"Data classification '{classification}' blocked: {reason}"
        )
        self.code = "DATA_CLASSIFICATION_ERROR"
