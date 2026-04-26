# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Arbiter - Dispute Resolution

The "Reward Agent" - a specialized, read-only agent that resolves disputes
between agents by replaying flight recorder logs against the Control Plane.
"""

from datetime import datetime, timezone
from typing import Optional, Literal
from dataclasses import dataclass, field
import hashlib
import uuid

from .schemas.receipt import DisputeReceipt
from .schemas.escrow import EscrowStatus, EscrowResolution
from .reputation import ReputationEngine
from .exceptions import (
    DisputeNotFoundError,
    DisputeAlreadyResolvedError,
    DisputeEvidenceError,
)


@dataclass
class FlightRecorderLog:
    """
    Flight recorder log from an agent's kernel.
    
    Contains all operations, tool calls, and outputs during a task.
    """
    
    agent_did: str
    task_id: str
    escrow_id: str
    
    # Log content (encrypted)
    encrypted_log: bytes
    log_hash: str
    
    # Metadata (not encrypted)
    start_time: datetime
    end_time: datetime
    operation_count: int
    
    # Signature
    agent_signature: str
    
    def verify_hash(self) -> bool:
        """Verify log integrity."""
        computed = hashlib.sha256(self.encrypted_log).hexdigest()
        return computed == self.log_hash


@dataclass
class DisputeResolution:
    """Result of dispute resolution by the Arbiter."""
    
    dispute_id: str
    escrow_id: str
    
    # Parties
    requester_did: str
    provider_did: str
    
    # Decision
    outcome: Literal["requester_wins", "provider_wins", "split"]
    decision_explanation: str
    confidence_score: float  # 0-1, how confident Arbiter is
    
    # Evidence analysis
    requester_logs_valid: bool
    provider_logs_valid: bool
    discrepancies_found: list[str] = field(default_factory=list)
    
    # Credit distribution
    credits_to_requester: int = 0
    credits_to_provider: int = 0
    
    # Reputation impact
    requester_reputation_change: int = 0
    provider_reputation_change: int = 0
    liar_identified: Optional[str] = None  # DID of agent found to be lying
    
    # Timestamps
    resolved_at: datetime = field(default_factory=datetime.utcnow)
    
    # Nexus attestation
    arbiter_signature: str = ""


class Arbiter:
    """
    The "Reward Agent" - resolves disputes between agents.
    
    A read-only agent hosted on Nexus that:
    1. Receives flight recorder logs from both parties
    2. Replays operations against the Control Plane
    3. Determines which agent's claim is accurate
    4. Applies reputation penalties to the lying agent
    """
    
    def __init__(
        self,
        reputation_engine: Optional[ReputationEngine] = None,
        escrow_manager: Optional[any] = None,  # Circular import avoidance
        control_plane: Optional[any] = None,  # Would be Control Plane reference
    ):
        self.reputation_engine = reputation_engine or ReputationEngine()
        self.escrow_manager = escrow_manager
        self.control_plane = control_plane
        
        # Storage
        self._disputes: dict[str, DisputeReceipt] = {}
        self._resolutions: dict[str, DisputeResolution] = {}
    
    async def submit_dispute(
        self,
        escrow_id: str,
        disputing_party: Literal["requester", "provider"],
        dispute_reason: str,
        claimed_outcome: Literal["success", "failure", "partial"],
        flight_recorder_log: FlightRecorderLog,
    ) -> DisputeReceipt:
        """
        Submit a new dispute for resolution.
        
        Args:
            escrow_id: ID of the disputed escrow
            disputing_party: Who is raising the dispute
            dispute_reason: Explanation of why they're disputing
            claimed_outcome: What the disputing party claims happened
            flight_recorder_log: Evidence from the disputing party
        """
        dispute_id = f"dispute_{uuid.uuid4().hex[:16]}"
        
        # Verify log integrity
        if not flight_recorder_log.verify_hash():
            raise DisputeEvidenceError(dispute_id, "Log hash verification failed")
        
        # Get escrow details (would fetch from EscrowManager)
        # For now, create a placeholder receipt
        
        dispute = DisputeReceipt(
            dispute_id=dispute_id,
            original_receipt=None,  # Would be the signed receipt
            disputing_party=disputing_party,
            dispute_reason=dispute_reason,
            claimed_outcome=claimed_outcome,
        )
        
        if disputing_party == "requester":
            dispute.requester_logs_hash = flight_recorder_log.log_hash
        else:
            dispute.provider_logs_hash = flight_recorder_log.log_hash
        
        self._disputes[dispute_id] = dispute
        
        return dispute
    
    async def submit_counter_evidence(
        self,
        dispute_id: str,
        flight_recorder_log: FlightRecorderLog,
    ) -> DisputeReceipt:
        """Submit counter-evidence from the other party."""
        if dispute_id not in self._disputes:
            raise DisputeNotFoundError(dispute_id)
        
        dispute = self._disputes[dispute_id]
        
        if dispute.resolved:
            raise DisputeAlreadyResolvedError(dispute_id)
        
        # Verify log integrity
        if not flight_recorder_log.verify_hash():
            raise DisputeEvidenceError(dispute_id, "Log hash verification failed")
        
        # Add logs from other party
        if dispute.disputing_party == "requester":
            dispute.provider_logs_hash = flight_recorder_log.log_hash
        else:
            dispute.requester_logs_hash = flight_recorder_log.log_hash
        
        return dispute
    
    async def resolve_dispute(
        self,
        dispute_id: str,
        requester_logs: Optional[FlightRecorderLog] = None,
        provider_logs: Optional[FlightRecorderLog] = None,
    ) -> DisputeResolution:
        """
        Resolve a dispute by replaying logs against Control Plane.
        
        Process:
        1. Parse both flight recorder logs
        2. Identify the disputed operation
        3. Replay operation against Control Plane
        4. Compare actual vs claimed outcomes
        5. Determine which agent's claim is accurate
        6. Apply reputation penalties to the lying agent
        """
        if dispute_id not in self._disputes:
            raise DisputeNotFoundError(dispute_id)
        
        dispute = self._disputes[dispute_id]
        
        if dispute.resolved:
            raise DisputeAlreadyResolvedError(dispute_id)
        
        # Verify we have evidence from both parties
        if not dispute.requester_logs_hash or not dispute.provider_logs_hash:
            raise DisputeEvidenceError(
                dispute_id,
                "Evidence required from both parties"
            )
        
        # Analyze the dispute
        resolution = await self._analyze_dispute(dispute, requester_logs, provider_logs)
        
        # Mark dispute as resolved
        dispute.resolved = True
        dispute.resolution_outcome = resolution.outcome
        dispute.arbiter_decision = resolution.decision_explanation
        dispute.resolved_at = resolution.resolved_at
        
        # Apply reputation changes
        if resolution.liar_identified:
            self.reputation_engine.slash_reputation(
                agent_did=resolution.liar_identified,
                reason="dispute_lost",
                severity="high",
                evidence_hash=dispute_id,
            )
        
        # Store resolution
        self._resolutions[dispute_id] = resolution
        
        return resolution
    
    async def _analyze_dispute(
        self,
        dispute: DisputeReceipt,
        requester_logs: Optional[FlightRecorderLog],
        provider_logs: Optional[FlightRecorderLog],
    ) -> DisputeResolution:
        """
        Analyze dispute evidence and determine outcome.
        
        In production, this would:
        1. Decrypt and parse logs
        2. Replay operations against Control Plane
        3. Use deterministic validation to find discrepancies
        """
        # Placeholder analysis - in production would use Control Plane
        discrepancies = []
        requester_valid = requester_logs.verify_hash() if requester_logs else False
        provider_valid = provider_logs.verify_hash() if provider_logs else False
        
        # Determine outcome based on evidence validity
        if requester_valid and not provider_valid:
            outcome = "requester_wins"
            liar = None  # Provider didn't submit valid logs
            decision = "Provider's evidence was invalid or missing"
            confidence = 0.9
        elif provider_valid and not requester_valid:
            outcome = "provider_wins"
            liar = None  # Requester didn't submit valid logs
            decision = "Requester's evidence was invalid or missing"
            confidence = 0.9
        elif requester_valid and provider_valid:
            # Both valid - would need deeper analysis
            # For now, split decision
            outcome = "split"
            liar = None
            decision = "Both parties provided valid evidence; compromise reached"
            confidence = 0.6
            discrepancies.append("Conflicting but valid evidence from both parties")
        else:
            # Neither valid
            outcome = "split"
            liar = None
            decision = "Neither party provided valid evidence"
            confidence = 0.3
        
        # Calculate credit distribution
        # Would get actual credits from escrow
        total_credits = 100  # Placeholder
        
        if outcome == "requester_wins":
            credits_to_requester = total_credits
            credits_to_provider = 0
            requester_rep = 10
            provider_rep = -50
        elif outcome == "provider_wins":
            credits_to_requester = 0
            credits_to_provider = total_credits
            requester_rep = -50
            provider_rep = 10
        else:  # split
            credits_to_requester = total_credits // 2
            credits_to_provider = total_credits // 2
            requester_rep = -10
            provider_rep = -10
        
        resolution = DisputeResolution(
            dispute_id=dispute.dispute_id,
            escrow_id="",  # Would get from dispute
            requester_did="",  # Would get from dispute
            provider_did="",  # Would get from dispute
            outcome=outcome,
            decision_explanation=decision,
            confidence_score=confidence,
            requester_logs_valid=requester_valid,
            provider_logs_valid=provider_valid,
            discrepancies_found=discrepancies,
            credits_to_requester=credits_to_requester,
            credits_to_provider=credits_to_provider,
            requester_reputation_change=requester_rep,
            provider_reputation_change=provider_rep,
            liar_identified=liar,
            arbiter_signature=self._sign_resolution(dispute.dispute_id, outcome),
        )
        
        return resolution
    
    def get_dispute(self, dispute_id: str) -> DisputeReceipt:
        """Get a dispute by ID."""
        if dispute_id not in self._disputes:
            raise DisputeNotFoundError(dispute_id)
        return self._disputes[dispute_id]
    
    def get_resolution(self, dispute_id: str) -> DisputeResolution:
        """Get resolution for a dispute."""
        if dispute_id not in self._resolutions:
            raise DisputeNotFoundError(dispute_id)
        return self._resolutions[dispute_id]
    
    def list_disputes(
        self,
        agent_did: Optional[str] = None,
        resolved: Optional[bool] = None,
    ) -> list[DisputeReceipt]:
        """List disputes with optional filtering."""
        results = list(self._disputes.values())
        
        if resolved is not None:
            results = [d for d in results if d.resolved == resolved]
        
        # Would filter by agent_did if we had that in the receipt
        
        return results
    
    def _sign_resolution(self, dispute_id: str, outcome: str) -> str:
        """Generate Arbiter signature for resolution."""
        data = f"arbiter:{dispute_id}:{outcome}:{datetime.now(timezone.utc).isoformat()}"
        return f"arbiter_sig_{hashlib.sha256(data.encode()).hexdigest()[:32]}"
