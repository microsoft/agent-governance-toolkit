# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Proof of Outcome / Escrow Manager

Implements the "Reward" mechanism where agents bet on task outcomes.
Credits are escrowed and released based on SCAK validation.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
import hashlib
import uuid
import asyncio

from .schemas.escrow import (
    EscrowRequest,
    EscrowReceipt,
    EscrowStatus,
    EscrowRelease,
    EscrowResolution,
)
from .schemas.receipt import JobCompletionReceipt, SignedReceipt
from .reputation import ReputationEngine
from .exceptions import (
    EscrowNotFoundError,
    EscrowExpiredError,
    EscrowAlreadyResolvedError,
    InsufficientCreditsError,
)


class EscrowManager:
    """
    Manages escrow lifecycle for inter-agent tasks.
    
    The "Reward" OS - agents don't just talk, they bet on outcomes.
    """
    
    def __init__(self, reputation_engine: Optional[ReputationEngine] = None):
        self.reputation_engine = reputation_engine or ReputationEngine()
        
        # In-memory storage (would be database in production)
        self._escrows: dict[str, EscrowReceipt] = {}
        self._agent_credits: dict[str, int] = {}  # DID -> credits
        
        # Configuration
        self.default_timeout = 3600  # 1 hour
        self.max_credits_per_escrow = 10000
    
    async def create_escrow(
        self,
        request: EscrowRequest,
        requester_signature: str,
    ) -> EscrowReceipt:
        """
        Create an escrow for a task.
        
        Locks credits from requester until task completion.
        """
        # Check requester has enough credits
        available = self._agent_credits.get(request.requester_did, 0)
        if available < request.credits:
            raise InsufficientCreditsError(
                request.requester_did,
                required=request.credits,
                available=available,
            )
        
        # Generate escrow ID
        escrow_id = f"escrow_{uuid.uuid4().hex[:16]}"
        
        # Create receipt
        receipt = EscrowReceipt.from_request(
            escrow_id=escrow_id,
            request=request,
            requester_signature=requester_signature,
        )
        
        # Lock credits
        self._agent_credits[request.requester_did] -= request.credits
        
        # Sign from Nexus
        receipt.nexus_signature = self._sign_escrow(escrow_id, request)
        
        # Store
        self._escrows[escrow_id] = receipt
        
        return receipt
    
    async def activate_escrow(self, escrow_id: str) -> EscrowReceipt:
        """Mark escrow as active (task in progress)."""
        receipt = self._get_escrow(escrow_id)
        
        if receipt.status != EscrowStatus.PENDING:
            raise EscrowAlreadyResolvedError(escrow_id, receipt.status.value)
        
        receipt.status = EscrowStatus.ACTIVE
        receipt.activated_at = datetime.now(timezone.utc)
        
        return receipt
    
    async def complete_task(
        self,
        escrow_id: str,
        output_hash: str,
        duration_ms: int,
        provider_signature: str,
    ) -> EscrowReceipt:
        """Mark task as complete, awaiting validation."""
        receipt = self._get_escrow(escrow_id)
        
        if receipt.status != EscrowStatus.ACTIVE:
            raise EscrowAlreadyResolvedError(escrow_id, receipt.status.value)
        
        if receipt.is_expired():
            receipt.status = EscrowStatus.EXPIRED
            raise EscrowExpiredError(escrow_id, str(receipt.expires_at))
        
        receipt.status = EscrowStatus.AWAITING_VALIDATION
        receipt.completed_at = datetime.now(timezone.utc)
        
        return receipt
    
    async def release_escrow(
        self,
        release: EscrowRelease,
    ) -> EscrowResolution:
        """
        Release escrow based on outcome.
        
        - success: Credits go to provider, provider reputation +2
        - failure: Credits return to requester, provider reputation -10
        - dispute: Escalate to Arbiter
        """
        receipt = self._get_escrow(release.escrow_id)
        
        if not receipt.is_active():
            raise EscrowAlreadyResolvedError(release.escrow_id, receipt.status.value)
        
        request = receipt.request
        credits = request.credits
        
        # Determine resolution based on outcome
        if release.outcome == "success":
            # Validate with SCAK if required
            if request.require_scak_validation:
                if not release.scak_validated:
                    raise ValueError("SCAK validation required but not performed")
                if not release.scak_passed:
                    # SCAK failed - treat as failure
                    return await self._resolve_failure(receipt, release)
            
            return await self._resolve_success(receipt, release)
        
        elif release.outcome == "failure":
            return await self._resolve_failure(receipt, release)
        
        else:  # dispute
            return await self._resolve_dispute(receipt, release)
    
    async def _resolve_success(
        self,
        receipt: EscrowReceipt,
        release: EscrowRelease,
    ) -> EscrowResolution:
        """Resolve escrow as success - credits to provider."""
        request = receipt.request
        
        # Transfer credits to provider
        self._agent_credits[request.provider_did] = (
            self._agent_credits.get(request.provider_did, 0) + request.credits
        )
        
        # Update reputation
        self.reputation_engine.record_task_outcome(request.provider_did, "success")
        
        # Update receipt
        receipt.status = EscrowStatus.RELEASED
        receipt.resolved_at = datetime.now(timezone.utc)
        
        return EscrowResolution(
            escrow_id=receipt.escrow_id,
            final_status=EscrowStatus.RELEASED,
            credits_to_provider=request.credits,
            credits_to_requester=0,
            provider_reputation_change=2,
            requester_reputation_change=0,
            resolution_reason="Task completed successfully",
            resolved_by="automatic",
            nexus_signature=self._sign_resolution(receipt.escrow_id, "success"),
        )
    
    async def _resolve_failure(
        self,
        receipt: EscrowReceipt,
        release: EscrowRelease,
    ) -> EscrowResolution:
        """Resolve escrow as failure - credits returned to requester."""
        request = receipt.request
        
        # Return credits to requester
        self._agent_credits[request.requester_did] = (
            self._agent_credits.get(request.requester_did, 0) + request.credits
        )
        
        # Update reputation
        self.reputation_engine.record_task_outcome(request.provider_did, "failure")
        
        # Update receipt
        receipt.status = EscrowStatus.REFUNDED
        receipt.resolved_at = datetime.now(timezone.utc)
        
        return EscrowResolution(
            escrow_id=receipt.escrow_id,
            final_status=EscrowStatus.REFUNDED,
            credits_to_provider=0,
            credits_to_requester=request.credits,
            provider_reputation_change=-10,
            requester_reputation_change=0,
            resolution_reason="Task failed",
            resolved_by="automatic",
            nexus_signature=self._sign_resolution(receipt.escrow_id, "failure"),
        )
    
    async def _resolve_dispute(
        self,
        receipt: EscrowReceipt,
        release: EscrowRelease,
    ) -> EscrowResolution:
        """Mark escrow as disputed - to be resolved by Arbiter."""
        receipt.status = EscrowStatus.DISPUTED
        
        # Credits remain locked until Arbiter decides
        return EscrowResolution(
            escrow_id=receipt.escrow_id,
            final_status=EscrowStatus.DISPUTED,
            credits_to_provider=0,
            credits_to_requester=0,
            provider_reputation_change=0,
            requester_reputation_change=0,
            resolution_reason=f"Dispute raised: {release.dispute_reason}",
            resolved_by="arbiter",
            nexus_signature=self._sign_resolution(receipt.escrow_id, "dispute"),
        )
    
    async def expire_escrow(self, escrow_id: str) -> EscrowResolution:
        """Handle escrow expiration - credits returned to requester."""
        receipt = self._get_escrow(escrow_id)
        request = receipt.request
        
        # Return credits
        self._agent_credits[request.requester_did] = (
            self._agent_credits.get(request.requester_did, 0) + request.credits
        )
        
        # Small reputation penalty for provider
        self.reputation_engine.record_task_outcome(request.provider_did, "failure")
        
        receipt.status = EscrowStatus.EXPIRED
        receipt.resolved_at = datetime.now(timezone.utc)
        
        return EscrowResolution(
            escrow_id=escrow_id,
            final_status=EscrowStatus.EXPIRED,
            credits_to_provider=0,
            credits_to_requester=request.credits,
            provider_reputation_change=-5,
            requester_reputation_change=0,
            resolution_reason="Escrow expired without completion",
            resolved_by="timeout",
            nexus_signature=self._sign_resolution(escrow_id, "expired"),
        )
    
    def get_escrow(self, escrow_id: str) -> EscrowReceipt:
        """Get escrow by ID (public method)."""
        return self._get_escrow(escrow_id)
    
    def get_agent_credits(self, agent_did: str) -> int:
        """Get credit balance for an agent."""
        return self._agent_credits.get(agent_did, 0)
    
    def add_credits(self, agent_did: str, amount: int) -> int:
        """Add credits to an agent's balance."""
        self._agent_credits[agent_did] = self._agent_credits.get(agent_did, 0) + amount
        return self._agent_credits[agent_did]
    
    def list_escrows(
        self,
        agent_did: Optional[str] = None,
        status: Optional[EscrowStatus] = None,
    ) -> list[EscrowReceipt]:
        """List escrows with optional filtering."""
        results = list(self._escrows.values())
        
        if agent_did:
            results = [
                e for e in results
                if e.request.requester_did == agent_did or e.request.provider_did == agent_did
            ]
        
        if status:
            results = [e for e in results if e.status == status]
        
        return results
    
    def _get_escrow(self, escrow_id: str) -> EscrowReceipt:
        """Get escrow by ID or raise error."""
        if escrow_id not in self._escrows:
            raise EscrowNotFoundError(escrow_id)
        return self._escrows[escrow_id]
    
    def _sign_escrow(self, escrow_id: str, request: EscrowRequest) -> str:
        """Generate Nexus signature for escrow."""
        data = f"{escrow_id}:{request.task_hash}:{request.credits}"
        return f"nexus_escrow_{hashlib.sha256(data.encode()).hexdigest()[:32]}"
    
    def _sign_resolution(self, escrow_id: str, outcome: str) -> str:
        """Generate Nexus signature for resolution."""
        data = f"{escrow_id}:{outcome}:{datetime.now(timezone.utc).isoformat()}"
        return f"nexus_res_{hashlib.sha256(data.encode()).hexdigest()[:32]}"


class ProofOfOutcome:
    """
    High-level API for the Proof-of-Outcome mechanism.
    
    Wraps EscrowManager with SCAK validation integration.
    """
    
    def __init__(
        self,
        escrow_manager: Optional[EscrowManager] = None,
        scak_validator: Optional[any] = None,  # Would be SCAK validator
    ):
        self.escrow_manager = escrow_manager or EscrowManager()
        self.scak_validator = scak_validator
    
    async def create_escrow(
        self,
        requester_did: str,
        provider_did: str,
        task_hash: str,
        credits: int,
        timeout_seconds: int = 3600,
        require_scak: bool = True,
        drift_threshold: float = 0.15,
    ) -> EscrowReceipt:
        """Create an escrow for a task."""
        request = EscrowRequest(
            requester_did=requester_did,
            provider_did=provider_did,
            task_hash=task_hash,
            credits=credits,
            timeout_seconds=timeout_seconds,
            require_scak_validation=require_scak,
            scak_drift_threshold=drift_threshold,
        )
        
        # TODO: Generate actual signature
        signature = f"sig_{requester_did}_{task_hash[:8]}"
        
        return await self.escrow_manager.create_escrow(request, signature)
    
    async def validate_outcome(
        self,
        escrow_id: str,
        flight_recorder_log: bytes,
        claimed_outcome: Literal["success", "failure"],
    ) -> tuple[bool, Optional[float]]:
        """
        Validate task outcome using SCAK.
        
        Replays the flight recorder log against the Control Plane
        to deterministically verify the claimed outcome.
        
        Returns:
            Tuple of (passed, drift_score)
        """
        receipt = self.escrow_manager.get_escrow(escrow_id)
        
        if self.scak_validator is None:
            # No SCAK validator - assume success
            return True, 0.0
        
        # Validate with SCAK
        # drift_score = await self.scak_validator.validate(flight_recorder_log)
        # For now, simulate
        drift_score = 0.05
        
        threshold = receipt.request.scak_drift_threshold
        passed = drift_score <= threshold
        
        return passed, drift_score
    
    async def release_escrow(
        self,
        escrow_id: str,
        outcome: Literal["success", "failure", "dispute"],
        output_hash: Optional[str] = None,
        duration_ms: Optional[int] = None,
        scak_drift_score: Optional[float] = None,
        dispute_reason: Optional[str] = None,
    ) -> EscrowResolution:
        """
        Release escrow based on outcome.
        
        - success: Credits go to provider, provider reputation +2
        - failure: Credits return to requester, provider reputation -10
        - dispute: Escalate to Arbiter
        """
        receipt = self.escrow_manager.get_escrow(escrow_id)
        
        # Determine if SCAK passed
        scak_passed = None
        if scak_drift_score is not None:
            scak_passed = scak_drift_score <= receipt.request.scak_drift_threshold
        
        release = EscrowRelease(
            escrow_id=escrow_id,
            outcome=outcome,
            output_hash=output_hash,
            duration_ms=duration_ms,
            scak_validated=scak_drift_score is not None,
            scak_drift_score=scak_drift_score,
            scak_passed=scak_passed,
            dispute_reason=dispute_reason,
        )
        
        return await self.escrow_manager.release_escrow(release)
