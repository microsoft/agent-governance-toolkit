# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Nexus Escrow / Proof of Outcome
"""

import pytest
from datetime import datetime

from nexus.escrow import EscrowManager, ProofOfOutcome
from nexus.schemas.escrow import EscrowRequest, EscrowStatus
from nexus.exceptions import (
    EscrowNotFoundError,
    EscrowAlreadyResolvedError,
    InsufficientCreditsError,
)


class TestEscrowManager:
    """Tests for EscrowManager."""
    
    @pytest.mark.asyncio
    async def test_create_escrow(self):
        """Test creating an escrow."""
        manager = EscrowManager()
        
        # Add credits to requester
        manager.add_credits("did:nexus:requester", 1000)
        
        request = EscrowRequest(
            requester_did="did:nexus:requester",
            provider_did="did:nexus:provider",
            task_hash="abc123",
            credits=100,
        )
        
        receipt = await manager.create_escrow(request, "signature")
        
        assert receipt.status == EscrowStatus.PENDING
        assert receipt.request.credits == 100
    
    @pytest.mark.asyncio
    async def test_insufficient_credits(self):
        """Test escrow creation fails with insufficient credits."""
        manager = EscrowManager()
        
        # Don't add credits
        request = EscrowRequest(
            requester_did="did:nexus:broke",
            provider_did="did:nexus:provider",
            task_hash="abc123",
            credits=1000,
        )
        
        with pytest.raises(InsufficientCreditsError):
            await manager.create_escrow(request, "signature")
    
    @pytest.mark.asyncio
    async def test_activate_escrow(self):
        """Test activating an escrow."""
        manager = EscrowManager()
        manager.add_credits("did:nexus:requester", 1000)
        
        request = EscrowRequest(
            requester_did="did:nexus:requester",
            provider_did="did:nexus:provider",
            task_hash="abc123",
            credits=100,
        )
        
        receipt = await manager.create_escrow(request, "sig")
        receipt = await manager.activate_escrow(receipt.escrow_id)
        
        assert receipt.status == EscrowStatus.ACTIVE
        assert receipt.activated_at is not None
    
    @pytest.mark.asyncio
    async def test_release_success(self):
        """Test releasing escrow on success."""
        manager = EscrowManager()
        manager.add_credits("did:nexus:requester", 1000)
        
        request = EscrowRequest(
            requester_did="did:nexus:requester",
            provider_did="did:nexus:provider",
            task_hash="abc123",
            credits=100,
            require_scak_validation=False,
        )
        
        receipt = await manager.create_escrow(request, "sig")
        await manager.activate_escrow(receipt.escrow_id)
        
        from nexus.schemas.escrow import EscrowRelease
        release = EscrowRelease(
            escrow_id=receipt.escrow_id,
            outcome="success",
        )
        
        resolution = await manager.release_escrow(release)
        
        assert resolution.final_status == EscrowStatus.RELEASED
        assert resolution.credits_to_provider == 100
        assert resolution.credits_to_requester == 0
    
    @pytest.mark.asyncio
    async def test_release_failure(self):
        """Test releasing escrow on failure."""
        manager = EscrowManager()
        manager.add_credits("did:nexus:requester", 1000)
        
        request = EscrowRequest(
            requester_did="did:nexus:requester",
            provider_did="did:nexus:provider",
            task_hash="abc123",
            credits=100,
            require_scak_validation=False,
        )
        
        receipt = await manager.create_escrow(request, "sig")
        await manager.activate_escrow(receipt.escrow_id)
        
        from nexus.schemas.escrow import EscrowRelease
        release = EscrowRelease(
            escrow_id=receipt.escrow_id,
            outcome="failure",
        )
        
        resolution = await manager.release_escrow(release)
        
        assert resolution.final_status == EscrowStatus.REFUNDED
        assert resolution.credits_to_provider == 0
        assert resolution.credits_to_requester == 100
    
    @pytest.mark.asyncio
    async def test_escrow_not_found(self):
        """Test error for nonexistent escrow."""
        manager = EscrowManager()
        
        with pytest.raises(EscrowNotFoundError):
            manager.get_escrow("nonexistent")
    
    @pytest.mark.asyncio
    async def test_credit_management(self):
        """Test credit add and get."""
        manager = EscrowManager()
        
        assert manager.get_agent_credits("did:nexus:agent") == 0
        
        manager.add_credits("did:nexus:agent", 500)
        assert manager.get_agent_credits("did:nexus:agent") == 500
        
        manager.add_credits("did:nexus:agent", 300)
        assert manager.get_agent_credits("did:nexus:agent") == 800


class TestProofOfOutcome:
    """Tests for ProofOfOutcome high-level API."""
    
    @pytest.mark.asyncio
    async def test_create_and_release(self):
        """Test the full escrow lifecycle."""
        poo = ProofOfOutcome()
        
        # Add credits
        poo.escrow_manager.add_credits("did:nexus:requester", 1000)
        
        # Create escrow
        receipt = await poo.create_escrow(
            requester_did="did:nexus:requester",
            provider_did="did:nexus:provider",
            task_hash="task123",
            credits=50,
            require_scak=False,
        )
        
        # Activate
        await poo.escrow_manager.activate_escrow(receipt.escrow_id)
        
        # Release
        resolution = await poo.release_escrow(
            escrow_id=receipt.escrow_id,
            outcome="success",
        )
        
        assert resolution.credits_to_provider == 50
    
    @pytest.mark.asyncio
    async def test_validate_outcome(self):
        """Test SCAK validation."""
        poo = ProofOfOutcome()
        poo.escrow_manager.add_credits("did:nexus:requester", 1000)
        
        receipt = await poo.create_escrow(
            requester_did="did:nexus:requester",
            provider_did="did:nexus:provider",
            task_hash="task123",
            credits=50,
            require_scak=True,
            drift_threshold=0.15,
        )
        
        # Validate (without actual SCAK validator)
        passed, drift_score = await poo.validate_outcome(
            escrow_id=receipt.escrow_id,
            flight_recorder_log=b"test log data",
            claimed_outcome="success",
        )
        
        assert passed is True  # No validator = auto pass
