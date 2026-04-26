# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Escrow Manager."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.escrow import EscrowManager
from nexus.reputation import ReputationEngine
from nexus.schemas.escrow import (
    EscrowRequest,
    EscrowReceipt,
    EscrowStatus,
    EscrowRelease,
    EscrowResolution,
)
from nexus.exceptions import (
    EscrowNotFoundError,
    EscrowExpiredError,
    EscrowAlreadyResolvedError,
    InsufficientCreditsError,
)


@pytest.fixture
def funded_escrow_manager(reputation_engine):
    """EscrowManager with pre-funded agents."""
    em = EscrowManager(reputation_engine=reputation_engine)
    em.add_credits("did:nexus:requester-agent", 1000)
    em.add_credits("did:nexus:provider-agent", 500)
    return em


class TestCreateEscrow:
    """Tests for EscrowManager.create_escrow()."""

    @pytest.mark.asyncio
    async def test_create_escrow_success(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        assert receipt.escrow_id.startswith("escrow_")
        assert receipt.status == EscrowStatus.PENDING
        assert receipt.request == sample_escrow_request
        assert receipt.nexus_signature is not None

    @pytest.mark.asyncio
    async def test_create_escrow_locks_credits(self, funded_escrow_manager, sample_escrow_request):
        before = funded_escrow_manager.get_agent_credits("did:nexus:requester-agent")
        await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        after = funded_escrow_manager.get_agent_credits("did:nexus:requester-agent")
        assert after == before - sample_escrow_request.credits

    @pytest.mark.asyncio
    async def test_insufficient_credits_raises(self, escrow_manager, sample_escrow_request):
        with pytest.raises(InsufficientCreditsError) as exc_info:
            await escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        assert exc_info.value.required == 100
        assert exc_info.value.available == 0


class TestActivateEscrow:
    """Tests for EscrowManager.activate_escrow()."""

    @pytest.mark.asyncio
    async def test_activate_pending_escrow(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        activated = await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        assert activated.status == EscrowStatus.ACTIVE
        assert activated.activated_at is not None

    @pytest.mark.asyncio
    async def test_activate_nonexistent_raises(self, funded_escrow_manager):
        with pytest.raises(EscrowNotFoundError):
            await funded_escrow_manager.activate_escrow("escrow_nonexistent")

    @pytest.mark.asyncio
    async def test_activate_already_active_raises(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        with pytest.raises(EscrowAlreadyResolvedError):
            await funded_escrow_manager.activate_escrow(receipt.escrow_id)


class TestCompleteTask:
    """Tests for EscrowManager.complete_task()."""

    @pytest.mark.asyncio
    async def test_complete_active_task(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        completed = await funded_escrow_manager.complete_task(
            receipt.escrow_id, output_hash="hash123", duration_ms=500, provider_signature="sig_prov",
        )
        assert completed.status == EscrowStatus.AWAITING_VALIDATION

    @pytest.mark.asyncio
    async def test_complete_non_active_raises(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        # Still PENDING, not ACTIVE
        with pytest.raises(EscrowAlreadyResolvedError):
            await funded_escrow_manager.complete_task(
                receipt.escrow_id, output_hash="h", duration_ms=100, provider_signature="s",
            )


class TestReleaseEscrow:
    """Tests for EscrowManager.release_escrow()."""

    @pytest.mark.asyncio
    async def test_release_success(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        release = EscrowRelease(
            escrow_id=receipt.escrow_id, outcome="success",
            scak_validated=False,
        )
        resolution = await funded_escrow_manager.release_escrow(release)
        assert resolution.final_status == EscrowStatus.RELEASED
        assert resolution.credits_to_provider == 100
        assert resolution.credits_to_requester == 0

    @pytest.mark.asyncio
    async def test_release_failure_refunds(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        release = EscrowRelease(escrow_id=receipt.escrow_id, outcome="failure")
        resolution = await funded_escrow_manager.release_escrow(release)
        assert resolution.final_status == EscrowStatus.REFUNDED
        assert resolution.credits_to_requester == 100

    @pytest.mark.asyncio
    async def test_release_dispute(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        release = EscrowRelease(
            escrow_id=receipt.escrow_id, outcome="dispute",
            dispute_reason="Output was wrong",
        )
        resolution = await funded_escrow_manager.release_escrow(release)
        assert resolution.final_status == EscrowStatus.DISPUTED

    @pytest.mark.asyncio
    async def test_release_already_resolved_raises(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        release = EscrowRelease(escrow_id=receipt.escrow_id, outcome="success", scak_validated=False)
        await funded_escrow_manager.release_escrow(release)
        with pytest.raises(EscrowAlreadyResolvedError):
            await funded_escrow_manager.release_escrow(release)


class TestExpireEscrow:
    """Tests for EscrowManager.expire_escrow()."""

    @pytest.mark.asyncio
    async def test_expire_returns_credits(self, funded_escrow_manager, sample_escrow_request):
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        resolution = await funded_escrow_manager.expire_escrow(receipt.escrow_id)
        assert resolution.final_status == EscrowStatus.EXPIRED
        assert resolution.credits_to_requester == 100

    @pytest.mark.asyncio
    async def test_expire_nonexistent_raises(self, funded_escrow_manager):
        with pytest.raises(EscrowNotFoundError):
            await funded_escrow_manager.expire_escrow("escrow_ghost")


class TestCredits:
    """Tests for credit management."""

    def test_get_agent_credits_default_zero(self, escrow_manager):
        assert escrow_manager.get_agent_credits("did:nexus:new") == 0

    def test_add_credits(self, escrow_manager):
        result = escrow_manager.add_credits("did:nexus:a", 500)
        assert result == 500
        assert escrow_manager.get_agent_credits("did:nexus:a") == 500

    def test_add_credits_accumulates(self, escrow_manager):
        escrow_manager.add_credits("did:nexus:a", 200)
        escrow_manager.add_credits("did:nexus:a", 300)
        assert escrow_manager.get_agent_credits("did:nexus:a") == 500


class TestEscrowStatusTransitions:
    """Tests for status transition validation."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, funded_escrow_manager, sample_escrow_request):
        """PENDING → ACTIVE → AWAITING_VALIDATION → RELEASED."""
        receipt = await funded_escrow_manager.create_escrow(sample_escrow_request, "sig_req")
        assert receipt.status == EscrowStatus.PENDING

        await funded_escrow_manager.activate_escrow(receipt.escrow_id)
        assert receipt.status == EscrowStatus.ACTIVE

        await funded_escrow_manager.complete_task(
            receipt.escrow_id, output_hash="h", duration_ms=100, provider_signature="s",
        )
        assert receipt.status == EscrowStatus.AWAITING_VALIDATION

        release = EscrowRelease(
            escrow_id=receipt.escrow_id, outcome="success", scak_validated=False,
        )
        # AWAITING_VALIDATION is still active per is_active()
        resolution = await funded_escrow_manager.release_escrow(release)
        assert resolution.final_status == EscrowStatus.RELEASED


class TestEscrowSchemas:
    """Tests for EscrowRequest and EscrowReceipt validation."""

    def test_escrow_request_credits_validation(self):
        with pytest.raises(Exception):  # pydantic ValidationError
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="hash", credits=0,  # must be > 0
            )

    def test_escrow_request_credits_max(self):
        with pytest.raises(Exception):
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="hash", credits=20000,  # max 10000
            )

    def test_escrow_request_timeout_min(self):
        with pytest.raises(Exception):
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="hash", credits=100, timeout_seconds=10,  # min 60
            )

    def test_escrow_receipt_is_expired(self):
        receipt = EscrowReceipt(
            escrow_id="e1",
            request=EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="hash", credits=100,
            ),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            requester_signature="sig",
        )
        assert receipt.is_expired() is True

    def test_escrow_receipt_is_active(self):
        receipt = EscrowReceipt(
            escrow_id="e1",
            request=EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="hash", credits=100,
            ),
            status=EscrowStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            requester_signature="sig",
        )
        assert receipt.is_active() is True

    def test_escrow_receipt_not_active_when_released(self):
        receipt = EscrowReceipt(
            escrow_id="e1",
            request=EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="hash", credits=100,
            ),
            status=EscrowStatus.RELEASED,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            requester_signature="sig",
        )
        assert receipt.is_active() is False
