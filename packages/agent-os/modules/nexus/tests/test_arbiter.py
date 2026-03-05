# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Arbiter (Dispute Resolution)."""

import os
import sys
import hashlib
from datetime import datetime, timezone

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.arbiter import Arbiter, FlightRecorderLog, DisputeResolution
from nexus.reputation import ReputationEngine
from nexus.escrow import EscrowManager
from nexus.schemas.receipt import DisputeReceipt
from nexus.exceptions import DisputeNotFoundError, DisputeAlreadyResolvedError, DisputeEvidenceError


@pytest.fixture
def arbiter(reputation_engine, escrow_manager):
    return Arbiter(
        reputation_engine=reputation_engine,
        escrow_manager=escrow_manager,
    )


def make_flight_log(agent_did: str, log_data: bytes = b"flight log data") -> FlightRecorderLog:
    """Create a flight recorder log with valid hash."""
    return FlightRecorderLog(
        agent_did=agent_did,
        task_id="task_001",
        escrow_id="escrow_001",
        encrypted_log=log_data,
        log_hash=hashlib.sha256(log_data).hexdigest(),
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        operation_count=10,
        agent_signature="sig_agent",
    )


class TestFlightRecorderLog:
    """Tests for FlightRecorderLog.verify_hash()."""

    def test_verify_hash_valid(self):
        log = make_flight_log("did:nexus:a")
        assert log.verify_hash() is True

    def test_verify_hash_tampered(self):
        log = make_flight_log("did:nexus:a")
        log.encrypted_log = b"tampered data"
        assert log.verify_hash() is False

    def test_verify_hash_empty_log(self):
        log = make_flight_log("did:nexus:a", log_data=b"")
        assert log.verify_hash() is True


class TestSubmitDispute:
    """Tests for Arbiter.submit_dispute()."""

    @pytest.mark.asyncio
    async def test_submit_dispute_success(self, arbiter):
        log = make_flight_log("did:nexus:requester")
        dispute = await arbiter.submit_dispute(
            escrow_id="escrow_001",
            disputing_party="requester",
            dispute_reason="Output was incorrect",
            claimed_outcome="failure",
            flight_recorder_log=log,
        )
        assert isinstance(dispute, DisputeReceipt)
        assert dispute.dispute_id.startswith("dispute_")
        assert dispute.disputing_party == "requester"
        assert dispute.dispute_reason == "Output was incorrect"

    @pytest.mark.asyncio
    async def test_submit_dispute_invalid_log_raises(self, arbiter):
        log = make_flight_log("did:nexus:requester")
        log.encrypted_log = b"tampered"  # hash won't match
        with pytest.raises(DisputeEvidenceError):
            await arbiter.submit_dispute(
                escrow_id="escrow_001",
                disputing_party="requester",
                dispute_reason="reason",
                claimed_outcome="failure",
                flight_recorder_log=log,
            )

    @pytest.mark.asyncio
    async def test_submit_dispute_requester_logs_stored(self, arbiter):
        log = make_flight_log("did:nexus:requester")
        dispute = await arbiter.submit_dispute(
            escrow_id="escrow_001",
            disputing_party="requester",
            dispute_reason="reason",
            claimed_outcome="failure",
            flight_recorder_log=log,
        )
        assert dispute.requester_logs_hash == log.log_hash

    @pytest.mark.asyncio
    async def test_submit_dispute_provider_logs_stored(self, arbiter):
        log = make_flight_log("did:nexus:provider")
        dispute = await arbiter.submit_dispute(
            escrow_id="escrow_001",
            disputing_party="provider",
            dispute_reason="reason",
            claimed_outcome="success",
            flight_recorder_log=log,
        )
        assert dispute.provider_logs_hash == log.log_hash


class TestResolveDispute:
    """Tests for Arbiter.resolve_dispute()."""

    @pytest.mark.asyncio
    async def test_resolve_with_both_logs(self, arbiter):
        req_log = make_flight_log("did:nexus:requester", b"requester log")
        dispute = await arbiter.submit_dispute(
            escrow_id="escrow_001", disputing_party="requester",
            dispute_reason="bad output", claimed_outcome="failure",
            flight_recorder_log=req_log,
        )
        # Submit counter-evidence
        prov_log = make_flight_log("did:nexus:provider", b"provider log")
        await arbiter.submit_counter_evidence(dispute.dispute_id, prov_log)

        resolution = await arbiter.resolve_dispute(
            dispute.dispute_id, requester_logs=req_log, provider_logs=prov_log,
        )
        assert isinstance(resolution, DisputeResolution)
        assert resolution.outcome in ("requester_wins", "provider_wins", "split")

    @pytest.mark.asyncio
    async def test_resolve_nonexistent_raises(self, arbiter):
        with pytest.raises(DisputeNotFoundError):
            await arbiter.resolve_dispute("dispute_nonexistent")

    @pytest.mark.asyncio
    async def test_resolve_marks_dispute_resolved(self, arbiter):
        req_log = make_flight_log("did:nexus:requester", b"req")
        dispute = await arbiter.submit_dispute(
            escrow_id="e1", disputing_party="requester",
            dispute_reason="r", claimed_outcome="failure",
            flight_recorder_log=req_log,
        )
        prov_log = make_flight_log("did:nexus:provider", b"prov")
        await arbiter.submit_counter_evidence(dispute.dispute_id, prov_log)
        await arbiter.resolve_dispute(dispute.dispute_id, req_log, prov_log)

        stored = arbiter.get_dispute(dispute.dispute_id)
        assert stored.resolved is True

    @pytest.mark.asyncio
    async def test_resolve_already_resolved_raises(self, arbiter):
        req_log = make_flight_log("did:nexus:requester", b"req")
        dispute = await arbiter.submit_dispute(
            escrow_id="e1", disputing_party="requester",
            dispute_reason="r", claimed_outcome="failure",
            flight_recorder_log=req_log,
        )
        prov_log = make_flight_log("did:nexus:provider", b"prov")
        await arbiter.submit_counter_evidence(dispute.dispute_id, prov_log)
        await arbiter.resolve_dispute(dispute.dispute_id, req_log, prov_log)

        with pytest.raises(DisputeAlreadyResolvedError):
            await arbiter.resolve_dispute(dispute.dispute_id, req_log, prov_log)


class TestGetDispute:
    """Tests for Arbiter.get_dispute()."""

    @pytest.mark.asyncio
    async def test_get_existing_dispute(self, arbiter):
        log = make_flight_log("did:nexus:a")
        dispute = await arbiter.submit_dispute(
            escrow_id="e1", disputing_party="requester",
            dispute_reason="r", claimed_outcome="failure",
            flight_recorder_log=log,
        )
        found = arbiter.get_dispute(dispute.dispute_id)
        assert found.dispute_id == dispute.dispute_id

    def test_get_nonexistent_raises(self, arbiter):
        with pytest.raises(DisputeNotFoundError):
            arbiter.get_dispute("dispute_ghost")
