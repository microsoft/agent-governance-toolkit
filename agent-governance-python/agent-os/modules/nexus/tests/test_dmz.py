# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the DMZ Protocol."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.dmz import DMZProtocol, DataHandlingPolicy, DMZRequest, SignedPolicy, DMZTransfer


@pytest.fixture
def dmz():
    return DMZProtocol()


@pytest.fixture
def policy():
    return DataHandlingPolicy(
        max_retention_seconds=3600,
        allow_persistence=False,
        allow_training=False,
        allow_forwarding=False,
    )


SENDER = "did:nexus:sender-agent"
RECEIVER = "did:nexus:receiver-agent"
DATA = b"sensitive data payload"


class TestInitiateTransfer:
    """Tests for DMZProtocol.initiate_transfer()."""

    @pytest.mark.asyncio
    async def test_initiate_returns_request(self, dmz, policy):
        request = await dmz.initiate_transfer(
            SENDER, RECEIVER, DATA, "internal", policy, expiry_hours=24,
        )
        assert isinstance(request, DMZRequest)
        assert request.sender_did == SENDER
        assert request.receiver_did == RECEIVER
        assert request.data_classification == "internal"
        assert request.data_size_bytes == len(DATA)

    @pytest.mark.asyncio
    async def test_initiate_creates_audit_entry(self, dmz, policy):
        request = await dmz.initiate_transfer(
            SENDER, RECEIVER, DATA, "confidential", policy,
        )
        trail = dmz.get_audit_trail(request.request_id)
        assert len(trail) == 1
        assert trail[0]["event"] == "transfer_initiated"

    @pytest.mark.asyncio
    async def test_initiate_sets_expiry(self, dmz, policy):
        request = await dmz.initiate_transfer(
            SENDER, RECEIVER, DATA, "internal", policy, expiry_hours=12,
        )
        assert request.expires_at is not None
        assert request.expires_at > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_initiate_computes_data_hash(self, dmz, policy):
        import hashlib
        expected_hash = hashlib.sha256(DATA).hexdigest()
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        assert request.data_hash == expected_hash


class TestSignPolicy:
    """Tests for DMZProtocol.sign_policy()."""

    @pytest.mark.asyncio
    async def test_sign_policy_success(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        signed = await dmz.sign_policy(request.request_id, RECEIVER, "receiver_sig")
        assert isinstance(signed, SignedPolicy)
        assert signed.signer_did == RECEIVER
        assert signed.verified is True

    @pytest.mark.asyncio
    async def test_sign_policy_wrong_receiver_raises(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        with pytest.raises(ValueError, match="Only intended receiver"):
            await dmz.sign_policy(request.request_id, "did:nexus:wrong", "sig")

    @pytest.mark.asyncio
    async def test_sign_policy_invalid_transfer_raises(self, dmz):
        with pytest.raises(ValueError, match="Transfer not found"):
            await dmz.sign_policy("nonexistent", RECEIVER, "sig")


class TestReleaseKey:
    """Tests for DMZProtocol.release_key()."""

    @pytest.mark.asyncio
    async def test_release_key_after_signing(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        await dmz.sign_policy(request.request_id, RECEIVER, "sig")
        key = await dmz.release_key(request.request_id, RECEIVER)
        assert isinstance(key, bytes)
        assert len(key) == 32  # AES-256

    @pytest.mark.asyncio
    async def test_release_key_without_signing_raises(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        with pytest.raises(ValueError, match="Policy must be signed"):
            await dmz.release_key(request.request_id, RECEIVER)

    @pytest.mark.asyncio
    async def test_release_key_wrong_requester_raises(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        await dmz.sign_policy(request.request_id, RECEIVER, "sig")
        with pytest.raises(ValueError, match="Only intended receiver"):
            await dmz.release_key(request.request_id, "did:nexus:wrong")


class TestRecordDataAccess:
    """Tests for DMZProtocol.record_data_access()."""

    @pytest.mark.asyncio
    async def test_record_access(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        await dmz.record_data_access(request.request_id, RECEIVER)
        transfer = dmz.get_transfer(request.request_id)
        assert transfer.data_accessed is True


class TestCompleteTransfer:
    """Tests for DMZProtocol.complete_transfer()."""

    @pytest.mark.asyncio
    async def test_complete_transfer(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        transfer = await dmz.complete_transfer(request.request_id)
        assert transfer.completed is True
        assert transfer.completed_at is not None

    @pytest.mark.asyncio
    async def test_complete_cleans_up_key(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        await dmz.complete_transfer(request.request_id)
        assert request.request_id not in dmz._encryption_keys


class TestAuditTrail:
    """Tests for DMZProtocol.get_audit_trail()."""

    @pytest.mark.asyncio
    async def test_full_audit_trail(self, dmz, policy):
        request = await dmz.initiate_transfer(SENDER, RECEIVER, DATA, "internal", policy)
        await dmz.sign_policy(request.request_id, RECEIVER, "sig")
        await dmz.release_key(request.request_id, RECEIVER)
        await dmz.record_data_access(request.request_id, RECEIVER)
        await dmz.complete_transfer(request.request_id)
        trail = dmz.get_audit_trail(request.request_id)
        events = [e["event"] for e in trail]
        assert "transfer_initiated" in events
        assert "policy_signed" in events
        assert "key_released" in events
        assert "data_accessed" in events
        assert "transfer_completed" in events


class TestDataHandlingPolicyModel:
    """Tests for DataHandlingPolicy validation."""

    def test_default_policy(self):
        p = DataHandlingPolicy()
        assert p.allow_persistence is False
        assert p.allow_training is False
        assert p.audit_required is True
        assert p.require_encryption_at_rest is True

    def test_max_retention_validation(self):
        with pytest.raises(Exception):
            DataHandlingPolicy(max_retention_seconds=3000000)  # > 30 days

    def test_compute_hash_deterministic(self):
        p1 = DataHandlingPolicy(max_retention_seconds=3600, allow_persistence=False)
        p2 = DataHandlingPolicy(max_retention_seconds=3600, allow_persistence=False)
        assert p1.compute_hash() == p2.compute_hash()

    def test_compute_hash_changes_with_values(self):
        p1 = DataHandlingPolicy(allow_persistence=False)
        p2 = DataHandlingPolicy(allow_persistence=True)
        assert p1.compute_hash() != p2.compute_hash()
