# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Nexus schema models."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.schemas.manifest import (
    AgentIdentity,
    AgentCapabilities,
    AgentPrivacy,
    MuteRules,
    AgentManifest,
)
from nexus.schemas.escrow import EscrowRequest, EscrowReceipt, EscrowStatus
from nexus.schemas.receipt import JobReceipt, JobCompletionReceipt, SignedReceipt
from nexus.schemas.compliance import ComplianceRecord, ComplianceAuditReport


class TestAgentIdentity:
    """Tests for AgentIdentity DID format validation."""

    def test_valid_did(self):
        identity = AgentIdentity(
            did="did:nexus:my-agent", verification_key="ed25519:key123", owner_id="org",
        )
        assert identity.did == "did:nexus:my-agent"

    def test_invalid_did_prefix(self):
        with pytest.raises(Exception):
            AgentIdentity(
                did="did:other:my-agent", verification_key="ed25519:key123", owner_id="org",
            )

    def test_invalid_verification_key(self):
        with pytest.raises(Exception):
            AgentIdentity(
                did="did:nexus:my-agent", verification_key="rsa:key123", owner_id="org",
            )

    def test_valid_ed25519_key(self):
        identity = AgentIdentity(
            did="did:nexus:agent", verification_key="ed25519:abc", owner_id="org",
        )
        assert identity.verification_key == "ed25519:abc"


class TestAgentCapabilities:
    """Tests for AgentCapabilities constraints."""

    def test_max_concurrency_min(self):
        with pytest.raises(Exception):
            AgentCapabilities(max_concurrency=0)

    def test_max_concurrency_max(self):
        with pytest.raises(Exception):
            AgentCapabilities(max_concurrency=1001)

    def test_max_concurrency_valid(self):
        cap = AgentCapabilities(max_concurrency=500)
        assert cap.max_concurrency == 500

    def test_sla_latency_min(self):
        with pytest.raises(Exception):
            AgentCapabilities(sla_latency_ms=50)  # min 100

    def test_sla_latency_max(self):
        with pytest.raises(Exception):
            AgentCapabilities(sla_latency_ms=500000)  # max 300000

    def test_sla_latency_valid(self):
        cap = AgentCapabilities(sla_latency_ms=10000)
        assert cap.sla_latency_ms == 10000

    def test_defaults(self):
        cap = AgentCapabilities()
        assert cap.max_concurrency == 10
        assert cap.idempotency is False
        assert cap.reversibility == "partial"


class TestAgentManifest:
    """Tests for AgentManifest creation."""

    def test_valid_manifest(self, sample_manifest):
        assert sample_manifest.identity.did == "did:nexus:test-agent-v1"
        assert sample_manifest.verification_level == "registered"

    def test_is_attestation_valid_false_by_default(self, sample_manifest):
        assert sample_manifest.is_attestation_valid() is False

    def test_is_attestation_valid_when_set(self):
        m = AgentManifest(
            identity=AgentIdentity(
                did="did:nexus:a", verification_key="ed25519:k", owner_id="org",
            ),
            attestation_signature="sig_123",
            attestation_expires=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        assert m.is_attestation_valid() is True

    def test_is_attestation_expired(self):
        m = AgentManifest(
            identity=AgentIdentity(
                did="did:nexus:a", verification_key="ed25519:k", owner_id="org",
            ),
            attestation_signature="sig_123",
            attestation_expires=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert m.is_attestation_valid() is False

    def test_to_iatp_manifest(self, sample_manifest):
        iatp = sample_manifest.to_iatp_manifest()
        assert iatp["$schema"].startswith("https://")
        assert iatp["identity"]["verification_key"] == "ed25519:testkey123abc"


class TestEscrowRequestConstraints:
    """Tests for EscrowRequest validation."""

    def test_credits_must_be_positive(self):
        with pytest.raises(Exception):
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="h", credits=-1,
            )

    def test_credits_max_10000(self):
        with pytest.raises(Exception):
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="h", credits=10001,
            )

    def test_timeout_min_60(self):
        with pytest.raises(Exception):
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="h", credits=100, timeout_seconds=30,
            )

    def test_timeout_max_86400(self):
        with pytest.raises(Exception):
            EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="h", credits=100, timeout_seconds=100000,
            )


class TestJobReceipt:
    """Tests for JobReceipt.compute_hash()."""

    def test_compute_hash_deterministic(self):
        now = datetime(2024, 1, 1, 12, 0, 0)
        r1 = JobReceipt(
            receipt_id="r1", task_id="t1", requester_did="did:nexus:a",
            provider_did="did:nexus:b", task_hash="hash1", created_at=now,
        )
        r2 = JobReceipt(
            receipt_id="r1", task_id="t1", requester_did="did:nexus:a",
            provider_did="did:nexus:b", task_hash="hash1", created_at=now,
        )
        assert r1.compute_hash() == r2.compute_hash()

    def test_compute_hash_differs_for_different_data(self):
        now = datetime(2024, 1, 1, 12, 0, 0)
        r1 = JobReceipt(
            receipt_id="r1", task_id="t1", requester_did="did:nexus:a",
            provider_did="did:nexus:b", task_hash="hash1", created_at=now,
        )
        r2 = JobReceipt(
            receipt_id="r2", task_id="t1", requester_did="did:nexus:a",
            provider_did="did:nexus:b", task_hash="hash1", created_at=now,
        )
        assert r1.compute_hash() != r2.compute_hash()

    def test_hash_is_sha256(self):
        r = JobReceipt(
            receipt_id="r1", task_id="t1", requester_did="did:nexus:a",
            provider_did="did:nexus:b", task_hash="hash1",
        )
        h = r.compute_hash()
        assert len(h) == 64  # SHA-256 hex digest length


class TestSignedReceipt:
    """Tests for SignedReceipt methods."""

    def _make_signed_receipt(self, req_sig=None, prov_sig=None, nexus_witnessed=False, nexus_sig=None):
        receipt = JobCompletionReceipt(
            receipt_id="r1", task_id="t1", requester_did="did:nexus:a",
            provider_did="did:nexus:b", task_hash="h", outcome="success",
            duration_ms=100,
        )
        return SignedReceipt(
            receipt=receipt,
            receipt_hash=receipt.compute_hash(),
            requester_signature=req_sig,
            provider_signature=prov_sig,
            nexus_witnessed=nexus_witnessed,
            nexus_signature=nexus_sig,
        )

    def test_is_fully_signed_both(self):
        sr = self._make_signed_receipt(req_sig="sig_r", prov_sig="sig_p")
        assert sr.is_fully_signed() is True

    def test_is_not_fully_signed_missing_provider(self):
        sr = self._make_signed_receipt(req_sig="sig_r")
        assert sr.is_fully_signed() is False

    def test_is_not_fully_signed_missing_requester(self):
        sr = self._make_signed_receipt(prov_sig="sig_p")
        assert sr.is_fully_signed() is False

    def test_is_nexus_witnessed(self):
        sr = self._make_signed_receipt(nexus_witnessed=True, nexus_sig="sig_n")
        assert sr.is_nexus_witnessed() is True

    def test_is_not_nexus_witnessed_no_sig(self):
        sr = self._make_signed_receipt(nexus_witnessed=True, nexus_sig=None)
        assert sr.is_nexus_witnessed() is False

    def test_is_not_nexus_witnessed_flag_false(self):
        sr = self._make_signed_receipt(nexus_witnessed=False, nexus_sig="sig_n")
        assert sr.is_nexus_witnessed() is False


class TestComplianceRecord:
    """Tests for ComplianceRecord.compute_hash()."""

    def test_compute_hash_deterministic(self):
        now = datetime(2024, 6, 1, 12, 0, 0)
        r1 = ComplianceRecord(event_id="e1", event_type="agent_registered", timestamp=now)
        r2 = ComplianceRecord(event_id="e1", event_type="agent_registered", timestamp=now)
        assert r1.compute_hash() == r2.compute_hash()

    def test_compute_hash_excludes_signature(self):
        now = datetime(2024, 6, 1, 12, 0, 0)
        r1 = ComplianceRecord(event_id="e1", event_type="agent_registered", timestamp=now)
        r2 = ComplianceRecord(
            event_id="e1", event_type="agent_registered", timestamp=now, signature="sig",
        )
        assert r1.compute_hash() == r2.compute_hash()


class TestEscrowReceiptMethods:
    """Tests for EscrowReceipt.is_expired() and is_active()."""

    def _make_receipt(self, status=EscrowStatus.PENDING, expires_delta_hours=1):
        return EscrowReceipt(
            escrow_id="e1",
            request=EscrowRequest(
                requester_did="did:nexus:a", provider_did="did:nexus:b",
                task_hash="h", credits=100,
            ),
            status=status,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=expires_delta_hours),
            requester_signature="sig",
        )

    def test_not_expired(self):
        r = self._make_receipt(expires_delta_hours=1)
        assert r.is_expired() is False

    def test_expired(self):
        r = self._make_receipt(expires_delta_hours=-1)
        assert r.is_expired() is True

    def test_active_pending(self):
        r = self._make_receipt(status=EscrowStatus.PENDING)
        assert r.is_active() is True

    def test_active_active(self):
        r = self._make_receipt(status=EscrowStatus.ACTIVE)
        assert r.is_active() is True

    def test_active_awaiting(self):
        r = self._make_receipt(status=EscrowStatus.AWAITING_VALIDATION)
        assert r.is_active() is True

    def test_not_active_released(self):
        r = self._make_receipt(status=EscrowStatus.RELEASED)
        assert r.is_active() is False

    def test_not_active_refunded(self):
        r = self._make_receipt(status=EscrowStatus.REFUNDED)
        assert r.is_active() is False
