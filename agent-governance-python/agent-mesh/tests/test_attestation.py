# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for provider-neutral attestation models."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentmesh.identity.attestation import (
    AttestationClaims,
    AttestationEvidence,
    ConfidentialLevel,
    KeyOrigin,
    ReferenceValues,
    compute_report_data_hash_hex,
    public_key_hash_hex,
)


def _valid_evidence(**overrides: object) -> AttestationEvidence:
    public_key_hash = public_key_hash_hex(b"\x01" * 32)
    values: dict[str, object] = {
        "platform": "azure-sev-snp",
        "evidence": "base64-attestation-report",
        "agent_did": "did:mesh:agent-1",
        "challenge_id": "challenge_123",
        "nonce": "nonce-abc",
        "public_key_hash": public_key_hash,
        "report_data_hash": compute_report_data_hash_hex(
            "did:mesh:agent-1",
            "challenge_123",
            "nonce-abc",
            public_key_hash,
        ),
        "key_origin": KeyOrigin.SKR,
        "runtime_measurements": {"measurement": "abc123"},
        "secure_boot_verified": True,
    }
    values.update(overrides)
    return AttestationEvidence(**values)


class TestAttestationEvidence:
    """Tests for the raw attestation evidence model."""

    def test_valid_evidence(self) -> None:
        evidence = _valid_evidence()

        assert evidence.platform == "azure-sev-snp"
        assert evidence.key_origin is KeyOrigin.SKR
        assert evidence.key_bound_to_tee is True
        assert evidence.runtime_measurements["measurement"] == "abc123"
        assert evidence.is_expired() is False

    def test_local_key_origin_is_not_tee_bound(self) -> None:
        public_key_hash = public_key_hash_hex(b"\x02" * 32)
        evidence = _valid_evidence(
            public_key_hash=public_key_hash,
            key_origin=KeyOrigin.LOCAL,
            report_data_hash=compute_report_data_hash_hex(
                "did:mesh:agent-1",
                "challenge_123",
                "nonce-abc",
                public_key_hash,
            ),
        )

        assert evidence.key_bound_to_tee is False

    def test_tee_generated_key_origin_is_tee_bound(self) -> None:
        evidence = _valid_evidence(key_origin=KeyOrigin.TEE_GENERATED)

        assert evidence.key_bound_to_tee is True

    def test_rejects_empty_required_fields(self) -> None:
        with pytest.raises(ValidationError, match="value must not be empty"):
            _valid_evidence(platform="")

    def test_rejects_invalid_public_key_hash(self) -> None:
        with pytest.raises(ValidationError, match="public_key_hash"):
            _valid_evidence(public_key_hash="not-a-digest")

    def test_rejects_invalid_report_data_hash(self) -> None:
        with pytest.raises(ValidationError, match="report_data_hash"):
            _valid_evidence(report_data_hash="f" * 63)

    def test_rejects_mismatched_report_data_hash(self) -> None:
        with pytest.raises(ValidationError, match="report_data_hash does not match"):
            _valid_evidence(report_data_hash="0" * 64)

    def test_rejects_expiry_before_timestamp(self) -> None:
        timestamp = datetime.now(UTC)

        with pytest.raises(ValidationError, match="expires_at must be later"):
            _valid_evidence(
                timestamp=timestamp,
                expires_at=timestamp - timedelta(seconds=1),
            )

    def test_expired_evidence(self) -> None:
        timestamp = datetime.now(UTC) - timedelta(minutes=10)
        expires_at = timestamp + timedelta(minutes=5)
        evidence = _valid_evidence(timestamp=timestamp, expires_at=expires_at)

        assert evidence.is_expired(datetime.now(UTC)) is True

    def test_normalizes_naive_datetimes_to_utc(self) -> None:
        timestamp = datetime(2026, 1, 1, 12, 0, 0)
        expires_at = datetime(2026, 1, 1, 12, 5, 0)
        evidence = _valid_evidence(timestamp=timestamp, expires_at=expires_at)

        assert evidence.timestamp.tzinfo is UTC
        assert evidence.expires_at.tzinfo is UTC


class TestAttestationClaims:
    """Tests for verified attestation claims."""

    def test_valid_claims(self) -> None:
        claims = AttestationClaims(
            platform="azure-sev-snp",
            confidential_level=ConfidentialLevel.TEE_VM,
            key_origin=KeyOrigin.SKR,
            platform_verified=True,
            report_data_match=True,
            tcb_status="up_to_date",
            runtime_measurements={"launch_measurement": "abc"},
            claims={"x-ms-attestation-type": "sevsnpvm"},
        )

        assert claims.platform_verified is True
        assert claims.key_bound_to_tee is True
        assert claims.is_expired() is False

    def test_claims_can_expire(self) -> None:
        verified_at = datetime.now(UTC) - timedelta(minutes=10)
        claims = AttestationClaims(
            platform="azure-sev-snp",
            verified_at=verified_at,
            expires_at=verified_at + timedelta(minutes=5),
        )

        assert claims.is_expired(datetime.now(UTC)) is True

    def test_rejects_empty_platform(self) -> None:
        with pytest.raises(ValidationError, match="value must not be empty"):
            AttestationClaims(platform="")


class TestReferenceValues:
    """Tests for verifier reference-value configuration."""

    def test_defaults(self) -> None:
        values = ReferenceValues()

        assert values.required_platform is None
        assert values.expected_measurements == {}
        assert values.required_claims == {}
        assert values.allowed_tcb_statuses == ["up_to_date"]
        assert values.require_debug_disabled is True


class TestPublicKeyHash:
    """Tests for Ed25519 public-key hashing helper."""

    def test_public_key_hash_hex(self) -> None:
        digest = public_key_hash_hex(b"\x01" * 32)

        assert len(digest) == 64
        assert digest == public_key_hash_hex(b"\x01" * 32)

    def test_rejects_wrong_public_key_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            public_key_hash_hex(b"\x01" * 31)
