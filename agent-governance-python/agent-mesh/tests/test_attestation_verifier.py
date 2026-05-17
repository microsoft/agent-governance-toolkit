# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for attestation evidence verifiers."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from agentmesh.exceptions import AttestationVerificationError
from agentmesh.identity.attestation import (
    AttestationEvidence,
    ImageMatchPolicy,
    KeyOrigin,
    ReferenceValues,
    compute_report_data_hash_hex,
    public_key_hash_hex,
)
from agentmesh.identity.attestation_verifier import MockAttestationVerifier


def _valid_evidence(**overrides: object) -> AttestationEvidence:
    public_key_hash = public_key_hash_hex(b"\x01" * 32)
    values: dict[str, Any] = {
        "platform": "azure-caci",
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
        "runtime_measurements": {"cce_policy_hash": "policy-v1"},
        "secure_boot_verified": True,
    }
    values.update(overrides)
    return AttestationEvidence(**values)


@pytest.mark.asyncio
async def test_mock_attestation_verifier_returns_claims() -> None:
    verifier = MockAttestationVerifier(
        claims={"x-ms-sevsnpvm-is-debuggable": "false"},
    )

    claims = await verifier.verify(
        _valid_evidence(),
        ReferenceValues(
            required_platform="azure-caci",
            expected_measurements={"cce_policy_hash": "policy-v1"},
        ),
    )

    assert claims.platform == "azure-caci"
    assert claims.platform_verified is True
    assert claims.report_data_match is True
    assert claims.key_origin is KeyOrigin.SKR
    assert claims.runtime_measurements["cce_policy_hash"] == "policy-v1"


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_platform_mismatch() -> None:
    verifier = MockAttestationVerifier()

    with pytest.raises(AttestationVerificationError, match="platform mismatch"):
        await verifier.verify(
            _valid_evidence(),
            ReferenceValues(required_platform="azure-cvm"),
        )


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_cce_policy_hash_mismatch() -> None:
    verifier = MockAttestationVerifier()

    with pytest.raises(AttestationVerificationError, match="measurement mismatch"):
        await verifier.verify(
            _valid_evidence(),
            ReferenceValues(expected_measurements={"cce_policy_hash": "policy-v2"}),
        )


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_required_claim_mismatch() -> None:
    verifier = MockAttestationVerifier(claims={"x-ms-compliance-status": "non-compliant"})

    with pytest.raises(AttestationVerificationError, match="claim mismatch"):
        await verifier.verify(
            _valid_evidence(),
            ReferenceValues(required_claims={"x-ms-compliance-status": "compliant"}),
        )


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_disallowed_tcb_status() -> None:
    verifier = MockAttestationVerifier(tcb_status="out_of_date")

    with pytest.raises(AttestationVerificationError, match="TCB status"):
        await verifier.verify(
            _valid_evidence(),
            ReferenceValues(allowed_tcb_statuses=["up_to_date"]),
        )


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_debug_mode() -> None:
    verifier = MockAttestationVerifier(claims={"x-ms-sevsnpvm-is-debuggable": "true"})

    with pytest.raises(AttestationVerificationError, match="debug mode"):
        await verifier.verify(_valid_evidence(), ReferenceValues())


@pytest.mark.asyncio
async def test_mock_attestation_verifier_supports_signing_identity_policy() -> None:
    verifier = MockAttestationVerifier(claims={"image_signer": "trusted-ci"})

    claims = await verifier.verify(
        _valid_evidence(),
        ReferenceValues(
            image_match_policy=ImageMatchPolicy.SIGNING_IDENTITY,
            allowed_image_signers=["trusted-ci"],
        ),
    )

    assert claims.claims["image_signer"] == "trusted-ci"


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_signing_identity_mismatch() -> None:
    verifier = MockAttestationVerifier(claims={"image_signer": "untrusted-ci"})

    with pytest.raises(AttestationVerificationError, match="image signer mismatch"):
        await verifier.verify(
            _valid_evidence(),
            ReferenceValues(
                image_match_policy=ImageMatchPolicy.SIGNING_IDENTITY,
                allowed_image_signers=["trusted-ci"],
            ),
        )


@pytest.mark.asyncio
async def test_mock_attestation_verifier_rejects_expired_evidence() -> None:
    timestamp = datetime.now(UTC) - timedelta(minutes=10)
    evidence = _valid_evidence(
        timestamp=timestamp,
        expires_at=timestamp + timedelta(minutes=5),
    )

    with pytest.raises(AttestationVerificationError, match="expired"):
        await MockAttestationVerifier().verify(evidence, ReferenceValues())


@pytest.mark.asyncio
async def test_mock_attestation_verifier_wraps_configured_error() -> None:
    verifier = MockAttestationVerifier(error=RuntimeError("MAA unavailable"))

    with pytest.raises(AttestationVerificationError, match="MAA unavailable"):
        await verifier.verify(_valid_evidence(), ReferenceValues())


@pytest.mark.parametrize(
    "factory",
    [
        lambda: MockAttestationVerifier(tcb_status=""),
        lambda: MockAttestationVerifier(ttl_seconds=0),
        lambda: MockAttestationVerifier(latency_seconds=-1.0),
    ],
)
def test_mock_attestation_verifier_rejects_invalid_configuration(
    factory: Callable[[], MockAttestationVerifier],
) -> None:
    with pytest.raises(ValueError):
        factory()

