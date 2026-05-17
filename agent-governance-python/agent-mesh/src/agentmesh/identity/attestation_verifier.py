# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Provider-neutral attestation verification interfaces and mocks."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from agentmesh.exceptions import AttestationVerificationError

from .attestation import (
    DEFAULT_EVIDENCE_TTL_SECONDS,
    AttestationClaims,
    AttestationEvidence,
    ConfidentialLevel,
    ImageMatchPolicy,
    ReferenceValues,
)

DEBUGGABLE_CLAIM = "x-ms-sevsnpvm-is-debuggable"
IMAGE_SIGNER_CLAIMS = ("image_signer", "x-ms-image-signer")


class AttestationVerifier(ABC):
    """Verifies attestation evidence against expected reference values."""

    @abstractmethod
    async def verify(
        self,
        evidence: AttestationEvidence,
        reference_values: ReferenceValues,
    ) -> AttestationClaims:
        """Validate evidence against reference values. Raise on failure."""


class MockAttestationVerifier(AttestationVerifier):
    """CI-safe verifier with configurable success and failure modes."""

    def __init__(
        self,
        *,
        platform_verified: bool = True,
        report_data_match: bool = True,
        confidential_level: ConfidentialLevel = ConfidentialLevel.TEE_CONTAINER,
        tcb_status: str = "up_to_date",
        runtime_measurements: Mapping[str, str] | None = None,
        claims: Mapping[str, str] | None = None,
        ttl_seconds: int = DEFAULT_EVIDENCE_TTL_SECONDS,
        latency_seconds: float = 0.0,
        error: Exception | None = None,
    ) -> None:
        if not tcb_status:
            raise ValueError("tcb_status must not be empty")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if latency_seconds < 0:
            raise ValueError("latency_seconds must not be negative")

        self._platform_verified = platform_verified
        self._report_data_match = report_data_match
        self._confidential_level = confidential_level
        self._tcb_status = tcb_status
        self._runtime_measurements = dict(runtime_measurements or {})
        self._claims = dict(claims or {})
        self._ttl_seconds = ttl_seconds
        self._latency_seconds = latency_seconds
        self._error = error

    async def verify(
        self,
        evidence: AttestationEvidence,
        reference_values: ReferenceValues,
    ) -> AttestationClaims:
        """Validate synthetic evidence and return normalized attestation claims."""
        if self._latency_seconds:
            await asyncio.sleep(self._latency_seconds)
        if self._error is not None:
            raise AttestationVerificationError(str(self._error)) from self._error
        if evidence.is_expired():
            raise AttestationVerificationError("attestation evidence is expired")
        if not self._platform_verified:
            raise AttestationVerificationError("attestation platform was not verified")
        if not self._report_data_match:
            raise AttestationVerificationError("attestation report data did not match")

        runtime_measurements = {**evidence.runtime_measurements, **self._runtime_measurements}
        claims = dict(self._claims)

        self._verify_reference_values(
            evidence=evidence,
            reference_values=reference_values,
            runtime_measurements=runtime_measurements,
            claims=claims,
        )

        verified_at = datetime.now(UTC)
        return AttestationClaims(
            platform=evidence.platform,
            confidential_level=self._confidential_level,
            key_origin=evidence.key_origin,
            platform_verified=True,
            report_data_match=True,
            tcb_status=self._tcb_status,
            runtime_measurements=runtime_measurements,
            verified_at=verified_at,
            expires_at=verified_at + timedelta(seconds=self._ttl_seconds),
            claims=claims,
        )

    def _verify_reference_values(
        self,
        *,
        evidence: AttestationEvidence,
        reference_values: ReferenceValues,
        runtime_measurements: Mapping[str, str],
        claims: Mapping[str, str],
    ) -> None:
        if reference_values.required_platform is not None:
            if evidence.platform != reference_values.required_platform:
                raise AttestationVerificationError(
                    "attestation platform mismatch: "
                    f"expected {reference_values.required_platform!r}, got {evidence.platform!r}"
                )

        if self._tcb_status not in reference_values.allowed_tcb_statuses:
            raise AttestationVerificationError(
                f"attestation TCB status {self._tcb_status!r} is not allowed"
            )

        if reference_values.require_debug_disabled:
            debuggable = claims.get(DEBUGGABLE_CLAIM, "false")
            if debuggable.lower() == "true":
                raise AttestationVerificationError("attestation debug mode is enabled")

        for name, expected in reference_values.expected_measurements.items():
            actual = runtime_measurements.get(name)
            if actual != expected:
                raise AttestationVerificationError(
                    f"attestation measurement mismatch for {name!r}: "
                    f"expected {expected!r}, got {actual!r}"
                )

        for name, expected in reference_values.required_claims.items():
            actual = claims.get(name)
            if actual != expected:
                raise AttestationVerificationError(
                    f"attestation claim mismatch for {name!r}: "
                    f"expected {expected!r}, got {actual!r}"
                )

        if reference_values.image_match_policy is ImageMatchPolicy.SIGNING_IDENTITY:
            self._verify_signing_identity(reference_values, claims)

    def _verify_signing_identity(
        self,
        reference_values: ReferenceValues,
        claims: Mapping[str, str],
    ) -> None:
        if not reference_values.allowed_image_signers:
            return

        signer = next((claims.get(name) for name in IMAGE_SIGNER_CLAIMS if claims.get(name)), None)
        if signer not in reference_values.allowed_image_signers:
            raise AttestationVerificationError(
                "attestation image signer mismatch: "
                f"expected one of {reference_values.allowed_image_signers!r}, got {signer!r}"
            )

