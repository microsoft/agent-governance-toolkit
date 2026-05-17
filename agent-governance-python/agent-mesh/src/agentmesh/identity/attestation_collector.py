# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Provider-neutral attestation evidence collection interfaces and mocks."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from agentmesh.exceptions import AttestationCollectionError

from .attestation import (
    DEFAULT_EVIDENCE_TTL_SECONDS,
    AttestationEvidence,
    KeyOrigin,
    compute_report_data_hash_hex,
)


class AttestationCollector(ABC):
    """Collects attestation evidence from the current runtime environment."""

    @abstractmethod
    async def collect(
        self,
        agent_did: str,
        challenge_id: str,
        nonce: str,
        public_key_hash: str,
    ) -> AttestationEvidence | None:
        """Gather platform evidence bound to the agent identity and challenge."""

    @abstractmethod
    def platform(self) -> str:
        """Return the attestation platform identifier."""


class NoopAttestationCollector(AttestationCollector):
    """Collector used when attestation is disabled."""

    async def collect(
        self,
        agent_did: str,
        challenge_id: str,
        nonce: str,
        public_key_hash: str,
    ) -> None:
        """Return no evidence without touching a platform attestation provider."""
        return None

    def platform(self) -> str:
        """Return the no-op platform identifier."""
        return "none"


class MockAttestationCollector(AttestationCollector):
    """CI-safe collector that synthesizes valid attestation evidence."""

    def __init__(
        self,
        *,
        platform: str = "mock",
        evidence: str = "mock-attestation-evidence",
        key_origin: KeyOrigin = KeyOrigin.LOCAL,
        runtime_measurements: Mapping[str, str] | None = None,
        secure_boot_verified: bool = False,
        ttl_seconds: int = DEFAULT_EVIDENCE_TTL_SECONDS,
        latency_seconds: float = 0.0,
        error: Exception | None = None,
    ) -> None:
        if not platform:
            raise ValueError("platform must not be empty")
        if not evidence:
            raise ValueError("evidence must not be empty")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if latency_seconds < 0:
            raise ValueError("latency_seconds must not be negative")

        self._platform = platform
        self._evidence = evidence
        self._key_origin = key_origin
        self._runtime_measurements = dict(runtime_measurements or {})
        self._secure_boot_verified = secure_boot_verified
        self._ttl_seconds = ttl_seconds
        self._latency_seconds = latency_seconds
        self._error = error

    async def collect(
        self,
        agent_did: str,
        challenge_id: str,
        nonce: str,
        public_key_hash: str,
    ) -> AttestationEvidence:
        """Return synthetic evidence with a deterministic ADR 0010 binding."""
        if self._latency_seconds:
            await asyncio.sleep(self._latency_seconds)
        if self._error is not None:
            raise AttestationCollectionError(str(self._error)) from self._error

        timestamp = datetime.now(UTC)
        return AttestationEvidence(
            platform=self._platform,
            evidence=self._evidence,
            agent_did=agent_did,
            challenge_id=challenge_id,
            nonce=nonce,
            public_key_hash=public_key_hash,
            report_data_hash=compute_report_data_hash_hex(
                agent_did=agent_did,
                challenge_id=challenge_id,
                nonce=nonce,
                public_key_hash=public_key_hash,
            ),
            key_origin=self._key_origin,
            runtime_measurements=self._runtime_measurements,
            secure_boot_verified=self._secure_boot_verified,
            timestamp=timestamp,
            expires_at=timestamp + timedelta(seconds=self._ttl_seconds),
        )

    def platform(self) -> str:
        """Return the configured mock platform identifier."""
        return self._platform

