# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for attestation evidence collectors."""

from collections.abc import Callable

import pytest

from agentmesh.exceptions import AttestationCollectionError
from agentmesh.identity.attestation import KeyOrigin, public_key_hash_hex
from agentmesh.identity.attestation_collector import (
    AttestationCollector,
    MockAttestationCollector,
    NoopAttestationCollector,
)


@pytest.mark.asyncio
async def test_noop_attestation_collector_returns_no_evidence() -> None:
    collector: AttestationCollector = NoopAttestationCollector()

    evidence = await collector.collect(
        agent_did="did:mesh:agent-1",
        challenge_id="challenge_123",
        nonce="nonce-abc",
        public_key_hash=public_key_hash_hex(b"\x01" * 32),
    )

    assert evidence is None
    assert collector.platform() == "none"


@pytest.mark.asyncio
async def test_mock_attestation_collector_returns_bound_evidence() -> None:
    public_key_hash = public_key_hash_hex(b"\x02" * 32)
    collector = MockAttestationCollector(
        platform="azure-caci",
        key_origin=KeyOrigin.SKR,
        runtime_measurements={"cce_policy_hash": "policy-v1"},
        secure_boot_verified=True,
    )

    evidence = await collector.collect(
        agent_did="did:mesh:agent-1",
        challenge_id="challenge_123",
        nonce="nonce-abc",
        public_key_hash=public_key_hash,
    )

    assert evidence.platform == "azure-caci"
    assert evidence.key_origin is KeyOrigin.SKR
    assert evidence.key_bound_to_tee is True
    assert evidence.runtime_measurements["cce_policy_hash"] == "policy-v1"
    assert evidence.secure_boot_verified is True
    assert evidence.matches_binding(
        agent_did="did:mesh:agent-1",
        challenge_id="challenge_123",
        nonce="nonce-abc",
        public_key_hash=public_key_hash,
    )


@pytest.mark.asyncio
async def test_mock_attestation_collector_wraps_configured_error() -> None:
    collector = MockAttestationCollector(error=RuntimeError("sidecar unavailable"))

    with pytest.raises(AttestationCollectionError, match="sidecar unavailable"):
        await collector.collect(
            agent_did="did:mesh:agent-1",
            challenge_id="challenge_123",
            nonce="nonce-abc",
            public_key_hash=public_key_hash_hex(b"\x03" * 32),
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: MockAttestationCollector(platform=""),
        lambda: MockAttestationCollector(evidence=""),
        lambda: MockAttestationCollector(ttl_seconds=0),
        lambda: MockAttestationCollector(latency_seconds=-1.0),
    ],
)
def test_mock_attestation_collector_rejects_invalid_configuration(
    factory: Callable[[], MockAttestationCollector],
) -> None:
    with pytest.raises(ValueError):
        factory()

