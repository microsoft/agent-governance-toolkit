# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for attestation evidence collectors."""

from collections.abc import Callable

import pytest

from agentmesh.exceptions import AttestationCollectionError
from agentmesh.identity.attestation import (
    AttestationRequest,
    KeyOrigin,
    compute_binding_hash,
    compute_startup_binding,
    public_key_hash_hex,
)
from agentmesh.identity.attestation_collector import (
    AttestationCollector,
    MockAttestationCollector,
    NoopAttestationCollector,
)


@pytest.mark.asyncio
async def test_noop_attestation_collector_returns_no_evidence() -> None:
    collector: AttestationCollector = NoopAttestationCollector()

    evidence = await collector.collect(
        AttestationRequest(binding=b"opaque-runtime-binding")
    )

    assert evidence is None
    assert collector.platform() == "none"


@pytest.mark.asyncio
async def test_mock_attestation_collector_returns_bound_evidence() -> None:
    public_key_hash = public_key_hash_hex(b"\x02" * 32)
    binding = compute_startup_binding("did:mesh:agent-1", public_key_hash)
    collector = MockAttestationCollector(
        platform="mock-tee",
        key_origin=KeyOrigin.TEE_GENERATED,
        runtime_measurements={"measurement": "policy-v1"},
        secure_boot_verified=True,
    )

    evidence = await collector.collect(
        AttestationRequest(
            binding=binding,
            agent_did="did:mesh:agent-1",
            public_key_hash=public_key_hash,
        )
    )

    assert evidence.platform == "mock-tee"
    assert evidence.key_origin is KeyOrigin.TEE_GENERATED
    assert evidence.key_bound_to_tee is True
    assert evidence.runtime_measurements["measurement"] == "policy-v1"
    assert evidence.secure_boot_verified is True
    assert evidence.binding_hash == compute_binding_hash(binding)
    assert evidence.matches_binding(binding=binding)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "platform,binding",
    [
        ("aws-nitro", b"nitro-user-data-binding"),
        ("intel-tdx", b"tdx-report-data-binding"),
        ("gcp-confidential-space", b"gcp-eat-nonce-binding"),
    ],
)
async def test_mock_attestation_collector_accepts_opaque_provider_bindings(
    platform: str,
    binding: bytes,
) -> None:
    collector = MockAttestationCollector(platform=platform)

    evidence = await collector.collect(AttestationRequest(binding=binding))

    assert evidence.platform == platform
    assert evidence.binding_hash == compute_binding_hash(binding)
    assert evidence.matches_binding(binding=binding)


@pytest.mark.asyncio
async def test_mock_attestation_collector_wraps_configured_error() -> None:
    collector = MockAttestationCollector(error=RuntimeError("provider unavailable"))

    with pytest.raises(AttestationCollectionError, match="provider unavailable"):
        await collector.collect(
            AttestationRequest(binding=b"opaque-runtime-binding")
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
