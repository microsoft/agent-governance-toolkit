# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from datetime import UTC, datetime, timedelta

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.identity.attestation import (
    AttestationEvidence,
    KeyOrigin,
    compute_binding_hash,
    compute_startup_binding,
)
from agentmesh.identity.attestation_verifier import MockAttestationVerifier
from agentmesh.identity.tee_keystore import MockSKRKeyStore, TEEKeyHandle
from agentmesh.trust.bridge import TrustBridge


def _make_identity(name: str) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        organization="Microsoft",
        capabilities=["read:data"],
    )


def _make_registry(*identities: AgentIdentity) -> IdentityRegistry:
    registry = IdentityRegistry()
    for identity in identities:
        registry.register(identity)
    return registry


def _make_evidence(
    *,
    agent_did: str,
    handle: TEEKeyHandle,
    key_origin: KeyOrigin | None = None,
) -> AttestationEvidence:
    timestamp = datetime.now(UTC)
    binding = compute_startup_binding(
        agent_did=agent_did,
        public_key_hash=handle.public_key_hash(),
    )
    binding_hash = compute_binding_hash(binding)
    return AttestationEvidence(
        platform="mock",
        evidence_type="mock",
        evidence="bridge-test-evidence",
        agent_did=agent_did,
        timestamp=timestamp,
        expires_at=timestamp + timedelta(minutes=5),
        runtime_measurements={},
        key_origin=key_origin or handle.key_origin,
        public_key_hash=handle.public_key_hash(),
        binding_hash=binding_hash,
        report_data_hash=binding_hash,
        secure_boot_verified=True,
        debug_disabled=True,
    )


@pytest.mark.asyncio
async def test_trust_bridge_threads_attestation_requirements_to_handshake() -> None:
    verifier_identity = _make_identity("verifier")
    responder_identity = _make_identity("responder")
    registry = _make_registry(verifier_identity, responder_identity)
    store = MockSKRKeyStore()
    handle = await store.acquire_key("responder-key")
    evidence = _make_evidence(
        agent_did=str(responder_identity.did),
        handle=handle,
    )

    bridge = TrustBridge(
        agent_did=str(verifier_identity.did),
        identity=verifier_identity,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        tee_key_store=store,
        tee_key_id="responder-key",
        attestation_evidence=evidence,
        require_attestation=True,
        require_tee_bound_key=True,
        default_trust_threshold=0,
    )

    result = await bridge.verify_peer(str(responder_identity.did))

    assert result.verified is True
    assert result.attestation_verified is True
    assert result.key_origin is KeyOrigin.SKR
