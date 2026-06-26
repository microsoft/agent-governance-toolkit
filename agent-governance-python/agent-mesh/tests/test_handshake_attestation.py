# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for optional confidential-computing attestation in trust handshakes."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.identity.attestation import (
    AttestationEvidence,
    KeyOrigin,
    compute_binding_hash,
    compute_startup_binding,
)
from agentmesh.identity.attestation_verifier import MockAttestationVerifier
from agentmesh.identity.tee_keystore import LocalTEEKeyStore, MockSKRKeyStore, TEEKeyHandle
from agentmesh.trust.handshake import HandshakeChallenge, TrustHandshake


def _make_identity(name: str) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
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
    evidence: str = "cached-attestation-token",
    **overrides: Any,
) -> AttestationEvidence:
    public_key_hash = handle.public_key_hash()
    binding = compute_startup_binding(agent_did, public_key_hash)
    binding_hash = compute_binding_hash(binding)
    values: dict[str, Any] = {
        "platform": "mock-tee",
        "evidence": evidence,
        "agent_did": agent_did,
        "public_key_hash": public_key_hash,
        "report_data_hash": binding_hash,
        "binding_hash": binding_hash,
        "key_origin": key_origin or handle.key_origin,
    }
    values.update(overrides)
    return AttestationEvidence(**values)


@pytest.mark.asyncio
async def test_required_attestation_accepts_valid_layer2_signature() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    store = MockSKRKeyStore()
    handle = await store.acquire_key("responder-key")
    challenge = HandshakeChallenge.generate()
    evidence = _make_evidence(agent_did=str(agent_b.did), handle=handle)

    responder = TrustHandshake(
        agent_did=str(agent_b.did),
        identity=agent_b,
        registry=registry,
        tee_key_store=store,
        tee_key_id="responder-key",
        attestation_evidence=evidence,
    )
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
        verifier_did=str(agent_a.did),
    )

    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
        require_tee_bound_key=True,
    )
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is True
    claims = verification["attestation_claims"]
    assert claims.key_origin is KeyOrigin.SKR
    assert claims.key_bound_to_tee is True


@pytest.mark.asyncio
async def test_required_attestation_rejects_unexpected_provider_binding_hash() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    store = MockSKRKeyStore()
    handle = await store.acquire_key("responder-key")
    challenge = HandshakeChallenge.generate()
    unexpected_binding_hash = compute_binding_hash(b"not-derived-from-agent-or-public-key")
    evidence = _make_evidence(
        agent_did=str(agent_b.did),
        handle=handle,
        report_data_hash=unexpected_binding_hash,
        binding_hash=unexpected_binding_hash,
    )

    responder = TrustHandshake(
        agent_did=str(agent_b.did),
        identity=agent_b,
        registry=registry,
        tee_key_store=store,
        tee_key_id="responder-key",
        attestation_evidence=evidence,
    )
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
        verifier_did=str(agent_a.did),
    )

    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
        require_tee_bound_key=True,
    )
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is False
    assert "startup binding mismatch" in verification["reason"].lower()


@pytest.mark.asyncio
async def test_optional_attestation_allows_missing_evidence() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    challenge = HandshakeChallenge.generate()
    responder = TrustHandshake(agent_did=str(agent_b.did), identity=agent_b, registry=registry)
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
    )

    verifier = TrustHandshake(agent_did=str(agent_a.did), identity=agent_a, registry=registry)
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is True
    assert verification["attestation_claims"] is None


@pytest.mark.asyncio
async def test_required_attestation_rejects_missing_evidence() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    challenge = HandshakeChallenge.generate()
    responder = TrustHandshake(agent_did=str(agent_b.did), identity=agent_b, registry=registry)
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
    )

    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
    )
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is False
    assert "evidence required" in verification["reason"].lower()


@pytest.mark.asyncio
async def test_required_tee_bound_key_rejects_local_origin() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    store = LocalTEEKeyStore()
    handle = await store.acquire_key("local-key")
    challenge = HandshakeChallenge.generate()
    evidence = _make_evidence(agent_did=str(agent_b.did), handle=handle)
    responder = TrustHandshake(
        agent_did=str(agent_b.did),
        identity=agent_b,
        registry=registry,
        tee_key_store=store,
        tee_key_id="local-key",
        attestation_evidence=evidence,
    )
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
        verifier_did=str(agent_a.did),
    )

    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
        require_tee_bound_key=True,
    )
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is False
    assert "tee-bound key required" in verification["reason"].lower()


@pytest.mark.asyncio
async def test_attestation_signature_tampering_is_rejected() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    store = MockSKRKeyStore()
    handle = await store.acquire_key("responder-key")
    challenge = HandshakeChallenge.generate()
    evidence = _make_evidence(agent_did=str(agent_b.did), handle=handle)
    responder = TrustHandshake(
        agent_did=str(agent_b.did),
        identity=agent_b,
        registry=registry,
        tee_key_store=store,
        tee_key_id="responder-key",
        attestation_evidence=evidence,
    )
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
        verifier_did=str(agent_a.did),
    )
    signature = base64.b64decode(response.attestation_signature or "")
    response.attestation_signature = base64.b64encode(
        bytes([signature[0] ^ 0xFF]) + signature[1:]
    ).decode()

    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
    )
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is False
    assert "signature verification failed" in verification["reason"].lower()


@pytest.mark.asyncio
async def test_required_attestation_rejects_missing_layer2_signature() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    store = MockSKRKeyStore()
    handle = await store.acquire_key("responder-key")
    challenge = HandshakeChallenge.generate()
    evidence = _make_evidence(agent_did=str(agent_b.did), handle=handle)
    responder = TrustHandshake(
        agent_did=str(agent_b.did),
        identity=agent_b,
        registry=registry,
        tee_key_store=store,
        tee_key_id="responder-key",
        attestation_evidence=evidence,
    )
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
        verifier_did=str(agent_a.did),
    )
    response.attestation_signature = None

    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
    )
    verification = await verifier._verify_response(response, challenge, 0, None)

    assert verification["valid"] is False
    assert "signature required" in verification["reason"].lower()


@pytest.mark.asyncio
async def test_attestation_replay_is_rejected_after_success() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    store = MockSKRKeyStore()
    handle = await store.acquire_key("responder-key")
    challenge = HandshakeChallenge.generate()
    evidence = _make_evidence(agent_did=str(agent_b.did), handle=handle)
    responder = TrustHandshake(
        agent_did=str(agent_b.did),
        identity=agent_b,
        registry=registry,
        tee_key_store=store,
        tee_key_id="responder-key",
        attestation_evidence=evidence,
    )
    response = await responder.respond(
        challenge=challenge,
        my_capabilities=agent_b.capabilities,
        my_trust_score=500,
        identity=agent_b,
        verifier_did=str(agent_a.did),
    )
    verifier = TrustHandshake(
        agent_did=str(agent_a.did),
        identity=agent_a,
        registry=registry,
        attestation_verifier=MockAttestationVerifier(),
        require_attestation=True,
    )

    first = await verifier._verify_response(response, challenge, 0, None)
    replay = await verifier._verify_response(response, challenge, 0, None)

    assert first["valid"] is True
    assert replay["valid"] is False
    assert "replay" in replay["reason"].lower()


@pytest.mark.asyncio
async def test_cache_key_separates_attestation_requirements() -> None:
    agent_a = _make_identity("verifier")
    agent_b = _make_identity("responder")
    registry = _make_registry(agent_a, agent_b)
    verifier = TrustHandshake(agent_did=str(agent_a.did), identity=agent_a, registry=registry)
    standard_result = await verifier.initiate(
        str(agent_b.did),
        required_trust_score=0,
        require_attestation=False,
        require_tee_bound_key=False,
    )

    cached_standard = await verifier._get_cached_result(
        str(agent_b.did),
        require_attestation=False,
        require_tee_bound_key=False,
    )
    cached_required = await verifier._get_cached_result(
        str(agent_b.did),
        require_attestation=True,
        require_tee_bound_key=True,
    )

    assert standard_result.verified is True
    assert cached_standard is standard_result
    assert cached_required is None
