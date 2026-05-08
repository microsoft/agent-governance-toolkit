# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ADR 0010 canonical report-data binding."""

import hashlib

import pytest

from agentmesh.identity.attestation import (
    compute_report_data_hash,
    compute_report_data_hash_hex,
    matches_report_data_binding,
    public_key_hash_hex,
)


def test_compute_report_data_hash_matches_adr_encoding() -> None:
    public_key_hash = bytes.fromhex(public_key_hash_hex(b"\x01" * 32))

    expected_payload = b"".join(
        (
            b"agentmesh-attest-v1",
            (16).to_bytes(2, "big"),
            b"did:mesh:agent-1",
            (13).to_bytes(2, "big"),
            b"challenge_123",
            b"nonce-abc",
            public_key_hash,
        )
    )

    digest = compute_report_data_hash(
        agent_did="did:mesh:agent-1",
        challenge_id="challenge_123",
        nonce="nonce-abc",
        public_key_hash=public_key_hash,
    )

    assert digest == hashlib.sha256(expected_payload).digest()
    assert (
        compute_report_data_hash_hex(
            "did:mesh:agent-1",
            "challenge_123",
            "nonce-abc",
            public_key_hash,
        )
        == digest.hex()
    )


def test_compute_report_data_hash_accepts_public_key_hash_hex() -> None:
    public_key_hash = public_key_hash_hex(b"\x02" * 32)

    digest_from_bytes = compute_report_data_hash(
        "did:mesh:agent-1",
        "challenge_123",
        "nonce-abc",
        bytes.fromhex(public_key_hash),
    )
    digest_from_hex = compute_report_data_hash(
        "did:mesh:agent-1",
        "challenge_123",
        "nonce-abc",
        public_key_hash,
    )

    assert digest_from_hex == digest_from_bytes


def test_matches_report_data_binding_accepts_exact_match() -> None:
    public_key_hash = public_key_hash_hex(b"\x03" * 32)
    report_data_hash = compute_report_data_hash_hex(
        "did:mesh:agent-1",
        "challenge_123",
        "nonce-abc",
        public_key_hash,
    )

    assert (
        matches_report_data_binding(
            report_data_hash=report_data_hash,
            agent_did="did:mesh:agent-1",
            challenge_id="challenge_123",
            nonce="nonce-abc",
            public_key_hash=public_key_hash,
        )
        is True
    )


@pytest.mark.parametrize(
    ("agent_did", "challenge_id", "nonce", "public_key"),
    [
        ("did:mesh:other", "challenge_123", "nonce-abc", b"\x04" * 32),
        ("did:mesh:agent-1", "challenge_other", "nonce-abc", b"\x04" * 32),
        ("did:mesh:agent-1", "challenge_123", "nonce-other", b"\x04" * 32),
        ("did:mesh:agent-1", "challenge_123", "nonce-abc", b"\x05" * 32),
    ],
)
def test_matches_report_data_binding_rejects_mismatched_inputs(
    agent_did: str,
    challenge_id: str,
    nonce: str,
    public_key: bytes,
) -> None:
    original_public_key_hash = public_key_hash_hex(b"\x04" * 32)
    report_data_hash = compute_report_data_hash_hex(
        "did:mesh:agent-1",
        "challenge_123",
        "nonce-abc",
        original_public_key_hash,
    )

    assert (
        matches_report_data_binding(
            report_data_hash=report_data_hash,
            agent_did=agent_did,
            challenge_id=challenge_id,
            nonce=nonce,
            public_key_hash=public_key_hash_hex(public_key),
        )
        is False
    )


@pytest.mark.parametrize(
    ("agent_did", "challenge_id", "nonce"),
    [
        ("", "challenge_123", "nonce-abc"),
        ("did:mesh:agent-1", "", "nonce-abc"),
        ("did:mesh:agent-1", "challenge_123", ""),
    ],
)
def test_compute_report_data_hash_rejects_empty_binding_inputs(
    agent_did: str,
    challenge_id: str,
    nonce: str,
) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        compute_report_data_hash(
            agent_did,
            challenge_id,
            nonce,
            public_key_hash_hex(b"\x06" * 32),
        )


def test_compute_report_data_hash_rejects_oversized_length_prefixed_fields() -> None:
    with pytest.raises(ValueError, match="at most 65535 bytes"):
        compute_report_data_hash(
            "a" * 65536,
            "challenge_123",
            "nonce-abc",
            public_key_hash_hex(b"\x07" * 32),
        )


@pytest.mark.parametrize(
    "public_key_hash",
    [
        b"\x01" * 31,
        "0" * 63,
        "not-a-hex-digest",
    ],
)
def test_compute_report_data_hash_rejects_malformed_public_key_hash(
    public_key_hash: bytes | str,
) -> None:
    with pytest.raises(ValueError):
        compute_report_data_hash(
            "did:mesh:agent-1",
            "challenge_123",
            "nonce-abc",
            public_key_hash,
        )
