# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP message signing."""

from __future__ import annotations

import base64
import time
from datetime import timedelta

import pytest

from agent_os.mcp_protocols import InMemoryNonceStore
from agent_os.mcp_message_signer import MCPMessageSigner, MCPSignedEnvelope


def test_sign_and_verify_round_trip():
    signer = MCPMessageSigner(MCPMessageSigner.generate_key())

    envelope = signer.sign_message(
        '{"jsonrpc":"2.0","method":"tools/call","id":1}', sender_id="agent-1"
    )
    result = signer.verify_message(envelope)

    assert result.is_valid is True
    assert result.payload == envelope.payload
    assert result.sender_id == "agent-1"


def test_verify_detects_tampered_payload():
    signer = MCPMessageSigner(MCPMessageSigner.generate_key())
    envelope = signer.sign_message('{"method":"safe"}')
    tampered = MCPSignedEnvelope(
        payload='{"method":"evil"}',
        nonce=envelope.nonce,
        timestamp=envelope.timestamp,
        sender_id=envelope.sender_id,
        signature=envelope.signature,
    )

    result = signer.verify_message(tampered)

    assert result.is_valid is False
    assert "Invalid signature" in result.failure_reason


def test_verify_rejects_replay():
    signer = MCPMessageSigner(MCPMessageSigner.generate_key())
    envelope = signer.sign_message('{"method":"safe"}')

    assert signer.verify_message(envelope).is_valid is True
    replay = signer.verify_message(envelope)

    assert replay.is_valid is False
    assert "Duplicate nonce" in replay.failure_reason


def test_verify_rejects_expired_timestamp():
    signer = MCPMessageSigner(
        MCPMessageSigner.generate_key(),
        replay_window=timedelta(milliseconds=25),
    )
    envelope = signer.sign_message('{"method":"safe"}')
    old_timestamp = envelope.timestamp - timedelta(minutes=5)
    expired = MCPSignedEnvelope(
        payload=envelope.payload,
        nonce="expired-nonce",
        timestamp=old_timestamp,
        sender_id=envelope.sender_id,
        signature=signer._compute_signature(
            nonce="expired-nonce",
            timestamp=old_timestamp,
            sender_id=envelope.sender_id,
            payload=envelope.payload,
        ),
    )

    result = signer.verify_message(expired)

    assert result.is_valid is False
    assert "replay window" in result.failure_reason


def test_nonce_cache_cleanup_and_eviction():
    signer = MCPMessageSigner(
        MCPMessageSigner.generate_key(),
        replay_window=timedelta(milliseconds=10),
        max_nonce_cache_size=2,
    )

    for payload in ('{"id":1}', '{"id":2}', '{"id":3}'):
        assert signer.verify_message(signer.sign_message(payload)).is_valid is True

    assert signer.cached_nonce_count == 2

    time.sleep(0.05)
    assert signer.cleanup_nonce_cache() >= 1


def test_factory_and_validation():
    key = MCPMessageSigner.generate_key()
    signer = MCPMessageSigner.from_base64_key(base64.b64encode(key).decode("ascii"))
    envelope = signer.sign_message('{"ok":true}')

    assert signer.verify_message(envelope).is_valid is True

    with pytest.raises(ValueError, match="at least 32 bytes"):
        MCPMessageSigner(b"short")


def test_nonce_generator_and_store_injection():
    store = InMemoryNonceStore()
    signer = MCPMessageSigner(
        MCPMessageSigner.generate_key(),
        nonce_store=store,
        nonce_generator=lambda: "fixed-nonce",
    )

    envelope = signer.sign_message('{"id":1}')
    result = signer.verify_message(envelope)

    assert envelope.nonce == "fixed-nonce"
    assert result.is_valid is True
    assert store.has("fixed-nonce") is True


def test_nonce_cache_uses_lru_eviction_when_full():
    store = InMemoryNonceStore(max_entries=2)
    nonces = iter(["nonce-1", "nonce-2", "nonce-3"])
    signer = MCPMessageSigner(
        MCPMessageSigner.generate_key(),
        max_nonce_cache_size=2,
        nonce_store=store,
        nonce_generator=lambda: next(nonces),
    )

    first = signer.sign_message('{"id":1}')
    second = signer.sign_message('{"id":2}')
    third = signer.sign_message('{"id":3}')

    assert signer.verify_message(first).is_valid is True
    assert signer.verify_message(second).is_valid is True
    assert store.has("nonce-1") is True
    assert signer.verify_message(third).is_valid is True

    assert store.has("nonce-1") is True
    assert store.has("nonce-2") is False
    assert store.has("nonce-3") is True
