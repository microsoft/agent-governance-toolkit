# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP message signing."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from agent_os.mcp_protocols import InMemoryNonceStore, NonceStoreCapacityError
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


def test_nonce_store_fail_closed_and_expired_reclaim():
    """In-window nonces are never evicted; only expired entries free capacity.

    Replaces the previous test that asserted count-based eviction of an
    in-window nonce (which was the replay vulnerability).
    """
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = InMemoryNonceStore(clock=lambda: now[0], max_entries=2)

    store.add("n1", now[0] + timedelta(seconds=1))
    store.add("n2", now[0] + timedelta(seconds=1))
    assert store.count() == 2

    # Full of in-window nonces: fail closed instead of evicting a live nonce.
    with pytest.raises(NonceStoreCapacityError):
        store.add("n3", now[0] + timedelta(seconds=1))
    assert store.has("n1") is True
    assert store.has("n2") is True
    assert store.has("n3") is False

    # After the window elapses, expired nonces are reclaimed on the next add.
    now[0] += timedelta(seconds=2)
    store.add("n3", now[0] + timedelta(seconds=1))
    assert store.has("n3") is True
    assert store.count() == 1


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


def test_replay_within_window_rejected_under_capacity_pressure():
    """TASK repro, flipped: a small nonce cache must not re-open the replay window.

    Previously (LRU count-eviction) verifying more messages than the cache size
    evicted the earliest nonce, so re-verifying msg0 returned is_valid=True. Now
    in-window nonces are retained and overflow messages fail closed, so msg0's
    nonce is still tracked and the replay is rejected.
    """
    nonces = iter([f"nonce-{i}" for i in range(4)])
    signer = MCPMessageSigner(
        MCPMessageSigner.generate_key(),
        max_nonce_cache_size=2,
        nonce_generator=lambda: next(nonces),
    )

    envelopes = [signer.sign_message(f'{{"id":{i}}}') for i in range(4)]
    for env in envelopes:
        signer.verify_message(env)

    # Overflow messages beyond the cache size fail closed rather than evicting.
    assert signer.verify_message(envelopes[2]).is_valid is False

    # msg0's nonce was never evicted, so replaying it is caught as a duplicate.
    replay = signer.verify_message(envelopes[0])
    assert replay.is_valid is False
    assert replay.failure_reason is not None
