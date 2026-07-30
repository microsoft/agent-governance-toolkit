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


def _reframe(envelope: MCPSignedEnvelope, *, payload=..., sender_id=...):
    """Return *envelope* with fields moved but the signature kept as-is.

    Models the whole of the attacker's capability: they hold one valid envelope
    and may rewrite its fields, but cannot compute a new signature.
    """
    return MCPSignedEnvelope(
        payload=envelope.payload if payload is ... else payload,
        nonce=envelope.nonce,
        timestamp=envelope.timestamp,
        sender_id=envelope.sender_id if sender_id is ... else sender_id,
        signature=envelope.signature,
    )


class TestCanonicalStringIsInjective:
    """Field boundaries must not be movable inside the signed canonical string.

    The canonical string was ``f"{nonce}|{timestamp_ms}|{sender_id or ''}|{payload}"``.
    ``|`` is legal inside a payload and inside a sender id, so distinct
    (nonce, timestamp, sender, payload) tuples collapsed to the same canonical
    string and therefore the same HMAC. Holding one valid envelope was enough to
    forge others: move text across a boundary and the signature still verified.

    Each case uses a fresh verifier, since a real receiver has its own nonce
    store and would not have seen the original envelope's nonce.
    """

    KEY = b"k" * 32

    def _signer(self) -> MCPMessageSigner:
        return MCPMessageSigner(self.KEY)

    def test_text_moved_from_payload_into_sender_id(self):
        # sender="alice" + payload="alpha|beta" and sender="alice|alpha" +
        # payload="beta" both ended "...|alice|alpha|beta".
        envelope = self._signer().sign_message("alpha|beta", sender_id="alice")
        forged = _reframe(envelope, payload="beta", sender_id="alice|alpha")

        result = self._signer().verify_message(forged)

        assert result.is_valid is False
        assert "Invalid signature" in result.failure_reason

    def test_text_moved_from_sender_id_into_payload(self):
        # The same shift in the other direction, which is the dangerous one: it
        # prepends attacker-chosen text to the payload a consumer will act on.
        envelope = self._signer().sign_message("x", sender_id="alice|INJECTED")
        forged = _reframe(envelope, payload="INJECTED|x", sender_id="alice")

        result = self._signer().verify_message(forged)

        assert result.is_valid is False
        assert result.payload is None

    def test_absent_sender_is_not_an_empty_sender(self):
        # ``sender_id or ''`` erased the difference, so an envelope signed with
        # no sender verified as one sent by "".
        envelope = self._signer().sign_message("p", sender_id=None)
        forged = _reframe(envelope, sender_id="")

        assert self._signer().verify_message(forged).is_valid is False

    @pytest.mark.parametrize(
        ("payload", "sender_id"),
        [
            ("plain", "agent-1"),
            ("a|b|c", "x|y"),  # separator inside both fields
            ("3:abc", "5:hello"),  # content shaped like the length prefix itself
            ("-", "-"),  # content equal to the absent-value marker
            ("{}", None),
            ("unicode 中文 \U0001f600", "中文"),
        ],
    )
    def test_round_trip_survives_framing(self, payload, sender_id):
        # Fixing the ambiguity must not break any legitimate field content,
        # including content that mimics the framing.
        signer = self._signer()
        result = signer.verify_message(signer.sign_message(payload, sender_id=sender_id))

        assert result.is_valid is True
        assert result.payload == payload
        assert result.sender_id == sender_id

    def test_distinct_field_tuples_never_share_a_canonical_string(self):
        # The property the fix rests on: the encoding is injective, so two
        # different tuples can never produce one signature.
        timestamp = self._signer().sign_message("seed").timestamp
        awkward = ["", "a", "|", "a|", "|a", "a|b", "1:a", "-", "2:ab"]
        seen: dict[str, tuple] = {}
        for nonce in ("n", "n|", "1:n"):
            for sender_id in [*awkward, None]:
                for payload in awkward:
                    canonical = MCPMessageSigner._build_canonical_string(
                        nonce=nonce,
                        timestamp=timestamp,
                        sender_id=sender_id,
                        payload=payload,
                    )
                    key = (nonce, sender_id, payload)
                    collided = seen.setdefault(canonical, key)
                    assert collided == key, (
                        f"collision: {collided} and {key} both encode to {canonical!r}"
                    )
        assert len(seen) == 3 * 10 * 9


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


def test_nonce_retained_at_exact_expiry_boundary():
    """At now == expires_at the nonce is still tracked (replay window is inclusive).

    The verifier accepts a message whose age == replay_window, so the store must
    not treat the nonce as expired at that exact instant or a replay slips through.
    """
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = InMemoryNonceStore(clock=lambda: now[0])
    store.add("n1", now[0] + timedelta(seconds=5))

    now[0] += timedelta(seconds=5)  # now == expires_at (boundary)
    assert store.has("n1") is True  # still present -> replay would be rejected

    now[0] += timedelta(microseconds=1)  # strictly past expiry
    assert store.has("n1") is False


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
