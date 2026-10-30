# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Adversarial regression tests for MCP signed-envelope canonicalization.

Reframing cases and the collision-matrix approach derive from #3507 and #3508.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta, timezone
from itertools import product

import pytest

from agent_os.mcp_message_signer import MCPMessageSigner, MCPSignedEnvelope
from agent_os.mcp_protocols import InMemoryNonceStore

KEY = b"k" * 32
NOW = datetime(2026, 9, 24, 10, 0, 0, 123456, tzinfo=UTC)


@pytest.fixture
def fixed_clock(monkeypatch):
    monkeypatch.setattr("agent_os.mcp_message_signer._utcnow", lambda: NOW)

    def nonce_store(**kwargs):
        return InMemoryNonceStore(clock=lambda: NOW, **kwargs)

    monkeypatch.setattr("agent_os.mcp_message_signer.InMemoryNonceStore", nonce_store)


@pytest.mark.parametrize(
    ("sender", "payload", "forged_sender", "forged_payload"),
    [
        ("alice", "alpha|beta", "alice|alpha", "beta"),
        ("alice|INJECTED", "x", "alice", "INJECTED|x"),
        (None, "p", "", "p"),
        ("", "p", None, "p"),
        ("alice", '|{"method":"tools/call"}', "alice|", '{"method":"tools/call"}'),
    ],
)
def test_reframed_envelope_fails_without_consuming_nonce(
    sender, payload, forged_sender, forged_payload
):
    signed = MCPMessageSigner(KEY).sign_message(payload, sender_id=sender)
    forged = replace(signed, sender_id=forged_sender, payload=forged_payload)
    receiver = MCPMessageSigner(KEY)

    result = receiver.verify_message(forged)

    assert not result.is_valid
    assert result.failure_reason == "Invalid signature."
    assert result.payload is None
    assert result.sender_id is None
    assert receiver.cached_nonce_count == 0
    assert receiver.verify_message(signed).is_valid
    assert not receiver.verify_message(signed).is_valid


def test_nonce_timestamp_boundary_cannot_be_reframed(fixed_clock):
    later = NOW + timedelta(seconds=1)
    now_ms = int(NOW.timestamp() * 1000)
    later_ms = int(later.timestamp() * 1000)
    signer = MCPMessageSigner(KEY, nonce_generator=lambda: f"n|{now_ms}")
    signed = signer.sign_message("payload", sender_id="alice")
    signed = replace(
        signed,
        timestamp=later,
        signature=signer._compute_signature(
            nonce=signed.nonce, timestamp=later, sender_id="alice", payload="payload"
        ),
    )
    forged = replace(signed, nonce="n", timestamp=NOW, sender_id=f"{later_ms}|alice")
    receiver = MCPMessageSigner(KEY)

    assert not receiver.verify_message(forged).is_valid
    assert receiver.cached_nonce_count == 0
    assert receiver.verify_message(signed).is_valid


@pytest.mark.parametrize("sender", [None, "", "alice", "alice|INJECTED"])
@pytest.mark.parametrize("payload", ["payload", "alpha|beta"])
def test_legacy_signatures_are_rejected_without_fallback(sender, payload, fixed_clock):
    signed = MCPMessageSigner(KEY).sign_message(payload, sender_id=sender)
    legacy = (
        f"{signed.nonce}|{int(signed.timestamp.timestamp() * 1000)}|{sender or ''}|{signed.payload}"
    )
    digest = hmac.new(KEY, legacy.encode("utf-8"), hashlib.sha256).digest()
    envelope = replace(signed, signature=base64.b64encode(digest).decode("ascii"))
    receiver = MCPMessageSigner(KEY)

    assert not receiver.verify_message(envelope).is_valid
    assert receiver.cached_nonce_count == 0
    assert receiver.verify_message(signed).is_valid


def test_canonical_encoding_is_injective_over_adversarial_fields():
    values = ("", "|", "a|", "|a", "a|b", ",", "]", '["', "null", "\\", '"', "\x00", "\n", "a\nb")
    non_blank_values = tuple(value for value in values if value.strip())
    nonces = ("n",) + non_blank_values
    payloads = ("p",) + non_blank_values
    senders = (None,) + values
    timestamps = (NOW, NOW + timedelta(microseconds=1))
    encodings = set()

    for nonce, timestamp, sender_id, payload in product(nonces, timestamps, senders, payloads):
        canonical = MCPMessageSigner._build_canonical_string(
            nonce=nonce, timestamp=timestamp, sender_id=sender_id, payload=payload
        )
        assert canonical not in encodings
        encodings.add(canonical)

    assert len(encodings) == len(nonces) * len(timestamps) * len(senders) * len(payloads)


def test_versioned_canonical_encoding_and_signature_vector(fixed_clock):
    signer = MCPMessageSigner(KEY, nonce_generator=lambda: 'n|"\\\n')
    envelope = signer.sign_message('{"text":"caf\u00e9|\U0001f600"}', sender_id=None)
    canonical = (
        '["agent-os:mcp-message:v2","n|\\"\\\\\\n",'
        '"2026-09-24T10:00:00.123456+00:00",null,'
        '"{\\"text\\":\\"caf\u00e9|\U0001f600\\"}"]'
    )

    assert (
        signer._build_canonical_string(
            nonce=envelope.nonce,
            timestamp=envelope.timestamp,
            sender_id=envelope.sender_id,
            payload=envelope.payload,
        )
        == canonical
    )
    expected = base64.b64encode(
        hmac.new(KEY, canonical.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")
    assert envelope.signature == expected
    assert json.loads(canonical)[-2:] == [None, envelope.payload]
    assert MCPMessageSigner(KEY).verify_message(envelope).is_valid


@pytest.mark.parametrize("field", ["nonce", "timestamp", "sender_id", "payload", "signature"])
def test_each_signed_field_is_authenticated(field, fixed_clock):
    signed = MCPMessageSigner(KEY).sign_message("payload", sender_id="alice")
    value = getattr(signed, field)
    changed = value + timedelta(microseconds=1) if field == "timestamp" else value + "|"
    receiver = MCPMessageSigner(KEY)

    result = receiver.verify_message(replace(signed, **{field: changed}))

    assert not result.is_valid
    assert result.failure_reason == "Invalid signature."
    assert receiver.verify_message(signed).is_valid


def test_equivalent_timezone_representation_preserves_the_signed_instant(fixed_clock):
    signed = MCPMessageSigner(KEY).sign_message("payload")
    offset = timezone(timedelta(hours=5, minutes=30))
    envelope = replace(signed, timestamp=signed.timestamp.astimezone(offset))

    assert MCPMessageSigner(KEY).verify_message(envelope).is_valid


def test_envelope_survives_json_transport_round_trip(fixed_clock):
    signed = MCPMessageSigner(KEY).sign_message('{"method":"tools/call"}', sender_id="alice|")
    wire = json.dumps(asdict(signed), default=lambda value: value.isoformat())
    fields = json.loads(wire)
    fields["timestamp"] = datetime.fromisoformat(fields["timestamp"])
    received = MCPSignedEnvelope(**fields)

    assert received == signed
    assert MCPMessageSigner(KEY).verify_message(received).is_valid


@pytest.mark.parametrize("sender", [None, "", "a|b", '"\\\x00\n', "\u00e9", "e\u0301"])
@pytest.mark.parametrize("payload", ["a|b", '"\\\x00\n', "\u00e9", "e\u0301", "\U0001f600"])
def test_valid_special_characters_round_trip_unchanged(sender, payload):
    signer = MCPMessageSigner(KEY, nonce_generator=lambda: 'n|:"\\\x00\n')
    signed = signer.sign_message(payload, sender_id=sender)

    result = MCPMessageSigner(KEY).verify_message(signed)

    assert result.is_valid
    assert result.sender_id == sender
    assert result.payload == payload


@pytest.mark.parametrize("field", ["nonce", "sender_id", "payload"])
def test_unicode_normalization_is_not_silently_applied(field):
    signer = MCPMessageSigner(KEY, nonce_generator=lambda: "\u00e9")
    signed = signer.sign_message("\u00e9", sender_id="\u00e9")
    receiver = MCPMessageSigner(KEY)

    assert not receiver.verify_message(replace(signed, **{field: "e\u0301"})).is_valid
    assert receiver.verify_message(signed).is_valid


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payload", None),
        ("payload", b"payload"),
        ("payload", 1),
        ("payload", ""),
        ("payload", " \t"),
        ("payload", "\ud83d\ude00"),
        ("sender_id", 0),
        ("sender_id", False),
        ("sender_id", []),
        ("sender_id", b"alice"),
        ("sender_id", "\ud800"),
        ("nonce", None),
        ("nonce", 1),
        ("nonce", b"nonce"),
        ("nonce", ""),
        ("nonce", " \n"),
        ("nonce", "\ud800"),
        ("timestamp", None),
        ("timestamp", "2026-09-24T10:00:00Z"),
        ("timestamp", NOW.replace(tzinfo=None)),
        ("signature", None),
        ("signature", b"signature"),
        ("signature", "\u00e9"),
    ],
)
def test_malformed_envelopes_fail_closed_without_consuming_nonce(field, value, fixed_clock):
    signed = MCPMessageSigner(KEY).sign_message("payload", sender_id="alice")
    receiver = MCPMessageSigner(KEY)

    result = receiver.verify_message(replace(signed, **{field: value}))

    assert not result.is_valid
    assert result.failure_reason
    assert result.payload is None
    assert result.sender_id is None
    assert receiver.cached_nonce_count == 0
    assert receiver.verify_message(signed).is_valid


@pytest.mark.parametrize("payload", [None, b"payload", 1, "", " \t", "\ud800"])
def test_signer_rejects_invalid_payloads(payload):
    with pytest.raises((TypeError, ValueError)):
        MCPMessageSigner(KEY).sign_message(payload)


@pytest.mark.parametrize("sender", [False, 0, [], b"alice", "\ud800"])
def test_signer_rejects_invalid_sender_types(sender):
    with pytest.raises((TypeError, ValueError)):
        MCPMessageSigner(KEY).sign_message("payload", sender_id=sender)


@pytest.mark.parametrize("nonce", [None, 0, [], b"nonce", "", " \t", "\ud800"])
def test_signer_rejects_invalid_generated_nonces(nonce):
    signer = MCPMessageSigner(KEY, nonce_generator=lambda: nonce)

    with pytest.raises((TypeError, ValueError)):
        signer.sign_message("payload")


@pytest.mark.parametrize("timestamp", [None, NOW.replace(tzinfo=None), "2026-09-24"])
def test_canonical_encoding_rejects_invalid_timestamps(timestamp):
    with pytest.raises(ValueError, match="timezone-aware datetime"):
        MCPMessageSigner._build_canonical_string(
            nonce="nonce", timestamp=timestamp, sender_id=None, payload="payload"
        )
