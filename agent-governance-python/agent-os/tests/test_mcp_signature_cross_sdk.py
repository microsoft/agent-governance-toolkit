# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cross-SDK shared HMAC vectors for the agent-os MCP message v2 encoding
(#4132, #4199).

The Rust SDK (``agent-governance-rust/agentmesh-mcp``) asserts the identical
vector set in ``src/mcp/signing.rs``
(``matches_python_v2_shared_vectors``). Vectors were generated once from the
shared canonical spec; if this test fails, the two SDKs have drifted and
cross-SDK signed-envelope compatibility is broken.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import agent_os.mcp_message_signer as signer_module
from agent_os.mcp_message_signer import MCPMessageSigner, MCPSignedEnvelope

SECRET = b"mcp-sig-v2-cross-sdk-vector-key-000001"
TS_A = datetime(2023, 11, 14, 22, 13, 20, 123456, tzinfo=UTC)
TS_B = datetime(2023, 11, 14, 22, 13, 20, 999999, tzinfo=UTC)

# (nonce, sender, payload, timestamp, expected base64-standard signature)
VECTORS = [
    ("n", None, "x:y", TS_A, "ulKQJ88YmF6olg4ML3ekYf7vTA2jh7m434nn/bh59ns="),
    ("n:x", None, "y", TS_A, "4LV3y6oukPpuK7KicYSjmRejFuDmA2q2NiDgocNtUZs="),
    ("a|b", "s|t", "p|q", TS_A, "JYCranEAW75tG9xotPxrynub4VUm1JJ04Pn5jrwPknc="),
    ("நி", None, '🚀 {"json":[1,2]}', TS_A, "OfjfnaSRytNHOrwwVGIjfVI9+KshmVKThfmw+ZJILDE="),
    ("n", "", "hello", TS_A, "VFK/y1V5v3BpfZ92s+XbfBDpcJ37hC7obDb5qGAhDU4="),
    ("n", None, "hello", TS_A, "jNdf63ZaaLmvYOoPhwKDDwYjZOXgImRYAyFsny+UK5I="),
    (
        'q"uote\\slash',
        "a\u0001b",
        "line\n\u0000end",
        TS_A,
        "RMaggh8DnjNCnfsfMmC41aOUSl5z0rvj+U+pMp6PMK4=",
    ),
    (
        "n",
        None,
        '["agent-os:mcp-message:v2","x","2023-11-14T22:13:20.123456+00:00",null,"y"]',
        TS_A,
        "z449mTVpVmzBmacGaEUecnunNGj49iOevfdpBeqyqPk=",
    ),
    ("n", "agent-1", "hello", TS_B, "VdH7Z13r4EVkC8PZsl7qrnu9Na/vDEyzvKjyCU2SuWE="),
]


def _signer(nonce: str) -> MCPMessageSigner:
    return MCPMessageSigner(SECRET, nonce_generator=lambda: nonce)


def test_matches_shared_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    for nonce, sender, payload, ts, expected in VECTORS:
        monkeypatch.setattr(signer_module, "_utcnow", lambda ts=ts: ts)
        envelope = _signer(nonce).sign_message(payload, sender)
        assert envelope.nonce == nonce
        assert envelope.timestamp == ts
        assert envelope.signature == expected, f"vector mismatch for nonce={nonce!r}"


def test_reframed_envelope_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression for #4199: (nonce "n", payload "x:y") and
    (nonce "n:x", payload "y") must not share a signature."""
    monkeypatch.setattr(signer_module, "_utcnow", lambda: TS_A)
    signer = _signer("n")
    signed = signer.sign_message("x:y", None)
    assert signed.signature == VECTORS[0][4]

    reframed = MCPSignedEnvelope(
        payload="y",
        nonce="n:x",
        timestamp=signed.timestamp,
        sender_id=signed.sender_id,
        signature=signed.signature,
    )
    result = signer.verify_message(reframed)
    assert not result.is_valid
    assert result.failure_reason == "Invalid signature."


def test_absent_and_empty_sender_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON null (absent sender) and an empty-string sender are distinct
    encodings, so a relay cannot flip a signed message between "no sender"
    and "empty sender" without breaking the MAC."""
    monkeypatch.setattr(signer_module, "_utcnow", lambda: TS_A)
    absent = _signer("n").sign_message("payload", None)
    empty = _signer("n").sign_message("payload", "")
    assert absent.signature != empty.signature
