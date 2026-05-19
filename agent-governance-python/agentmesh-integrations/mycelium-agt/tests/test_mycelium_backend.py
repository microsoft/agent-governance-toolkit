# Copyright (c) giskard09 (Rama / Mycelium)
# Licensed under the Apache License, Version 2.0.
"""Tests for MyceliumBackend.

No live Mycelium endpoint required — HTTP calls are intercepted by urllib mocks.
"""

from __future__ import annotations

import hashlib
import json
import pytest
from unittest.mock import MagicMock, patch

from mycelium_agt import MyceliumBackend
from mycelium_agt.backend import AnchorReceipt, compute_action_ref, _jcs_encode


# =============================================================================
# action_ref derivation — JCS RFC 8785 + SHA-256
# =============================================================================

class TestActionRefDerivation:
    """Canonical derivation must match AlgoVoi / andysalvo verifier byte-for-byte."""

    def test_known_vector_nexus(self):
        """NEXUS oracle signal vector — verified by andysalvo verifier (ec7201a)."""
        ref = compute_action_ref(
            agent_id="nexus-agent-xa12.onrender.com",
            action_type="oracle.signal",
            scope="BTC",
            timestamp="2025-05-18T11:40:31.000Z",
        )
        assert ref == "fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a"

    def test_known_vector_conformance_committed(self):
        """Conformance fixture COMMITTED vector."""
        ref = compute_action_ref(
            agent_id="nobulex-gogani",
            action_type="payment.send",
            scope="payment:usdc:50",
            timestamp="2025-05-18T10:00:00.000Z",
        )
        assert ref == "31ddbd9f89f0e54700744addc7fa23f41518cf8c9d63d206e6da5cc3669defdd"

    def test_jcs_key_order_is_lexicographic(self):
        """Keys must sort by Unicode code point: action_type < agent_id < scope < timestamp."""
        payload = _jcs_encode({
            "agent_id": "x",
            "action_type": "y",
            "scope": "z",
            "timestamp": "t",
        })
        assert payload == b'{"action_type":"y","agent_id":"x","scope":"z","timestamp":"t"}'

    def test_output_is_64_hex_chars(self):
        ref = compute_action_ref("a", "b", "c", "2026-01-01T00:00:00.000Z")
        assert len(ref) == 64
        assert all(c in "0123456789abcdef" for c in ref)

    def test_deterministic(self):
        kwargs = dict(agent_id="ag", action_type="op", scope="s", timestamp="2026-01-01T00:00:00.000Z")
        assert compute_action_ref(**kwargs) == compute_action_ref(**kwargs)

    def test_different_inputs_produce_different_refs(self):
        a = compute_action_ref("agent-1", "file:write", "audit", "2026-05-15T00:00:00.000Z")
        b = compute_action_ref("agent-2", "file:write", "audit", "2026-05-15T00:00:00.000Z")
        assert a != b

    @pytest.mark.parametrize("bad_ts", [
        "2026-05-15T10:00:00Z",          # missing ms
        "2026-05-15T10:00:00.1Z",        # 1-digit ms
        "2026-05-15 10:00:00.123Z",      # space instead of T
        "2026-05-15T10:00:00.123",       # missing Z
        "not-a-timestamp",
    ])
    def test_invalid_timestamp_raises(self, bad_ts):
        with pytest.raises(ValueError, match="RFC 3339"):
            compute_action_ref("agent", "op", "scope", bad_ts)

    def test_empty_scope_is_valid(self):
        """Empty scope is a legitimate value — must not raise."""
        ref = compute_action_ref("agent", "op", "", "2026-01-01T00:00:00.000Z")
        assert len(ref) == 64


# =============================================================================
# Protocol surface
# =============================================================================

class TestProtocol:
    def test_name(self):
        b = MyceliumBackend(agent_id="test-agent")
        assert b.name == "mycelium"

    def test_anchor_returns_anchor_receipt(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            r = b.anchor({"action_type": "file:write", "scope": "audit"})
        assert isinstance(r, AnchorReceipt)
        assert r.anchored is False
        assert r.error is not None

    def test_anchor_preimage_populated(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            r = b.anchor({"action_type": "file:write", "scope": "audit"})
        assert r.preimage["agent_id"] == "test-agent"
        assert r.preimage["action_type"] == "file:write"
        assert r.preimage["scope"] == "audit"
        assert "timestamp" in r.preimage

    def test_anchor_action_ref_matches_preimage(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            r = b.anchor({"action_type": "file:write", "scope": ""})
        recomputed = compute_action_ref(
            r.preimage["agent_id"],
            r.preimage["action_type"],
            r.preimage["scope"],
            r.preimage["timestamp"],
        )
        assert r.action_ref == recomputed

    def test_verify_url_contains_action_ref(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            r = b.anchor({"action_type": "op", "scope": ""})
        assert r.action_ref in r.verify_url
        assert "test-agent" in r.verify_url

    def test_timing_populated(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            r = b.anchor({"action_type": "op", "scope": ""})
        assert r.evaluation_ms >= 0


# =============================================================================
# HTTP anchoring
# =============================================================================

def _mock_urlopen_success(trail_id="abc-123", trail_status="committed", tx_hash=None):
    response_body = json.dumps({
        "trail_id": trail_id,
        "trail_status": trail_status,
        "tx_hash": tx_hash,
    }).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = response_body
    return mock_resp


class TestHTTPAnchoring:
    def test_successful_anchor(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success()):
            r = b.anchor({"action_type": "payment.send", "scope": "usdc:50"})
        assert r.anchored is True
        assert r.trail_id == "abc-123"
        assert r.trail_status == "committed"

    def test_committed_with_tx_hash(self):
        b = MyceliumBackend(agent_id="test-agent")
        tx = "0x7fd0a8ededd1feb65ab37b3324218a0386dbf124174cf122bffc40717c057b84"
        with patch("urllib.request.urlopen", return_value=_mock_urlopen_success(tx_hash=tx)):
            r = b.anchor({"action_type": "payment.send", "scope": ""})
        assert r.tx_hash == tx

    def test_request_payload_contains_jcs_format(self):
        captured: dict = {}

        def _fake_urlopen(request, timeout):
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return _mock_urlopen_success()

        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            b.anchor({"action_type": "file:write", "scope": "audit"})

        assert captured["payload"]["preimage_format"] == "jcs-rfc8785"
        assert captured["payload"]["preimage"]["agent_id"] == "test-agent"
        assert captured["payload"]["action_ref"] == compute_action_ref(
            "test-agent",
            "file:write",
            "audit",
            captured["payload"]["preimage"]["ts"],
        )

    def test_http_error_returns_failed_receipt(self):
        import urllib.error
        b = MyceliumBackend(agent_id="test-agent")
        err = urllib.error.HTTPError(url="u", code=429, msg="Too Many Requests", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            r = b.anchor({"action_type": "op", "scope": ""})
        assert r.anchored is False
        assert r.error is not None

    def test_verify_success(self):
        body = json.dumps({"verified": True, "trail_status": "committed", "tx_hash": "0xabc"}).encode()
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = body
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = b.verify("31ddbd9f" + "0" * 56)
        assert result["verified"] is True

    def test_verify_http_404_returns_not_verified(self):
        import urllib.error
        b = MyceliumBackend(agent_id="test-agent")
        err = urllib.error.HTTPError(url="u", code=404, msg="Not Found", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            result = b.verify("31ddbd9f" + "0" * 56)
        assert result["verified"] is False
        assert "404" in result["error"]

    def test_anchor_uses_configured_timeout(self):
        """MyceliumBackend must forward timeout_seconds to urlopen."""
        captured: dict = {}

        def _fake_urlopen(request, timeout):
            captured["timeout"] = timeout
            return _mock_urlopen_success()

        b = MyceliumBackend(agent_id="test-agent", timeout_seconds=42.0)
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            b.anchor({"action_type": "op", "scope": ""})

        assert captured["timeout"] == 42.0

    def test_anchor_receipt_repr_contains_action_ref_prefix(self):
        b = MyceliumBackend(agent_id="test-agent")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            r = b.anchor({"action_type": "op", "scope": ""})
        rep = repr(r)
        assert r.action_ref[:16] in rep
