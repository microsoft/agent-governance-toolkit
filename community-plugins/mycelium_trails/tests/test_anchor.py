"""Tests for MyceliumAnchor (anchor + verify)."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from mycelium_trails.anchor import MyceliumAnchor
from mycelium_trails._types import (
    AnchorReceipt,
    AnchorVerifyStatus,
)

EVIDENCE_HASH = "sha256:abc123def456"
TRAIL_ID = "trail-uuid-0001"
TX_HASH = "0xdeadbeef"
ACTION_REF = "a" * 64


def _mock_anchor_response():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "trail_id": TRAIL_ID,
        "tx_hash": TX_HASH,
        "anchored_at": "2026-05-15T10:00:00.123Z",
    }
    resp.raise_for_status = MagicMock()
    return resp


def _make_receipt(action_ref=ACTION_REF):
    return AnchorReceipt(
        backend="mycelium-trails",
        anchor_id=TRAIL_ID,
        anchored_at="2026-05-15T10:00:00.123Z",
        evidence_hash=EVIDENCE_HASH,
        metadata={"action_ref": action_ref, "agent_id": "test-agent", "tx_hash": TX_HASH},
    )


# ── anchor() ──────────────────────────────────────────────────────────────────

class TestAnchor:
    def test_happy_path_returns_receipt(self):
        with patch("requests.post", return_value=_mock_anchor_response()):
            anchor = MyceliumAnchor(agent_id="test-agent")
            receipt = anchor.anchor(EVIDENCE_HASH, {})

        assert receipt.backend == "mycelium-trails"
        assert receipt.anchor_id == TRAIL_ID
        assert receipt.evidence_hash == EVIDENCE_HASH
        assert "action_ref" in receipt.metadata
        assert receipt.metadata["tx_hash"] == TX_HASH

    def test_metadata_action_type_and_scope_forwarded(self):
        with patch("requests.post", return_value=_mock_anchor_response()) as mock_post:
            anchor = MyceliumAnchor()
            anchor.anchor(EVIDENCE_HASH, {"action_type": "stripe:charge", "scope": "billing"})

        payload = mock_post.call_args.kwargs["json"]
        assert payload["operation"] == "stripe:charge"
        assert payload["scope"] == "billing"

    def test_parent_trail_id_forwarded(self):
        with patch("requests.post", return_value=_mock_anchor_response()) as mock_post:
            anchor = MyceliumAnchor()
            anchor.anchor(EVIDENCE_HASH, {"parent_trail_id": "parent-123"})

        payload = mock_post.call_args.kwargs["json"]
        assert payload.get("parent_trail_id") == "parent-123"

    def test_network_error_raises_runtime_error(self):
        with patch("requests.post", side_effect=requests.ConnectionError("timeout")):
            anchor = MyceliumAnchor()
            with pytest.raises(RuntimeError, match="MyceliumAnchor.anchor failed"):
                anchor.anchor(EVIDENCE_HASH, {})

    def test_action_ref_in_receipt_metadata(self):
        with patch("requests.post", return_value=_mock_anchor_response()):
            anchor = MyceliumAnchor()
            receipt = anchor.anchor(EVIDENCE_HASH, {})

        assert len(receipt.metadata["action_ref"]) == 64


# ── verify() ──────────────────────────────────────────────────────────────────

class TestVerify:
    def _verify_response(self, verified=True, stored_hash=EVIDENCE_HASH, tx_hash=TX_HASH):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "verified": verified,
            "trail_id": TRAIL_ID,
            "claims": {"evidence_hash": stored_hash},
            "tx_hash": tx_hash,
        }
        resp.raise_for_status = MagicMock()
        return resp

    def test_verified_happy_path(self):
        with patch("requests.get", return_value=self._verify_response()):
            anchor = MyceliumAnchor()
            result = anchor.verify(EVIDENCE_HASH, _make_receipt())

        assert result.status == AnchorVerifyStatus.VERIFIED
        assert result.evidence_hash == EVIDENCE_HASH
        assert result.inclusion_proof is not None
        assert result.inclusion_proof.proof_type == "tx_receipt"
        assert result.inclusion_proof.proof_data["tx_hash"] == TX_HASH

    def test_hash_mismatch(self):
        with patch("requests.get", return_value=self._verify_response(stored_hash="sha256:different")):
            anchor = MyceliumAnchor()
            result = anchor.verify(EVIDENCE_HASH, _make_receipt())

        assert result.status == AnchorVerifyStatus.HASH_MISMATCH
        assert "stored" in (result.error_detail or "")

    def test_not_found_on_404(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.raise_for_status = MagicMock()
        with patch("requests.get", return_value=resp):
            anchor = MyceliumAnchor()
            result = anchor.verify(EVIDENCE_HASH, _make_receipt())

        assert result.status == AnchorVerifyStatus.NOT_FOUND

    def test_backend_unavailable_on_network_error(self):
        with patch("requests.get", side_effect=requests.ConnectionError("down")):
            anchor = MyceliumAnchor()
            result = anchor.verify(EVIDENCE_HASH, _make_receipt())

        assert result.status == AnchorVerifyStatus.BACKEND_UNAVAILABLE
        assert result.error_detail is not None

    def test_falls_back_to_trail_id_without_action_ref(self):
        receipt = AnchorReceipt(
            backend="mycelium-trails",
            anchor_id=TRAIL_ID,
            anchored_at="2026-05-15T10:00:00.123Z",
            evidence_hash=EVIDENCE_HASH,
            metadata={"agent_id": "test-agent"},  # no action_ref
        )
        with patch("requests.get", return_value=self._verify_response()) as mock_get:
            anchor = MyceliumAnchor()
            anchor.verify(EVIDENCE_HASH, receipt)

        url = mock_get.call_args.args[0]
        assert TRAIL_ID in url

    def test_inclusion_proof_has_arbiscan_url(self):
        with patch("requests.get", return_value=self._verify_response()):
            anchor = MyceliumAnchor()
            result = anchor.verify(EVIDENCE_HASH, _make_receipt())

        assert result.inclusion_proof is not None
        explorer_url = result.inclusion_proof.proof_data.get("explorer_url", "")
        assert "arbiscan.io" in explorer_url
