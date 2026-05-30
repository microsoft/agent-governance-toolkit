# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Relay service."""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agentmesh.relay.app import RelayServer
from agentmesh.relay.store import InMemoryInboxStore, StoredMessage


# ── Connect-frame helper ─────────────────────────────────────────────
#
# Every test in this file used to send the legacy unauthenticated frame
# ``{"v":1,"type":"connect","from":"did:agentmesh:<name>"}``. The relay
# now requires proof-of-possession of the DID's private key (see
# ``_verify_connect_pop`` in ``relay/app.py``), so we build connect
# frames whose ``from`` is derived from the supplied public key.
#
# A per-label cache keeps the DID stable across calls in the same test
# so a sender and a recipient can refer to the same identity.

_KEY_CACHE: dict[str, SigningKey] = {}


def _key_for(label: str) -> SigningKey:
    if label not in _KEY_CACHE:
        _KEY_CACHE[label] = SigningKey.generate()
    return _KEY_CACHE[label]


def _did_for(label: str) -> str:
    pk = _key_for(label).verify_key.encode()
    return f"did:mesh:{hashlib.sha256(pk).hexdigest()[:32]}"


def _connect_frame(label: str) -> dict:
    """Build a valid (signed) ``connect`` frame for *label*."""
    sk = _key_for(label)
    pk = sk.verify_key.encode()
    ts = datetime.now(timezone.utc).isoformat()
    sig = sk.sign(ts.encode("utf-8")).signature
    return {
        "v": 1,
        "type": "connect",
        "from": f"did:mesh:{hashlib.sha256(pk).hexdigest()[:32]}",
        "public_key": base64.b64encode(pk).decode(),
        "timestamp": ts,
        "signature": base64.b64encode(sig).decode(),
    }


@pytest.fixture(autouse=True)
def _clear_key_cache():
    """Give each test a fresh DID universe to avoid cross-test bleed."""
    _KEY_CACHE.clear()
    yield
    _KEY_CACHE.clear()


# ── Inbox Store Tests ────────────────────────────────────────────────


class TestInboxStore:
    def test_store_and_fetch(self):
        store = InMemoryInboxStore()
        msg = StoredMessage(
            message_id="msg-1", sender_did="did:agentmesh:alice",
            recipient_did="did:agentmesh:bob", payload='{"data":"hello"}',
        )
        assert store.store(msg) is True
        pending = store.fetch_pending("did:agentmesh:bob")
        assert len(pending) == 1
        assert pending[0].message_id == "msg-1"

    def test_duplicate_rejected(self):
        store = InMemoryInboxStore()
        msg = StoredMessage(
            message_id="dup-1", sender_did="a", recipient_did="b", payload="{}",
        )
        assert store.store(msg) is True
        assert store.store(msg) is False  # duplicate

    def test_acknowledge(self):
        store = InMemoryInboxStore()
        msg = StoredMessage(message_id="ack-1", sender_did="a", recipient_did="b", payload="{}")
        store.store(msg)
        assert store.acknowledge("ack-1") is True
        assert store.fetch_pending("b") == []
        assert store.acknowledge("ack-1") is False  # already gone

    def test_cleanup_expired(self):
        store = InMemoryInboxStore(ttl=timedelta(seconds=0))
        msg = StoredMessage(message_id="exp-1", sender_did="a", recipient_did="b", payload="{}")
        store.store(msg)
        removed = store.cleanup_expired()
        assert removed == 1
        assert store.message_count == 0

    def test_fetch_ordering(self):
        store = InMemoryInboxStore()
        for i in range(5):
            store.store(StoredMessage(
                message_id=f"ord-{i}", sender_did="a", recipient_did="b", payload=f'{{"n":{i}}}',
            ))
        pending = store.fetch_pending("b")
        ids = [m.message_id for m in pending]
        assert ids == ["ord-0", "ord-1", "ord-2", "ord-3", "ord-4"]

    def test_message_count(self):
        store = InMemoryInboxStore()
        assert store.message_count == 0
        store.store(StoredMessage(message_id="c-1", sender_did="a", recipient_did="b", payload="{}"))
        assert store.message_count == 1
        store.store(StoredMessage(message_id="c-2", sender_did="a", recipient_did="b", payload="{}"))
        assert store.message_count == 2

    def test_fetch_empty(self):
        store = InMemoryInboxStore()
        assert store.fetch_pending("did:agentmesh:nobody") == []


# ── Relay Server Tests ───────────────────────────────────────────────


class TestRelayServer:
    def test_health(self):
        server = RelayServer()
        client = TestClient(server.app)
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["connected_agents"] == 0

    def test_websocket_connect(self):
        server = RelayServer()
        client = TestClient(server.app)
        alice_did = _did_for("alice")
        with client.websocket_connect("/ws") as ws:
            ws.send_json(_connect_frame("alice"))
            # Should stay connected (no error response). Send a heartbeat
            # to verify the socket is alive.
            ws.send_json({"v": 1, "type": "heartbeat", "from": alice_did})

    def test_websocket_connect_missing_from(self):
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"v": 1, "type": "connect"})
            resp = ws.receive_json()
            assert resp["type"] == "error"

    def test_websocket_invalid_first_frame(self):
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"v": 1, "type": "message", "from": "x"})
            resp = ws.receive_json()
            assert resp["type"] == "error"

    def test_message_routing_online(self):
        """Two agents connected — messages route directly."""
        server = RelayServer()
        client = TestClient(server.app)
        alice_did = _did_for("alice")
        bob_did = _did_for("bob")

        with client.websocket_connect("/ws") as ws_bob:
            ws_bob.send_json(_connect_frame("bob"))

            with client.websocket_connect("/ws") as ws_alice:
                ws_alice.send_json(_connect_frame("alice"))

                # Alice sends to Bob
                ws_alice.send_json({
                    "v": 1, "type": "message",
                    "from": alice_did, "to": bob_did,
                    "id": "msg-001", "ciphertext": "encrypted_payload",
                })

                # Bob receives
                msg = ws_bob.receive_json()
                assert msg["type"] == "message"
                assert msg["from"] == alice_did
                assert msg["id"] == "msg-001"

        assert server.stats["messages_routed"] == 1

    def test_message_stored_when_offline(self):
        """Message stored when recipient is offline."""
        server = RelayServer()
        client = TestClient(server.app)
        alice_did = _did_for("alice")
        bob_did = _did_for("bob")

        with client.websocket_connect("/ws") as ws_alice:
            ws_alice.send_json(_connect_frame("alice"))

            # Send to offline Bob
            ws_alice.send_json({
                "v": 1, "type": "message",
                "from": alice_did, "to": bob_did,
                "id": "offline-001", "ciphertext": "stored_payload",
            })

        assert server.stats["messages_stored"] == 1

    def test_pending_delivered_on_connect(self):
        """Stored messages delivered when agent reconnects."""
        server = RelayServer()
        inbox = server._inbox
        alice_did = _did_for("alice")
        bob_did = _did_for("bob")

        # Pre-store a message for Bob
        inbox.store(StoredMessage(
            message_id="pending-001",
            sender_did=alice_did,
            recipient_did=bob_did,
            payload=json.dumps({
                "v": 1, "type": "message",
                "from": alice_did, "to": bob_did,
                "id": "pending-001", "ciphertext": "old_message",
            }),
        ))

        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws_bob:
            ws_bob.send_json(_connect_frame("bob"))

            # Should receive the pending message
            msg = ws_bob.receive_json()
            assert msg["id"] == "pending-001"

        assert server.stats["messages_delivered"] == 1

    def test_knock_routing(self):
        """KNOCK frames route like messages."""
        server = RelayServer()
        client = TestClient(server.app)
        alice_did = _did_for("alice")
        bob_did = _did_for("bob")

        with client.websocket_connect("/ws") as ws_bob:
            ws_bob.send_json(_connect_frame("bob"))

            with client.websocket_connect("/ws") as ws_alice:
                ws_alice.send_json(_connect_frame("alice"))

                ws_alice.send_json({
                    "v": 1, "type": "knock",
                    "from": alice_did, "to": bob_did,
                    "id": "knock-001",
                    "intent": {"action": "delegate_task"},
                })

                msg = ws_bob.receive_json()
                assert msg["type"] == "knock"
                assert msg["id"] == "knock-001"

    def test_ack_removes_from_inbox(self):
        """ACK frame removes message from inbox."""
        server = RelayServer()
        inbox = server._inbox
        acker_did = _did_for("acker")

        inbox.store(StoredMessage(
            message_id="ack-test",
            sender_did="a", recipient_did=acker_did,
            payload=json.dumps({"v": 1, "type": "message", "id": "ack-test", "from": "a", "to": acker_did}),
        ))
        assert inbox.message_count == 1

        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json(_connect_frame("acker"))
            # Receive pending message
            msg = ws.receive_json()
            assert msg["id"] == "ack-test"
            # Recipient explicitly acks — only then is it removed.
            ws.send_json({"v": 1, "type": "ack", "id": "ack-test"})

        assert inbox.message_count == 0

    def test_pending_message_survives_disconnect_before_ack(self):
        """Regression: previously _deliver_pending acknowledged immediately
        after send_json, so a recipient that received the frame but
        disconnected before processing it lost the message permanently.
        Now the message stays in the inbox until an explicit ack frame
        is received, and a reconnect re-delivers it.
        """
        server = RelayServer()
        inbox = server._inbox
        bob_did = _did_for("bob")

        inbox.store(StoredMessage(
            message_id="survives-001",
            sender_did="alice",
            recipient_did=bob_did,
            payload=json.dumps({
                "v": 1, "type": "message",
                "from": "alice", "to": bob_did,
                "id": "survives-001", "ciphertext": "important",
            }),
        ))
        assert inbox.message_count == 1

        client = TestClient(server.app)
        # First connect: receive frame, disconnect WITHOUT acking.
        with client.websocket_connect("/ws") as ws:
            ws.send_json(_connect_frame("bob"))
            msg = ws.receive_json()
            assert msg["id"] == "survives-001"
            # Drop the connection without sending an ack.

        # Inbox must still contain the message.
        assert inbox.message_count == 1

        # Reconnect: message must be re-delivered.
        with client.websocket_connect("/ws") as ws:
            ws.send_json(_connect_frame("bob"))
            msg = ws.receive_json()
            assert msg["id"] == "survives-001"
            ws.send_json({"v": 1, "type": "ack", "id": "survives-001"})

        assert inbox.message_count == 0


class TestRelayStats:
    def test_initial_stats(self):
        server = RelayServer()
        assert server.stats["messages_routed"] == 0
        assert server.stats["messages_stored"] == 0
        assert server.stats["messages_delivered"] == 0


# ── Ghost-Connection Cleanup (Gap G5) ────────────────────────────────


class TestGhostConnectionCleanup:
    """Vendored relay patch #2 equivalent: when an agent reconnects with
    the same DID, the previous ("ghost") socket is closed eagerly instead
    of relying on the 90-second heartbeat-eviction timer. Verifies that
    after a rebind, only the freshest connection routes messages."""

    def test_rebind_replaces_ghost_connection(self):
        server = RelayServer()
        client = TestClient(server.app)
        rebind_did = _did_for("rebind")
        sender_did = _did_for("sender")

        # First connection registers
        with client.websocket_connect("/ws") as ws_old:
            ws_old.send_json(_connect_frame("rebind"))
            # Second connection with same DID triggers ghost close on old.
            with client.websocket_connect("/ws") as ws_new:
                ws_new.send_json(_connect_frame("rebind"))
                # Send a message to the rebinding DID from another agent.
                with client.websocket_connect("/ws") as ws_sender:
                    ws_sender.send_json(_connect_frame("sender"))
                    ws_sender.send_json({
                        "v": 1, "type": "message",
                        "from": sender_did,
                        "to": rebind_did,
                        "id": "post-rebind",
                        "ciphertext": "data",
                    })
                    # The NEW socket must receive it (ghost old socket is closed).
                    msg = ws_new.receive_json()
                    assert msg["id"] == "post-rebind"
                    assert msg["from"] == sender_did

        # Active connection count returns to 0 after both rebind sockets
        # leave their `with` blocks (sender already left).
        assert len(server._connections) == 0



# ── PR #2659 review fix: Entra-enabled connect MUST require a token ──


class TestEntraAuthBypassFix:
    """When ``_ENTRA_VERIFY_ENABLED`` is true, the relay must REQUIRE
    a valid Entra JWT on connect. Specifically:

      * Empty/missing ``token`` field MUST NOT silently fall through
        to the shared-secret check or to open-acceptance.
      * Verifier-init failure MUST NOT downgrade to shared-secret.

    Regression guard for the bypass flagged in PR #2659 review:
      _ENTRA_VERIFY_ENABLED and client_token  →  if either side
      is falsy, the if-branch is skipped entirely and execution
      falls through to the legacy auth path or to open-accept.
    """

    def _connect_with_entra_enabled(
        self,
        monkeypatch,
        frame: dict,
    ) -> tuple[str, dict | None]:
        """Connect with Entra enabled. Returns (close_reason, error_payload)."""
        from agentmesh.relay import app as relay_app
        monkeypatch.setattr(relay_app, "_ENTRA_VERIFY_ENABLED", True)
        # Disable upstream DID proof-of-possession for these tests —
        # PoP and Entra auth are independent layers; we're testing the
        # Entra-bypass fix here, not PoP. PoP is exercised in the
        # dedicated TestRelayDIDProofOfPossession class.
        monkeypatch.setattr(relay_app, "_REQUIRE_DID_POP", False)
        # Force get_verifier() to return None so we don't actually
        # try to validate — the bypass we care about happens BEFORE
        # any JWT decode work.
        async def _no_verifier():
            return None
        monkeypatch.setattr(
            "agentmesh.identity.entra_verifier.get_verifier",
            _no_verifier,
        )
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json(frame)
            try:
                resp = ws.receive_json()
            except Exception:
                resp = None
            return ("ok", resp)

    def test_missing_token_field_rejected_when_entra_enabled(self, monkeypatch):
        """A connect frame with no ``token`` field must be rejected."""
        _, resp = self._connect_with_entra_enabled(
            monkeypatch,
            {"v": 1, "type": "connect", "from": "did:agentmesh:attacker"},
        )
        assert resp is not None
        assert resp["type"] == "error"
        assert "Entra" in resp["detail"], (
            "Error must distinguish Entra-required from generic auth-failed"
        )

    def test_empty_token_rejected_when_entra_enabled(self, monkeypatch):
        """``token: \"\"`` is a bypass attempt — reject."""
        _, resp = self._connect_with_entra_enabled(
            monkeypatch,
            {"v": 1, "type": "connect", "from": "did:agentmesh:attacker", "token": ""},
        )
        assert resp is not None
        assert resp["type"] == "error"
        assert "Entra" in resp["detail"]

    def test_null_token_rejected_when_entra_enabled(self, monkeypatch):
        """``token: null`` is also a bypass attempt — reject."""
        _, resp = self._connect_with_entra_enabled(
            monkeypatch,
            {"v": 1, "type": "connect", "from": "did:agentmesh:attacker", "token": None},
        )
        assert resp is not None
        assert resp["type"] == "error"
        assert "Entra" in resp["detail"]

    def test_verifier_init_failure_fails_closed(self, monkeypatch):
        """If Entra is enabled but ``get_verifier()`` returns None
        (e.g. post-boot JWKS reachability issue), MUST fail closed.
        Falling through to shared-secret would let an attacker
        downgrade auth by triggering JWKS unavailability."""
        from agentmesh.relay import app as relay_app
        monkeypatch.setattr(relay_app, "_ENTRA_VERIFY_ENABLED", True)
        # PoP is an independent upstream gate; disable for this test.
        monkeypatch.setattr(relay_app, "_REQUIRE_DID_POP", False)
        # Set a legacy shared-secret too — even with the secret
        # present, Entra-enabled mode must NOT silently downgrade.
        monkeypatch.setattr(relay_app, "_RELAY_TOKEN", "legacy-shared-secret")
        async def _no_verifier():
            return None
        monkeypatch.setattr(
            "agentmesh.identity.entra_verifier.get_verifier",
            _no_verifier,
        )
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            # Attacker presents the legacy shared secret hoping for
            # silent downgrade.
            ws.send_json({
                "v": 1,
                "type": "connect",
                "from": "did:agentmesh:attacker",
                "token": "legacy-shared-secret",
            })
            resp = ws.receive_json()
        assert resp["type"] == "error", "shared-secret downgrade must be rejected"

    def test_shared_secret_still_works_when_entra_disabled(self, monkeypatch):
        """Backward compat: when ENTRA is OFF, the legacy shared-secret
        path is unchanged. (This guards against over-tightening: we
        only want to block the bypass under the new Entra-enabled
        contract, not change behavior for unmigrated clusters.)"""
        from agentmesh.relay import app as relay_app
        monkeypatch.setattr(relay_app, "_ENTRA_VERIFY_ENABLED", False)
        # PoP is an independent upstream gate; disable for this back-compat test.
        monkeypatch.setattr(relay_app, "_REQUIRE_DID_POP", False)
        monkeypatch.setattr(relay_app, "_RELAY_TOKEN", "legacy-shared-secret")
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json({
                "v": 1,
                "type": "connect",
                "from": "did:agentmesh:legit",
                "token": "legacy-shared-secret",
            })
            # No error response — connect accepted.
            ws.send_json({
                "v": 1, "type": "heartbeat", "from": "did:agentmesh:legit",
            })


# -- DID Proof-of-Possession (security regression) -------------------


class TestRelayDIDProofOfPossession:
    """Connect frames must carry a valid DID proof; relay must reject
    spoofed DIDs that don't match the supplied public key."""

    def test_rejects_missing_pop_fields(self):
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json({
                "v": 1, "type": "connect",
                "from": "did:mesh:1234567890abcdef1234567890abcdef",
            })
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "did proof failed" in resp["detail"].lower()

    def test_rejects_did_not_matching_pubkey(self):
        """Attacker uses their own key but claims someone else's DID."""
        server = RelayServer()
        client = TestClient(server.app)
        frame = _connect_frame("attacker")
        # Swap the DID for a fabricated one — public_key, timestamp and
        # signature are all still the attacker's. The relay must catch
        # the sha256 mismatch.
        frame["from"] = "did:mesh:" + "00" * 16
        with client.websocket_connect("/ws") as ws:
            ws.send_json(frame)
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "sha256 mismatch" in resp["detail"].lower()

    def test_rejects_bad_signature(self):
        server = RelayServer()
        client = TestClient(server.app)
        frame = _connect_frame("victim")
        frame["signature"] = base64.b64encode(b"\x00" * 64).decode()
        with client.websocket_connect("/ws") as ws:
            ws.send_json(frame)
            resp = ws.receive_json()
            assert resp["type"] == "error"

    def test_rejects_stale_timestamp(self):
        server = RelayServer()
        client = TestClient(server.app)
        sk = _key_for("late")
        pk = sk.verify_key.encode()
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        sig = sk.sign(old_ts.encode()).signature
        frame = {
            "v": 1, "type": "connect",
            "from": f"did:mesh:{hashlib.sha256(pk).hexdigest()[:32]}",
            "public_key": base64.b64encode(pk).decode(),
            "timestamp": old_ts,
            "signature": base64.b64encode(sig).decode(),
        }
        with client.websocket_connect("/ws") as ws:
            ws.send_json(frame)
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "replay" in resp["detail"].lower()

    def test_valid_pop_succeeds(self):
        server = RelayServer()
        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json(_connect_frame("legit"))
            # Heartbeat round-trip proves the socket is still open.
            ws.send_json({"v": 1, "type": "heartbeat", "from": _did_for("legit")})
