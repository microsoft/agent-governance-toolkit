# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Relay service."""

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from agentmesh.relay.app import RelayServer
from agentmesh.relay.store import InMemoryInboxStore, StoredMessage


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
        with client.websocket_connect("/ws") as ws:
            ws.send_json({
                "v": 1, "type": "connect", "from": "did:agentmesh:alice",
            })
            # Should stay connected (no error response)
            # Send heartbeat to verify connection works
            ws.send_json({
                "v": 1, "type": "heartbeat", "from": "did:agentmesh:alice",
            })

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

        with client.websocket_connect("/ws") as ws_bob:
            ws_bob.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:bob"})

            with client.websocket_connect("/ws") as ws_alice:
                ws_alice.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:alice"})

                # Alice sends to Bob
                ws_alice.send_json({
                    "v": 1, "type": "message",
                    "from": "did:agentmesh:alice", "to": "did:agentmesh:bob",
                    "id": "msg-001", "ciphertext": "encrypted_payload",
                })

                # Bob receives
                msg = ws_bob.receive_json()
                assert msg["type"] == "message"
                assert msg["from"] == "did:agentmesh:alice"
                assert msg["id"] == "msg-001"

        assert server.stats["messages_routed"] == 1

    def test_message_stored_when_offline(self):
        """Message stored when recipient is offline."""
        server = RelayServer()
        client = TestClient(server.app)

        with client.websocket_connect("/ws") as ws_alice:
            ws_alice.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:alice"})

            # Send to offline Bob
            ws_alice.send_json({
                "v": 1, "type": "message",
                "from": "did:agentmesh:alice", "to": "did:agentmesh:bob",
                "id": "offline-001", "ciphertext": "stored_payload",
            })

        assert server.stats["messages_stored"] == 1

    def test_pending_delivered_on_connect(self):
        """Stored messages delivered when agent reconnects."""
        server = RelayServer()
        inbox = server._inbox

        # Pre-store a message for Bob
        inbox.store(StoredMessage(
            message_id="pending-001",
            sender_did="did:agentmesh:alice",
            recipient_did="did:agentmesh:bob",
            payload=json.dumps({
                "v": 1, "type": "message",
                "from": "did:agentmesh:alice", "to": "did:agentmesh:bob",
                "id": "pending-001", "ciphertext": "old_message",
            }),
        ))

        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws_bob:
            ws_bob.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:bob"})

            # Should receive the pending message
            msg = ws_bob.receive_json()
            assert msg["id"] == "pending-001"

        assert server.stats["messages_delivered"] == 1

    def test_knock_routing(self):
        """KNOCK frames route like messages."""
        server = RelayServer()
        client = TestClient(server.app)

        with client.websocket_connect("/ws") as ws_bob:
            ws_bob.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:bob"})

            with client.websocket_connect("/ws") as ws_alice:
                ws_alice.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:alice"})

                ws_alice.send_json({
                    "v": 1, "type": "knock",
                    "from": "did:agentmesh:alice", "to": "did:agentmesh:bob",
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

        inbox.store(StoredMessage(
            message_id="ack-test",
            sender_did="a", recipient_did="did:agentmesh:acker",
            payload=json.dumps({"v": 1, "type": "message", "id": "ack-test", "from": "a", "to": "did:agentmesh:acker"}),
        ))
        assert inbox.message_count == 1

        client = TestClient(server.app)
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"v": 1, "type": "connect", "from": "did:agentmesh:acker"})
            # Receive pending message
            msg = ws.receive_json()
            assert msg["id"] == "ack-test"

        # Message should be acknowledged (delivered removes from inbox)
        assert inbox.message_count == 0


class TestRelayStats:
    def test_initial_stats(self):
        server = RelayServer()
        assert server.stats["messages_routed"] == 0
        assert server.stats["messages_stored"] == 0
        assert server.stats["messages_delivered"] == 0
