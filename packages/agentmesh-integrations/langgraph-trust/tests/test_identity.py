"""Tests for langgraph_trust.identity — AgentIdentityManager and AgentID."""

import threading

from langgraph_trust.identity import AgentIdentityManager


class TestAgentIdentityManager:
    def test_create_identity(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("alice", capabilities=["read", "write"])
        assert identity.did.startswith("did:langgraph:")
        assert len(identity.public_key_bytes) == 32
        assert identity.has_capability("read")
        assert identity.has_capability("write")
        assert not identity.has_capability("admin")

    def test_get_identity(self):
        mgr = AgentIdentityManager()
        mgr.create_identity("bob")
        assert mgr.get_identity("bob") is not None
        assert mgr.get_identity("unknown") is None

    def test_get_or_create_idempotent(self):
        mgr = AgentIdentityManager()
        id1 = mgr.get_or_create("charlie", capabilities=["x"])
        id2 = mgr.get_or_create("charlie", capabilities=["y"])
        assert id1.did == id2.did

    def test_sign_and_verify(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("signer")
        data = b"important data"
        signature = identity.sign(data)
        assert identity.verify(signature, data)

    def test_verify_wrong_data(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("signer")
        signature = identity.sign(b"original")
        assert not identity.verify(signature, b"tampered")

    def test_register_peer(self):
        mgr = AgentIdentityManager()
        local = mgr.create_identity("local")
        peer = mgr.register_peer(
            "remote",
            did="did:langgraph:abc123",
            public_key_bytes=local.public_key_bytes,
            capabilities=["summarize"],
        )
        assert peer.did == "did:langgraph:abc123"
        assert peer.has_capability("summarize")

    def test_peer_cannot_sign(self):
        mgr = AgentIdentityManager()
        local = mgr.create_identity("local")
        peer = mgr.register_peer(
            "remote", did="did:x", public_key_bytes=local.public_key_bytes
        )
        try:
            peer.sign(b"data")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_wildcard_capability(self):
        mgr = AgentIdentityManager()
        admin = mgr.create_identity("admin", capabilities=["*"])
        assert admin.has_capability("anything")
        assert admin.has_capability("everything")

    def test_public_key_hex(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("hex-test")
        assert len(identity.public_key_hex) == 64  # 32 bytes = 64 hex chars

    def test_all_identities(self):
        mgr = AgentIdentityManager()
        mgr.create_identity("a")
        mgr.create_identity("b")
        assert len(mgr.all_identities) == 2

    def test_thread_safety(self):
        mgr = AgentIdentityManager()
        errors = []

        def create_many(prefix: str):
            try:
                for i in range(20):
                    mgr.create_identity(f"{prefix}-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_many, args=(f"t{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(mgr.all_identities) == 80
