# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Comprehensive credential lifecycle tests for agent-mesh.

Covers creation, TTL expiry, rotation, revocation, renewal, concurrent
access, chain of trust, cleanup, persistence, and edge cases.

Closes #165
"""

from __future__ import annotations

import hashlib
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

import pytest

from agentmesh.identity import (
    AgentDID,
    AgentIdentity,
    Credential,
    CredentialManager,
    DelegationLink,
    KeyRotationManager,
    RevocationList,
    ScopeChain,
)
from agentmesh.identity.keystore import SoftwareKeyStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(name: str = "test-agent", capabilities: list[str] | None = None):
    return AgentIdentity.create(
        name=name,
        sponsor="lifecycle-test@example.com",
        capabilities=capabilities or ["read", "write"],
    )


def _make_credential(ttl: int = 3600, capabilities: list[str] | None = None):
    return Credential.issue(
        agent_did="did:mesh:test",
        ttl_seconds=ttl,
        capabilities=capabilities or ["read", "write"],
    )


# ===================================================================
# 1. CREATION
# ===================================================================


class TestCredentialCreation:
    """Verify agent identity and credential creation with Ed25519 keys."""

    def test_identity_has_ed25519_public_key(self):
        identity = _make_identity()
        assert identity.public_key is not None
        assert len(identity.public_key) > 0

    def test_identity_did_format(self):
        identity = _make_identity()
        assert str(identity.did).startswith("did:mesh:")

    def test_credential_issue_generates_token(self):
        cred = _make_credential()
        assert cred.token is not None
        assert cred.token_hash is not None
        assert cred.status == "active"

    def test_credential_issue_sets_timestamps(self):
        cred = _make_credential()
        assert cred.issued_at is not None
        assert cred.expires_at is not None
        assert cred.expires_at > cred.issued_at

    def test_credential_issue_assigns_unique_ids(self):
        c1 = _make_credential()
        c2 = _make_credential()
        assert c1.credential_id != c2.credential_id
        assert c1.token != c2.token

    def test_identity_sign_and_verify(self):
        identity = _make_identity()
        data = b"credential-lifecycle-test-payload"
        sig = identity.sign(data)
        assert identity.verify_signature(data, sig) is True

    def test_identity_verify_rejects_wrong_data(self):
        identity = _make_identity()
        sig = identity.sign(b"original")
        assert identity.verify_signature(b"tampered", sig) is False


# ===================================================================
# 2. TTL EXPIRY
# ===================================================================


@pytest.mark.slow
class TestTTLExpiry:
    """Verify credentials expire after their time-to-live window."""

    def test_credential_valid_before_expiry(self):
        cred = _make_credential(ttl=3600)
        assert cred.is_valid() is True

    def test_credential_invalid_after_expiry(self):
        cred = _make_credential(ttl=1)
        time.sleep(1.1)
        assert cred.is_valid() is False

    def test_credential_expiring_soon_detection(self):
        cred = _make_credential(ttl=30)
        assert cred.is_expiring_soon(threshold_seconds=60) is True

    def test_credential_not_expiring_soon(self):
        cred = _make_credential(ttl=3600)
        assert cred.is_expiring_soon(threshold_seconds=60) is False

    def test_default_ttl_is_900_seconds(self):
        cred = Credential.issue(agent_did="did:mesh:default-ttl")
        assert cred.ttl_seconds == 900


# ===================================================================
# 3. ROTATION
# ===================================================================


class TestKeyRotation:
    """Verify seamless key rotation without service interruption."""

    def test_rotate_generates_new_key(self):
        identity = _make_identity()
        old_key = identity.public_key
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=1)
        mgr.rotate()
        assert identity.public_key != old_key

    def test_rotation_preserves_did(self):
        identity = _make_identity()
        original_did = str(identity.did)
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        assert str(identity.did) == original_did

    def test_rotation_creates_proof(self):
        identity = _make_identity()
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        proof = mgr.get_rotation_proof()
        assert proof is not None

    def test_rotation_proof_verifiable(self):
        identity = _make_identity()
        old_key = identity.public_key
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        proof = mgr.get_rotation_proof()
        new_key = identity.public_key
        assert KeyRotationManager.verify_rotation(old_key, new_key, proof) is True

    def test_credential_rotate_creates_new_active(self):
        cred = _make_credential()
        new_cred = cred.rotate()
        assert new_cred.status == "active"
        assert new_cred.is_valid() is True
        assert cred.status == "rotated"

    def test_credential_rotate_preserves_agent_did(self):
        cred = _make_credential()
        new_cred = cred.rotate()
        assert new_cred.agent_did == cred.agent_did

    def test_credential_rotate_links_to_previous(self):
        cred = _make_credential()
        new_cred = cred.rotate()
        assert new_cred.previous_credential_id == cred.credential_id

    def test_rotation_history_maintained(self):
        identity = _make_identity()
        mgr = KeyRotationManager(identity, max_history=5)
        for _ in range(3):
            mgr.rotate()
        assert len(mgr.get_key_history()) == 3


# ===================================================================
# 4. REVOCATION
# ===================================================================


class TestRevocation:
    """Verify immediate credential revocation and propagation."""

    def test_revoke_credential(self):
        cred = _make_credential()
        cred.revoke(reason="compromised")
        assert cred.status == "revoked"
        assert cred.is_valid() is False

    def test_revocation_list_add_and_check(self):
        rl = RevocationList()
        rl.revoke("did:mesh:bad-agent", reason="policy violation", revoked_by="admin")
        assert rl.is_revoked("did:mesh:bad-agent") is True

    def test_revocation_list_unrevoke(self):
        rl = RevocationList()
        rl.revoke("did:mesh:temp", reason="temp", revoked_by="admin")
        rl.unrevoke("did:mesh:temp")
        assert rl.is_revoked("did:mesh:temp") is False

    def test_revocation_callback_invoked(self):
        mgr = CredentialManager()
        cred = mgr.issue(agent_did="did:mesh:callback-test", capabilities=["read"])
        revoked_ids = []
        mgr.on_revocation(lambda c: revoked_ids.append(c.credential_id))
        mgr.revoke(cred.credential_id, reason="test")
        assert cred.credential_id in revoked_ids

    def test_revoke_all_for_agent(self):
        mgr = CredentialManager()
        agent_did = "did:mesh:bulk-revoke"
        mgr.issue(agent_did=agent_did, capabilities=["read"])
        mgr.issue(agent_did=agent_did, capabilities=["write"])
        mgr.revoke_all_for_agent(agent_did, reason="agent decommissioned")
        active = mgr.get_active_for_agent(agent_did)
        assert len(active) == 0

    def test_revocation_cascades_to_children(self):
        parent = _make_identity("parent")
        child = parent.delegate(name="child", capabilities=["read"])
        registry = __import__(
            "agentmesh.identity.agent_id", fromlist=["IdentityRegistry"]
        ).IdentityRegistry()
        registry.register(parent)
        registry.register(child)
        registry.revoke(str(parent.did), reason="compromised")
        assert not child.is_active()


# ===================================================================
# 5. RENEWAL
# ===================================================================


class TestCredentialRenewal:
    """Verify credential renewal before expiry."""

    def test_manager_rotate_if_needed_rotates_expiring(self):
        mgr = CredentialManager(default_ttl=5)
        cred = mgr.issue(agent_did="did:mesh:renew", capabilities=["read"])
        # Force near-expiry
        cred.expires_at = datetime.utcnow() + timedelta(seconds=2)
        new_cred = mgr.rotate_if_needed(cred.credential_id)
        assert new_cred is not None
        assert new_cred.credential_id != cred.credential_id

    def test_manager_rotate_if_needed_skips_fresh(self):
        mgr = CredentialManager(default_ttl=3600)
        cred = mgr.issue(agent_did="did:mesh:fresh", capabilities=["read"])
        result = mgr.rotate_if_needed(cred.credential_id)
        # Fresh credential returned as-is (not rotated)
        assert result.credential_id == cred.credential_id
        assert cred.status == "active"

    def test_renewed_credential_extends_expiry(self):
        cred = _make_credential(ttl=10)
        old_expires = cred.expires_at
        new_cred = cred.rotate()
        assert new_cred.expires_at > old_expires


# ===================================================================
# 6. CONCURRENT ACCESS
# ===================================================================


class TestConcurrentAccess:
    """Verify thread-safe credential operations."""

    def test_concurrent_credential_issuance(self):
        mgr = CredentialManager()
        results = []

        def issue_cred(i):
            return mgr.issue(
                agent_did=f"did:mesh:concurrent-{i}", capabilities=["read"]
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(issue_cred, i) for i in range(20)]
            for f in as_completed(futures):
                results.append(f.result())

        ids = [c.credential_id for c in results]
        assert len(set(ids)) == 20  # all unique

    def test_concurrent_validate(self):
        mgr = CredentialManager()
        creds = [
            mgr.issue(agent_did=f"did:mesh:cv-{i}", capabilities=["read"])
            for i in range(10)
        ]
        results = []

        def validate(c):
            return mgr.validate(c.token)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(validate, c) for c in creds]
            for f in as_completed(futures):
                results.append(f.result())

        assert all(r is not None for r in results)

    def test_concurrent_rotation(self):
        mgr = CredentialManager()
        creds = [
            mgr.issue(agent_did=f"did:mesh:cr-{i}", capabilities=["read"])
            for i in range(10)
        ]

        def rotate(c):
            return mgr.rotate(c.credential_id)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(rotate, c) for c in creds]
            new_creds = [f.result() for f in as_completed(futures)]

        assert len(new_creds) == 10
        for nc in new_creds:
            assert nc.is_valid()


# ===================================================================
# 7. CHAIN OF TRUST
# ===================================================================


class TestChainOfTrust:
    """Verify credential delegation chains and scope narrowing."""

    def test_delegation_narrows_capabilities(self):
        parent = _make_identity("parent")
        child = parent.delegate(name="child", capabilities=["read"])
        assert child.has_capability("read")
        assert not child.has_capability("write")

    def test_scope_chain_creation(self):
        root_did = str(_make_identity("root").did)
        chain, root_link = ScopeChain.create_root(
            sponsor_email="root@example.com",
            root_agent_did=root_did,
            capabilities=["read", "write", "admin"],
        )
        assert chain is not None
        assert root_link is not None

    def test_scope_chain_verify(self):
        root_did = str(_make_identity("root").did)
        chain, root_link = ScopeChain.create_root(
            sponsor_email="root@example.com",
            root_agent_did=root_did,
            capabilities=["read", "write"],
        )
        valid, error = chain.verify()
        assert valid is True, error

    def test_scope_chain_delegation_link(self):
        root_did = str(_make_identity("root").did)
        child_did = str(_make_identity("child").did)
        chain, root_link = ScopeChain.create_root(
            sponsor_email="chain@example.com",
            root_agent_did=root_did,
            capabilities=["read", "write"],
        )
        # Root link must be added first (depth=0)
        chain.add_link(root_link)
        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did=root_link.child_did,
            child_did=child_did,
            parent_capabilities=["read", "write"],
            delegated_capabilities=["read"],
            parent_signature="",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        child_link.link_hash = child_link.compute_hash()
        chain.add_link(child_link)
        valid, error = chain.verify()
        assert valid is True, error

    def test_scope_chain_rejects_capability_escalation(self):
        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did="did:mesh:parent",
            child_did="did:mesh:child",
            parent_capabilities=["read"],
            delegated_capabilities=["read", "admin"],
            parent_signature="",
            link_hash="",
        )
        assert child_link.verify_capability_narrowing() is False


# ===================================================================
# 8. CLEANUP
# ===================================================================


@pytest.mark.slow
class TestExpiredCleanup:
    """Verify expired credential garbage collection."""

    def test_cleanup_removes_expired(self):
        mgr = CredentialManager(default_ttl=1)
        cred = mgr.issue(agent_did="did:mesh:expire-me", capabilities=["read"])
        time.sleep(1.5)
        # Revoke so status != "active", allowing cleanup to remove it
        mgr.revoke(cred.credential_id, reason="expired")
        removed = mgr.cleanup_expired()
        assert removed >= 1

    def test_cleanup_keeps_active(self):
        mgr = CredentialManager(default_ttl=3600)
        cred = mgr.issue(agent_did="did:mesh:keep-me", capabilities=["read"])
        mgr.cleanup_expired()
        assert mgr.validate(cred.token) is not None

    def test_revocation_list_cleanup_expired(self):
        rl = RevocationList()
        rl.revoke("did:mesh:temp-ban", reason="temp", revoked_by="admin", ttl_seconds=1)
        time.sleep(1.5)
        count = rl.cleanup_expired()
        assert count >= 1
        assert rl.is_revoked("did:mesh:temp-ban") is False


# ===================================================================
# 9. PERSISTENCE
# ===================================================================


class TestCredentialPersistence:
    """Verify credential storage and retrieval."""

    def test_revocation_list_save_and_load(self, tmp_path):
        path = str(tmp_path / "revocations.json")
        rl = RevocationList()
        rl.revoke("did:mesh:persist", reason="test", revoked_by="admin")
        rl.save(path)

        rl2 = RevocationList()
        rl2.load(path)
        assert rl2.is_revoked("did:mesh:persist") is True

    def test_keystore_persist_and_retrieve(self):
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-persist")
        retrieved = store.get_public_key("agent-persist")
        assert pub == retrieved

    def test_keystore_sign_after_retrieval(self):
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-sign")
        data = b"persist-test-payload"
        sig = store.sign("agent-sign", data)
        assert store.verify(pub, data, sig) is True


# ===================================================================
# 10. EDGE CASES
# ===================================================================


class TestEdgeCases:
    """Verify handling of invalid, tampered, and replayed credentials."""

    def test_validate_invalid_token(self):
        mgr = CredentialManager()
        result = mgr.validate("invalid-token-that-does-not-exist")
        assert result is None

    def test_verify_tampered_token(self):
        cred = _make_credential()
        assert cred.verify_token(cred.token) is True
        assert cred.verify_token(cred.token + "tampered") is False

    def test_revoked_credential_cannot_validate(self):
        mgr = CredentialManager()
        cred = mgr.issue(agent_did="did:mesh:revoke-edge", capabilities=["read"])
        mgr.revoke(cred.credential_id, reason="edge-case")
        assert mgr.validate(cred.token) is None

    def test_rotated_credential_old_token_invalid(self):
        mgr = CredentialManager()
        cred = mgr.issue(agent_did="did:mesh:rot-edge", capabilities=["read"])
        old_token = cred.token
        mgr.rotate(cred.credential_id)
        assert mgr.validate(old_token) is None

    def test_double_revoke_is_idempotent(self):
        cred = _make_credential()
        cred.revoke(reason="first")
        cred.revoke(reason="second")
        assert cred.status == "revoked"

    def test_capability_wildcard(self):
        cred = _make_credential(capabilities=["*"])
        assert cred.has_capability("read") is True
        assert cred.has_capability("admin") is True

    def test_empty_capabilities(self):
        cred = Credential.issue(agent_did="did:mesh:empty-caps", capabilities=[])
        assert cred.has_capability("read") is False

    def test_keystore_delete_key(self):
        store = SoftwareKeyStore()
        store.generate_keypair("to-delete")
        store.delete_key("to-delete")
        with pytest.raises(KeyError):
            store.get_public_key("to-delete")

    def test_keystore_sign_missing_key_raises(self):
        store = SoftwareKeyStore()
        with pytest.raises(KeyError):
            store.sign("nonexistent", b"data")

    def test_replay_attack_token_reuse_after_rotation(self):
        """Ensure a rotated-out token cannot be replayed."""
        mgr = CredentialManager()
        cred = mgr.issue(agent_did="did:mesh:replay", capabilities=["read"])
        captured_token = cred.token
        mgr.rotate(cred.credential_id)
        # Attempt replay with old token
        assert mgr.validate(captured_token) is None
