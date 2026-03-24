# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for identity revocation list."""

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentmesh.identity.revocation import RevocationEntry, RevocationList


class TestRevocationEntry:
    def test_entry_defaults(self):
        entry = RevocationEntry(agent_did="did:mesh:abc123", reason="compromised")
        assert entry.agent_did == "did:mesh:abc123"
        assert entry.reason == "compromised"
        assert entry.revoked_by is None
        assert entry.expires_at is None
        assert entry.revoked_at is not None

    def test_entry_with_all_fields(self):
        now = datetime.now(timezone.utc)
        entry = RevocationEntry(
            agent_did="did:mesh:abc123",
            reason="policy violation",
            revoked_by="did:mesh:admin",
            revoked_at=now,
            expires_at=now + timedelta(hours=1),
        )
        assert entry.revoked_by == "did:mesh:admin"
        assert entry.expires_at is not None


@pytest.mark.slow
class TestRevocationList:
    def test_revoke_and_check(self):
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="compromised")
        assert rl.is_revoked("did:mesh:agent1") is True
        assert rl.is_revoked("did:mesh:agent2") is False

    def test_unrevoke_removes_entry(self):
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="test")
        assert rl.is_revoked("did:mesh:agent1") is True
        result = rl.unrevoke("did:mesh:agent1")
        assert result is True
        assert rl.is_revoked("did:mesh:agent1") is False

    def test_unrevoke_not_revoked(self):
        rl = RevocationList()
        result = rl.unrevoke("did:mesh:nonexistent")
        assert result is False

    def test_temporary_revocation_expires(self):
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="timeout", ttl_seconds=1)
        assert rl.is_revoked("did:mesh:agent1") is True
        time.sleep(1.1)
        assert rl.is_revoked("did:mesh:agent1") is False

    def test_file_backed_persistence(self, tmp_path):
        path = str(tmp_path / "revocations.json")
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="test1")
        rl.revoke("did:mesh:agent2", reason="test2", revoked_by="did:mesh:admin")
        rl.save(path)

        rl2 = RevocationList()
        rl2.load(path)
        assert rl2.is_revoked("did:mesh:agent1") is True
        assert rl2.is_revoked("did:mesh:agent2") is True
        entry = rl2.get_entry("did:mesh:agent2")
        assert entry is not None
        assert entry.revoked_by == "did:mesh:admin"

    def test_file_backed_auto_persist(self, tmp_path):
        path = str(tmp_path / "revocations.json")
        rl = RevocationList(storage=path)
        rl.revoke("did:mesh:agent1", reason="auto-persist test")

        rl2 = RevocationList(storage=path)
        assert rl2.is_revoked("did:mesh:agent1") is True

    def test_cleanup_expired(self):
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="temp", ttl_seconds=1)
        rl.revoke("did:mesh:agent2", reason="permanent")
        time.sleep(1.1)
        removed = rl.cleanup_expired()
        assert removed == 1
        assert rl.is_revoked("did:mesh:agent1") is False
        assert rl.is_revoked("did:mesh:agent2") is True

    def test_list_revoked(self):
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="r1")
        rl.revoke("did:mesh:agent2", reason="r2")
        rl.revoke("did:mesh:agent3", reason="r3")
        revoked = rl.list_revoked()
        assert len(revoked) == 3
        dids = {e.agent_did for e in revoked}
        assert dids == {"did:mesh:agent1", "did:mesh:agent2", "did:mesh:agent3"}

    def test_revocation_with_reason_and_revoker(self):
        rl = RevocationList()
        entry = rl.revoke(
            "did:mesh:agent1",
            reason="policy violation",
            revoked_by="did:mesh:admin",
        )
        assert entry.reason == "policy violation"
        assert entry.revoked_by == "did:mesh:admin"
        retrieved = rl.get_entry("did:mesh:agent1")
        assert retrieved is not None
        assert retrieved.reason == "policy violation"
        assert retrieved.revoked_by == "did:mesh:admin"

    def test_revoke_already_revoked_overwrites(self):
        rl = RevocationList()
        rl.revoke("did:mesh:agent1", reason="first reason")
        rl.revoke("did:mesh:agent1", reason="updated reason")
        assert len(rl) == 1
        entry = rl.get_entry("did:mesh:agent1")
        assert entry is not None
        assert entry.reason == "updated reason"

    def test_get_entry_not_revoked(self):
        rl = RevocationList()
        assert rl.get_entry("did:mesh:nonexistent") is None

    def test_len(self):
        rl = RevocationList()
        assert len(rl) == 0
        rl.revoke("did:mesh:agent1", reason="r1")
        assert len(rl) == 1
        rl.revoke("did:mesh:agent2", reason="r2")
        assert len(rl) == 2
        rl.unrevoke("did:mesh:agent1")
        assert len(rl) == 1
