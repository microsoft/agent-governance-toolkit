# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for delta audit engine and commitment."""

from datetime import UTC

from hypervisor.audit.commitment import CommitmentEngine
from hypervisor.audit.delta import DeltaEngine, VFSChange
from hypervisor.audit.gc import EphemeralGC, RetentionPolicy


class TestDeltaEngine:
    def setup_method(self):
        self.engine = DeltaEngine("session:test-audit")

    def test_capture_delta(self):
        changes = [
            VFSChange(path="/file.txt", operation="add", content_hash="abc123"),
        ]
        delta = self.engine.capture("did:agent1", changes)
        assert delta.turn_id == 1
        assert delta.parent_hash is None  # first delta
        assert delta.delta_hash != ""

    def test_hash_chain(self):
        for i in range(3):
            changes = [VFSChange(path=f"/file{i}.txt", operation="add")]
            self.engine.capture("did:a", changes)

        deltas = self.engine.deltas
        assert deltas[0].parent_hash is None  # first delta has no parent
        assert deltas[1].parent_hash == deltas[0].delta_hash
        assert deltas[2].parent_hash == deltas[1].delta_hash

    def test_verify_chain_integrity(self):
        for i in range(5):
            changes = [VFSChange(path=f"/f{i}.txt", operation="add")]
            self.engine.capture("did:a", changes)
        valid, error = self.engine.verify_chain()
        assert valid is True
        assert error is None

    def test_hash_chain_root(self):
        for i in range(4):
            changes = [VFSChange(path=f"/f{i}.txt", operation="add")]
            self.engine.capture("did:a", changes)

        root = self.engine.compute_hash_chain_root()
        assert root is not None
        assert len(root) == 64  # SHA-256 hex

    def test_empty_engine_no_root(self):
        assert self.engine.compute_hash_chain_root() is None

    def test_tamper_content_detected(self):
        for i in range(3):
            changes = [VFSChange(path=f"/f{i}.txt", operation="add")]
            self.engine.capture("did:a", changes)
        # Tamper with content
        self.engine._deltas[1].changes[0].path = "/hacked.txt"
        valid, error = self.engine.verify_chain()
        assert valid is False
        assert "hash mismatch" in error

    def test_tamper_chain_linkage_detected(self):
        for i in range(3):
            changes = [VFSChange(path=f"/f{i}.txt", operation="add")]
            self.engine.capture("did:a", changes)
        # Break chain linkage
        self.engine._deltas[2].parent_hash = "forged"
        valid, error = self.engine.verify_chain()
        assert valid is False

    def test_empty_chain_verifies(self):
        valid, error = self.engine.verify_chain()
        assert valid is True
        assert error is None


class TestCommitmentEngine:
    def setup_method(self):
        self.engine = CommitmentEngine()

    def test_commit_and_verify(self):
        self.engine.commit("session:1", "abc123", ["did:a", "did:b"], 10)
        assert self.engine.verify("session:1", "abc123")
        assert not self.engine.verify("session:1", "wrong")

    def test_unknown_session(self):
        assert not self.engine.verify("nonexistent", "abc")

    def test_batch_queue(self):
        r = self.engine.commit("s1", "h1", ["did:a"], 5)
        self.engine.queue_for_batch(r)
        batch = self.engine.flush_batch()
        assert len(batch) == 1
        assert self.engine.flush_batch() == []  # cleared


class TestEphemeralGC:
    def test_collect(self):
        gc = EphemeralGC()
        result = gc.collect(
            session_id="session:1",
            vfs_file_count=100,
            cache_count=50,
            delta_count=20,
            estimated_vfs_bytes=1_000_000,
            estimated_cache_bytes=500_000,
            estimated_delta_bytes=50_000,
        )
        # Public preview: no actual purge, data retained
        assert result.purged_vfs_files == 0
        assert result.retained_deltas == 20
        # No savings since nothing is purged
        assert result.storage_saved_bytes == 0
        assert result.savings_pct == 0

    def test_retention_policy(self):
        from datetime import datetime, timedelta
        gc = EphemeralGC(RetentionPolicy(delta_retention_days=30))
        old = datetime.now(UTC) - timedelta(days=31)
        # Public preview: never expires deltas
        assert not gc.should_expire_deltas(old)
        recent = datetime.now(UTC) - timedelta(days=1)
        assert not gc.should_expire_deltas(recent)
