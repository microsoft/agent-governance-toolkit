# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the delta audit engine."""

from hypervisor.audit.delta import DeltaEngine, VFSChange


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
