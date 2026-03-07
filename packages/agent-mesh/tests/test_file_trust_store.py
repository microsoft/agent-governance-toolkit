# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for file-backed trust score store."""

import json
import os
import tempfile

import pytest

from agentmesh.storage.file_trust_store import FileTrustStore


@pytest.fixture
def trust_file(tmp_path):
    return str(tmp_path / "trust_scores.json")


class TestFileTrustStore:
    def test_store_and_retrieve(self, trust_file):
        store = FileTrustStore(trust_file)
        store.store_trust_score("did:mesh:agent-1", {"score": 850, "level": "high"})
        result = store.get_trust_score("did:mesh:agent-1")
        assert result == {"score": 850, "level": "high"}

    def test_persistence_across_instances(self, trust_file):
        store1 = FileTrustStore(trust_file)
        store1.store_trust_score("did:mesh:agent-1", {"score": 900})
        store1.store_trust_score("did:mesh:agent-2", {"score": 500})
        del store1

        store2 = FileTrustStore(trust_file)
        assert store2.get_trust_score("did:mesh:agent-1") == {"score": 900}
        assert store2.get_trust_score("did:mesh:agent-2") == {"score": 500}

    def test_update_score(self, trust_file):
        store = FileTrustStore(trust_file)
        store.store_trust_score("did:mesh:agent-1", {"score": 500})
        store.store_trust_score("did:mesh:agent-1", {"score": 900})
        assert store.get_trust_score("did:mesh:agent-1") == {"score": 900}

    def test_delete_score(self, trust_file):
        store = FileTrustStore(trust_file)
        store.store_trust_score("did:mesh:agent-1", {"score": 800})
        assert store.delete_trust_score("did:mesh:agent-1") is True
        assert store.get_trust_score("did:mesh:agent-1") is None

    def test_delete_nonexistent(self, trust_file):
        store = FileTrustStore(trust_file)
        assert store.delete_trust_score("did:mesh:ghost") is False

    def test_list_agents(self, trust_file):
        store = FileTrustStore(trust_file)
        store.store_trust_score("did:mesh:a", {"score": 1})
        store.store_trust_score("did:mesh:b", {"score": 2})
        agents = store.list_agents()
        assert set(agents) == {"did:mesh:a", "did:mesh:b"}

    def test_get_all_scores(self, trust_file):
        store = FileTrustStore(trust_file)
        store.store_trust_score("did:mesh:a", {"score": 100})
        all_scores = store.get_all_scores()
        assert "did:mesh:a" in all_scores

    def test_len_and_contains(self, trust_file):
        store = FileTrustStore(trust_file)
        assert len(store) == 0
        store.store_trust_score("did:mesh:a", {"score": 1})
        assert len(store) == 1
        assert "did:mesh:a" in store
        assert "did:mesh:b" not in store

    def test_nonexistent_returns_none(self, trust_file):
        store = FileTrustStore(trust_file)
        assert store.get_trust_score("did:mesh:ghost") is None

    def test_corrupt_file_starts_fresh(self, trust_file):
        with open(trust_file, "w") as f:
            f.write("NOT VALID JSON!!!")
        store = FileTrustStore(trust_file)
        assert len(store) == 0
        store.store_trust_score("did:mesh:a", {"score": 1})
        assert store.get_trust_score("did:mesh:a") == {"score": 1}

    def test_auto_save_disabled(self, trust_file):
        store = FileTrustStore(trust_file, auto_save=False)
        store.store_trust_score("did:mesh:a", {"score": 1})
        # File should not exist yet
        assert not os.path.exists(trust_file)
        store.save()
        assert os.path.exists(trust_file)

    def test_creates_parent_directories(self, tmp_path):
        deep_path = str(tmp_path / "a" / "b" / "c" / "scores.json")
        store = FileTrustStore(deep_path)
        store.store_trust_score("did:mesh:a", {"score": 1})
        assert os.path.exists(deep_path)

    def test_file_format(self, trust_file):
        store = FileTrustStore(trust_file)
        store.store_trust_score("did:mesh:a", {"score": 42})
        with open(trust_file) as f:
            data = json.load(f)
        assert data["version"] == "1.0"
        assert "saved_at" in data
        assert "did:mesh:a" in data["scores"]
        assert data["scores"]["did:mesh:a"]["score"] == 42
