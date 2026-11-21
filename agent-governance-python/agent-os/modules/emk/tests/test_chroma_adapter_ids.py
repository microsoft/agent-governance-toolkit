# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for ChromaDBAdapter id round-tripping and error handling.

These tests drive the adapter against a small in-memory stand-in for a Chroma
collection, so they run whether or not ``chromadb`` is installed.
"""

import importlib.util
import sys
import types
from pathlib import Path

import numpy as np
import pytest

from emk.schema import Episode


def _load_adapter_class():
    """Return ChromaDBAdapter, loading store.py with a stub chromadb if needed."""
    try:
        from emk.store import ChromaDBAdapter

        return ChromaDBAdapter
    except ImportError:
        pass

    stub = types.ModuleType("chromadb")
    stub.Client = lambda *args, **kwargs: None
    config = types.ModuleType("chromadb.config")
    config.Settings = lambda *args, **kwargs: None
    stub.config = config
    saved = {name: sys.modules.get(name) for name in ("chromadb", "chromadb.config")}
    sys.modules["chromadb"] = stub
    sys.modules["chromadb.config"] = config
    try:
        store_path = Path(__file__).resolve().parent.parent / "emk" / "store.py"
        spec = importlib.util.spec_from_file_location("_emk_store_with_chroma", store_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    return module.ChromaDBAdapter


ChromaDBAdapter = _load_adapter_class()


class FakeCollection:
    """Minimal stand-in for a Chroma collection: ids mapped to metadata."""

    def __init__(self):
        self.records = {}
        self.fail_get = None

    def add(self, ids, documents=None, embeddings=None, metadatas=None):
        for record_id, metadata in zip(ids, metadatas):
            self.records[record_id] = dict(metadata)

    def update(self, ids, metadatas=None):
        for record_id, metadata in zip(ids, metadatas):
            self.records[record_id] = dict(metadata)

    def get(self, ids=None, limit=None, where=None):
        if self.fail_get is not None:
            raise self.fail_get
        if ids is None:
            found = list(self.records.items())
        else:
            found = [(i, self.records[i]) for i in ids if i in self.records]
        if limit is not None:
            found = found[:limit]
        return {
            "ids": [i for i, _ in found],
            "metadatas": [m for _, m in found],
        }

    def query(self, query_embeddings=None, n_results=10, where=None):
        found = list(self.records.items())[:n_results]
        return {
            "ids": [[i for i, _ in found]],
            "metadatas": [[m for _, m in found]],
        }

    def delete(self, ids):
        for record_id in ids:
            self.records.pop(record_id, None)


def _adapter():
    adapter = ChromaDBAdapter.__new__(ChromaDBAdapter)
    adapter.collection = FakeCollection()
    return adapter


def _episode(**kwargs):
    defaults = dict(goal="g", action="a", result="r", reflection="f")
    defaults.update(kwargs)
    return Episode(**defaults)


def test_get_by_id_returns_requested_id_for_z_timestamp():
    adapter = _adapter()
    episode = _episode(timestamp="2026-01-01T00:00:00Z", metadata={"tag": "x"})
    requested = adapter.store(episode)

    returned = adapter.get_by_id(requested)

    assert returned is not None
    assert returned.episode_id == requested
    assert returned.metadata == {"tag": "x"}
    deleted = adapter.delete(returned.episode_id)
    assert deleted is True
    assert adapter.get_by_id(requested) is None


def test_retrieve_returns_stored_ids():
    adapter = _adapter()
    first = adapter.store(_episode(goal="one", timestamp="2026-01-01T00:00:00Z"))
    second = adapter.store(_episode(goal="two", timestamp="2026-01-02T00:00:00Z"))

    by_filter = adapter.retrieve()
    by_embedding = adapter.retrieve(query_embedding=np.zeros(4, dtype=np.float32))

    assert {ep.episode_id for ep in by_filter} == {first, second}
    assert {ep.episode_id for ep in by_embedding} == {first, second}
    for ep in by_filter + by_embedding:
        assert "episode_id" not in ep.metadata


def test_record_without_stored_id_uses_record_id():
    adapter = _adapter()
    adapter.collection.records["legacy-id"] = {
        "goal": "g",
        "action": "a",
        "result": "r",
        "reflection": "f",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "tag": "x",
    }

    returned = adapter.get_by_id("legacy-id")

    assert returned is not None
    assert returned.episode_id == "legacy-id"
    assert returned.metadata == {"tag": "x"}
    assert [ep.episode_id for ep in adapter.retrieve()] == ["legacy-id"]


def test_update_keeps_record_id():
    adapter = _adapter()
    eid = adapter.store(_episode(goal="before", timestamp="2026-01-01T00:00:00Z"))

    assert adapter.update(eid, _episode(goal="after", timestamp="2026-01-03T00:00:00Z"))

    returned = adapter.get_by_id(eid)
    assert returned.goal == "after"
    assert returned.episode_id == eid


def test_get_by_id_propagates_backend_error():
    adapter = _adapter()
    eid = adapter.store(_episode())
    adapter.collection.fail_get = RuntimeError("backend down")

    with pytest.raises(RuntimeError, match="backend down"):
        adapter.get_by_id(eid)


def test_get_by_id_missing_returns_none():
    adapter = _adapter()
    assert adapter.get_by_id("does-not-exist") is None
