# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the ChromaDBAdapter update/delete operations."""

import numpy as np
import pytest

from emk.schema import Episode

pytest.importorskip("chromadb")

from emk.store import ChromaDBAdapter  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_chroma():
    """Isolate ChromaDB's shared in-process system between tests."""
    from chromadb.api.shared_system_client import SharedSystemClient

    SharedSystemClient.clear_system_cache()
    yield
    SharedSystemClient.clear_system_cache()


def _adapter(tmp_path):
    return ChromaDBAdapter(
        collection_name="test_update_delete",
        persist_directory=str(tmp_path / "chroma"),
    )


def _episode(goal="goal", result="result", **kwargs):
    return Episode(
        goal=goal, action="action", result=result, reflection="ok", **kwargs
    )


def test_update_existing_episode(tmp_path):
    adapter = _adapter(tmp_path)
    eid = adapter.store(_episode(goal="original"), embedding=np.zeros(8, dtype=np.float32))

    updated = _episode(goal="changed", result="new-result", episode_id=eid)
    result = adapter.update(eid, updated)
    assert result is True

    got = adapter.get_by_id(eid)
    assert got is not None
    assert got.goal == "changed"
    assert got.result == "new-result"


def test_update_missing_returns_false(tmp_path):
    adapter = _adapter(tmp_path)
    result = adapter.update("does-not-exist", _episode())
    assert result is False


def test_delete_existing_episode(tmp_path):
    adapter = _adapter(tmp_path)
    eid = adapter.store(_episode(), embedding=np.zeros(8, dtype=np.float32))

    deleted = adapter.delete(eid)
    assert deleted is True
    assert adapter.get_by_id(eid) is None


def test_delete_missing_returns_false(tmp_path):
    adapter = _adapter(tmp_path)
    deleted = adapter.delete("does-not-exist")
    assert deleted is False
