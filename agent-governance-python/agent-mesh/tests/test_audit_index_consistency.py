# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for atomic audit chain and index publication."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest

from agentmesh.governance import audit
from agentmesh.governance.audit import AuditLog


class _ObservedLock:
    def __init__(self, lock, blocked):
        self.lock = lock
        self.blocked = blocked

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            self.blocked.set()
            assert self.lock.acquire(timeout=5), "chain lock was not released"
        return self

    def __exit__(self, *args):
        self.lock.release()


def _assert_indexes_match(log):
    entries = log.query(limit=None)
    by_agent, by_type = {}, {}
    for entry in entries:
        by_agent.setdefault(entry.agent_did, []).append(entry.entry_id)
        by_type.setdefault(entry.event_type, []).append(entry.entry_id)
    assert log._by_agent == by_agent
    assert log._by_type == by_type
    for agent in by_agent:
        assert log.get_entries_for_agent(agent, limit=0) == [
            entry for entry in entries if entry.agent_did == agent
        ]
    for event_type in by_type:
        assert log.get_entries_by_type(event_type, limit=0) == [
            entry for entry in entries if entry.event_type == event_type
        ]
    assert log.verify_integrity() == (True, None)


@pytest.mark.parametrize("index_name", ["_by_agent", "_by_type"])
def test_concurrent_first_bucket_creation_keeps_both_entries(monkeypatch, index_name):
    log = AuditLog()
    paused, release, second_boundary = (Event() for _ in range(3))

    class PausedIndex(dict):
        armed = True

        def pause_if_missing(self, missing):
            if missing and self.armed:
                self.armed = False
                paused.set()
                assert release.wait(5), "first writer was not released"

        def __contains__(self, key):
            found = super().__contains__(key)
            self.pause_if_missing(not found)
            return found

        def get(self, key, default=None):
            value = super().get(key, default)
            self.pause_if_missing(not super().__contains__(key))
            return value

    def second_write():
        try:
            return log.log("test", "did:mesh:test", "second")
        finally:
            second_boundary.set()

    monkeypatch.setattr(log, index_name, PausedIndex())
    monkeypatch.setattr(log._chain, "_lock", _ObservedLock(log._chain._lock, second_boundary))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(log.log, "test", "did:mesh:test", "first")
        try:
            assert paused.wait(5), "first writer did not reach bucket creation"
            second = pool.submit(second_write)
            assert second_boundary.wait(5), "second writer did not reach the boundary"
        finally:
            release.set()
        assert first.result(timeout=5).action == "first"
        assert second.result(timeout=5).action == "second"

    assert [entry.action for entry in log.query()] == ["first", "second"]
    _assert_indexes_match(log)


def test_reversed_sink_completion_preserves_index_order():
    paused, release = Event(), Event()
    completed = []

    class Sink:
        def write(self, entry):
            if entry.action == "first":
                paused.set()
                assert release.wait(5), "first sink call was not released"
            completed.append(entry.action)

    log = AuditLog(sink=Sink())
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(log.log, "test", "did:mesh:test", "first")
        try:
            assert paused.wait(5), "first writer did not reach the sink"
            second = pool.submit(log.log, "test", "did:mesh:test", "second")
            latest = second.result(timeout=5)
            _assert_indexes_match(log)
        finally:
            release.set()
        first.result(timeout=5)

    assert completed == ["second", "first"]
    _assert_indexes_match(log)
    assert log.get_entries_for_agent("did:mesh:test", limit=1) == [latest]
    assert log.get_entries_by_type("test", limit=1) == [latest]


def test_sink_exception_leaves_chain_and_indexes_committed():
    class Sink:
        def write(self, entry):
            raise OSError("injected sink failure")

    log = AuditLog(sink=Sink())
    with pytest.raises(OSError, match="injected sink failure"):
        log.log("test", "did:mesh:test", "failed-sink")

    assert [entry.action for entry in log.query()] == ["failed-sink"]
    _assert_indexes_match(log)


@pytest.mark.parametrize("fail", [False, True])
def test_sink_callback_sees_committed_indexes_outside_lock(fail):
    calls = []

    class Sink:
        def write(self, entry):
            assert isinstance(log._chain._lock, type(Lock()))
            assert log._chain._lock.acquire(blocking=False), "sink held the chain lock"
            log._chain._lock.release()
            calls.append(entry.action)
            _assert_indexes_match(log)
            if entry.action == "outer":
                log.log("nested", "did:mesh:other", "inner")
                if fail:
                    raise OSError("injected sink failure")

    log = AuditLog(sink=Sink())
    if fail:
        with pytest.raises(OSError, match="injected sink failure"):
            log.log("test", "did:mesh:test", "outer")
    else:
        log.log("test", "did:mesh:test", "outer")

    assert calls == ["outer", "inner"]
    assert [entry.action for entry in log.query()] == ["outer", "inner"]
    _assert_indexes_match(log)


@pytest.mark.parametrize("reader_name", ["get_entries_for_agent", "get_entries_by_type"])
@pytest.mark.parametrize("fail", [False, True])
def test_index_reader_waits_for_publication(monkeypatch, reader_name, fail):
    log = AuditLog()
    seed = log.log("test", "did:mesh:test", "seed")
    paused, release, reader_boundary, blocked = (Event() for _ in range(4))

    class PausedBucket(list):
        def append(self, entry_id):
            super().append(entry_id)
            paused.set()
            assert release.wait(5), "publication was not released"
            if fail:
                raise MemoryError("injected index failure")

    class ReaderLock(_ObservedLock):
        def __enter__(self):
            if self.lock.locked():
                blocked.set()
            return super().__enter__()

    def read():
        try:
            key = "did:mesh:test" if reader_name == "get_entries_for_agent" else "test"
            return getattr(log, reader_name)(key)
        finally:
            reader_boundary.set()

    log._by_agent["did:mesh:test"] = PausedBucket([seed.entry_id])
    monkeypatch.setattr(log._chain, "_lock", ReaderLock(log._chain._lock, reader_boundary))
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(log.log, "test", "did:mesh:test", "pending")
        try:
            assert paused.wait(5), "writer did not reach index publication"
            reader = pool.submit(read)
            assert reader_boundary.wait(5), "reader did not reach the boundary"
        finally:
            release.set()
        if fail:
            with pytest.raises(MemoryError, match="injected index failure"):
                writer.result(timeout=5)
            expected = [seed]
        else:
            expected = [seed, writer.result(timeout=5)]
        result = reader.result(timeout=5)

    assert blocked.is_set(), "reader bypassed the publication lock"
    assert result == expected
    _assert_indexes_match(log)


@pytest.mark.parametrize("index_name", ["_by_agent", "_by_type"])
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("after_mutation", [False, True])
def test_failed_index_append_rolls_back_publication(
    monkeypatch, index_name, existing, after_mutation
):
    sink_calls = []

    class Sink:
        def write(self, entry):
            sink_calls.append(entry.entry_id)

    class FailingBucket(list):
        armed = True

        def append(self, entry_id):
            if self.armed:
                self.armed = False
                if after_mutation:
                    super().append(entry_id)
                raise MemoryError("injected index failure")
            super().append(entry_id)

    class Index(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, FailingBucket(value))

    log = AuditLog(sink=Sink())
    log.log("seed", "did:mesh:seed", "seed")
    event_type, agent = ("seed", "did:mesh:seed") if existing else ("new", "did:mesh:new")
    key = agent if index_name == "_by_agent" else event_type
    original = getattr(log, index_name)
    index = Index(original)
    if existing:
        index[key] = original[key]
    monkeypatch.setattr(log, index_name, index)
    before = log._chain._snapshot()
    calls_before = list(sink_calls)

    with pytest.raises(MemoryError, match="injected index failure"):
        log.log(event_type, agent, "failed")

    assert log._chain._snapshot() == before
    assert sink_calls == calls_before
    _assert_indexes_match(log)
    monkeypatch.setattr(log, index_name, {key: list(ids) for key, ids in index.items()})
    retried = log.log(event_type, agent, "retry")
    assert sink_calls == [*calls_before, retried.entry_id]
    _assert_indexes_match(log)


@pytest.mark.parametrize("index_name", ["_by_agent", "_by_type"])
@pytest.mark.parametrize("after_mutation", [False, True])
def test_failed_bucket_creation_rolls_back_publication(monkeypatch, index_name, after_mutation):
    class FailingIndex(dict):
        def __setitem__(self, key, value):
            if after_mutation:
                super().__setitem__(key, value)
            raise MemoryError("injected bucket creation failure")

    log = AuditLog()
    monkeypatch.setattr(log, index_name, FailingIndex())
    with pytest.raises(MemoryError, match="injected bucket creation failure"):
        log.log("test", "did:mesh:test", "failed")

    assert log._chain._snapshot() == ([], None)
    _assert_indexes_match(log)


@pytest.mark.parametrize("existing", [False, True])
def test_failed_tree_update_rolls_back_both_indexes(monkeypatch, existing):
    log = AuditLog()
    seed = log.log("test", "did:mesh:test", "seed")
    before = log._chain._snapshot()

    def fail_node(**kwargs):
        raise MemoryError("injected tree failure")

    event_type, agent = ("test", seed.agent_did) if existing else ("new", "did:mesh:new")
    with monkeypatch.context() as patch:
        patch.setattr(audit, "MerkleNode", fail_node)
        with pytest.raises(MemoryError, match="injected tree failure"):
            log.log(event_type, agent, "failed")

    assert log._chain._snapshot() == before
    _assert_indexes_match(log)
    log.log(event_type, agent, "retry")
    _assert_indexes_match(log)


@pytest.mark.parametrize("reader_name", ["get_entries_for_agent", "get_entries_by_type"])
@pytest.mark.parametrize("limit", [1, 3, 100, 0, -1, -3])
def test_indexed_reader_preserves_limits_order_and_empty_keys(reader_name, limit):
    log = AuditLog()
    matching = []
    for i in range(105):
        matching.append(log.log("", "", f"match-{i}"))
        log.log("other", "did:mesh:other", f"other-{i}")
    read = getattr(log, reader_name)

    result = read("", limit=limit)
    assert isinstance(result, list)
    assert result == matching[-limit:]
    assert all(actual is expected for actual, expected in zip(result, matching[-limit:]))
    assert read("") == matching[-100:]
    assert read("missing", limit=limit) == []
    result.clear()
    assert read("", limit=limit) == matching[-limit:]
