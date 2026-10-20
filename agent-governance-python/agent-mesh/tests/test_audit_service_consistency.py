# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for consistent audit service and collector responses."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest

from agentmesh.governance import audit
from agentmesh.governance.audit import AuditEntry, AuditSnapshot
from agentmesh.services.audit import AuditService


def _service(count=5):
    service = AuditService()
    for i in range(count):
        service.log_action("did:mesh:test", f"action-{i}")
    return service


def _reader(service, kind, monkeypatch):
    if kind == "count":
        return lambda: service.entry_count
    if kind == "summary":
        return service.summary
    if kind == "snapshot":
        return service._log.verify_snapshot
    pytest.importorskip("fastapi", reason="fastapi not installed (optional server extra)")
    from agentmesh.server import audit_collector

    monkeypatch.setattr(audit_collector, "_audit_service", service)
    return lambda: asyncio.run(audit_collector.verify_integrity())


def _expected(kind, entries, root, valid=True, error=None):
    count = len(entries)
    if kind == "count":
        return count
    if kind == "snapshot":
        return AuditSnapshot(entries, root, valid, error)
    if kind == "summary":
        return {"total_entries": count, "chain_valid": valid, "root_hash": root}
    return {"chain_valid": valid, "entry_count": count}


@pytest.mark.parametrize("kind", ["count", "summary", "collector", "snapshot"])
@pytest.mark.parametrize("seed_count", [0, 5])
@pytest.mark.parametrize("fail", [False, True])
def test_service_reader_waits_for_commit_or_rollback(monkeypatch, kind, seed_count, fail):
    service = _service(seed_count)
    chain = service.chain
    read = _reader(service, kind, monkeypatch)
    before = chain._snapshot()
    paused, release, reader_boundary = (Event() for _ in range(3))
    blocked = []
    lock = chain._lock
    node = audit.MerkleNode

    class ObservedLock:
        def __enter__(self):
            acquired = lock.acquire(blocking=False)
            if not acquired:
                blocked.append(True)
                reader_boundary.set()
                assert lock.acquire(timeout=5), "writer did not release the lock"
            return self

        def __exit__(self, *args):
            lock.release()

    def pause_node(**kwargs):
        paused.set()
        assert release.wait(5), "writer was not released"
        if fail:
            raise MemoryError("injected append failure")
        return node(**kwargs)

    def read_at_boundary():
        try:
            return read()
        finally:
            reader_boundary.set()

    with monkeypatch.context() as patch:
        patch.setattr(chain, "_lock", ObservedLock())
        patch.setattr(audit, "MerkleNode", pause_node)
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(service.log_action, "did:mesh:test", "pending")
            try:
                assert paused.wait(5), "writer did not reach the controlled boundary"
                reader = pool.submit(read_at_boundary)
                assert reader_boundary.wait(5), "reader neither locked nor returned"
            finally:
                release.set()
            if fail:
                with pytest.raises(MemoryError, match="injected append failure"):
                    writer.result(timeout=5)
            else:
                writer.result(timeout=5)
            result = reader.result(timeout=5)

    entries, root = chain._snapshot()
    assert blocked == [True]
    assert len(entries) == seed_count + (not fail)
    assert result == _expected(kind, entries, root)
    if fail:
        assert (entries, root) == before


@pytest.mark.parametrize("kind", ["summary", "collector", "snapshot"])
@pytest.mark.parametrize("append_at", ["snapshot-release", "verification"])
def test_response_keeps_one_snapshot_during_append(monkeypatch, kind, append_at):
    service = _service()
    chain = service.chain
    entries, root = chain._snapshot()
    read = _reader(service, kind, monkeypatch)
    lock = chain._lock
    assert isinstance(lock, type(Lock()))
    verify_hash = AuditEntry.verify_hash
    verified = []
    appended = False

    def append_once():
        nonlocal appended
        if not appended:
            appended = True
            service.log_action("did:mesh:test", "after-snapshot")

    class AppendAfterRead:
        def __enter__(self):
            assert lock.acquire(timeout=5), "nested chain lock acquisition"
            return self

        def __exit__(self, *args):
            lock.release()
            if append_at == "snapshot-release":
                append_once()

    def verify_outside_lock(entry):
        assert lock.acquire(blocking=False), "verification held the chain lock"
        lock.release()
        if append_at == "verification":
            append_once()
        verified.append(entry.entry_id)
        return verify_hash(entry)

    with monkeypatch.context() as patch:
        patch.setattr(chain, "_lock", AppendAfterRead())
        patch.setattr(AuditEntry, "verify_hash", verify_outside_lock)
        result = read()

    assert appended
    assert service.entry_count == len(entries) + 1
    assert chain.get_root_hash() != root
    assert verified == [entry.entry_id for entry in entries]
    assert result == _expected(kind, entries, root)


@pytest.mark.parametrize("kind", ["summary", "collector", "snapshot"])
@pytest.mark.parametrize("state", ["empty", "healthy", "bad-hash", "bad-link"])
def test_response_preserves_shape_and_corruption_detection(monkeypatch, kind, state):
    service = _service(0 if state == "empty" else 5)
    entries, root = service.chain._snapshot()
    error = None
    if state == "bad-hash":
        entries[2].action = "tampered"
        error = "Entry 2 hash mismatch"
    elif state == "bad-link":
        entries[2].previous_hash = "0" * 64
        entries[2].entry_hash = entries[2].compute_hash()
        error = "Entry 2 chain broken"

    result = _reader(service, kind, monkeypatch)()

    assert result == _expected(kind, entries, root, state in ("empty", "healthy"), error)


def test_verified_snapshot_membership_is_detached_from_chain():
    service = _service()
    entries, root, valid, error = service._log.verify_snapshot()
    expected = list(entries)

    service.log_action("did:mesh:test", "later")

    assert entries == expected
    assert valid is True
    assert error is None
    assert root != service.chain.get_root_hash()
    entries.clear()
    assert service.entry_count == len(expected) + 1


@pytest.mark.parametrize("broken_link", [False, True])
def test_invalid_snapshot_returns_error_without_second_read(monkeypatch, broken_link):
    service = _service()
    entries, root = service.chain._snapshot()
    if broken_link:
        entries[2].previous_hash = "0" * 64
        entries[2].entry_hash = entries[2].compute_hash()
        error = "Entry 2 chain broken"
    else:
        entries[2].action = "tampered"
        error = "Entry 2 hash mismatch"
    capture = service.chain._snapshot
    calls = []

    def capture_once():
        assert not calls, "verification captured a second snapshot"
        calls.append(True)
        snapshot = capture()
        service.log_action("did:mesh:test", "after-snapshot")
        return snapshot

    def reject_second_verification():
        pytest.fail("snapshot error required a separate integrity check")

    monkeypatch.setattr(service.chain, "_snapshot", capture_once)
    monkeypatch.setattr(service._log, "verify_integrity", reject_second_verification)

    result = service._log.verify_snapshot()

    assert result.entries == entries
    assert result.root_hash == root
    assert result.valid is False
    assert result.error == error
    assert calls == [True]
    assert service.entry_count == len(entries) + 1
    assert service.chain.get_root_hash() != root


@pytest.mark.parametrize("kind", ["summary", "collector"])
@pytest.mark.parametrize("valid", [False, True])
def test_response_uses_public_verified_snapshot(monkeypatch, kind, valid):
    service = _service()
    entries, root = service.chain._snapshot()
    read = _reader(service, kind, monkeypatch)
    calls = []

    class SnapshotLog:
        def verify_snapshot(self):
            calls.append(True)
            return AuditSnapshot(entries, root, valid, None if valid else "Entry 2 hash mismatch")

    monkeypatch.setattr(service, "_log", SnapshotLog())

    assert read() == _expected(kind, entries, root, valid)
    assert calls == [True]
