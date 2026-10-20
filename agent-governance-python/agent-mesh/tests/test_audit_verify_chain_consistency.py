# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for chain verification during append rollback."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest

from agentmesh.governance import audit
from agentmesh.governance.audit import AuditEntry, AuditLog


def _log(count=5):
    log = AuditLog()
    for i in range(count):
        log.log("test", "did:mesh:test", f"action-{i}")
    return log


@pytest.mark.parametrize(
    ("seed_count", "fail_at"),
    [(0, 1), (5, 1), (5, 3), (4, 6)],
    ids=["empty-leaf", "leaf", "parent", "capacity-growth"],
)
def test_verify_chain_waits_for_failed_append_rollback(monkeypatch, seed_count, fail_at):
    log = _log(seed_count)
    chain = log._chain
    before = chain._snapshot()
    pending = AuditEntry(event_type="test", agent_did="did:mesh:test", action="pending")
    paused, release, writer_finished, reader_boundary = (Event() for _ in range(4))
    lock = chain._lock
    node = audit.MerkleNode
    verify_hash = AuditEntry.verify_hash
    verified = []
    calls = 0

    class ObservedLock:
        def __enter__(self):
            acquired = lock.acquire(blocking=False)
            if not acquired:
                reader_boundary.set()
                lock.acquire()
            return self

        def __exit__(self, *args):
            lock.release()

    def fail_node(**kwargs):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            paused.set()
            assert release.wait(5), "writer was not released"
            raise MemoryError("injected tree update failure")
        return node(**kwargs)

    def verify_entry(entry):
        verified.append(entry.entry_id)
        if entry is pending:
            reader_boundary.set()
            assert writer_finished.wait(5), "rollback did not finish"
        return verify_hash(entry)

    def write():
        try:
            chain.add_entry(pending)
        finally:
            writer_finished.set()

    def read():
        try:
            return chain.verify_chain()
        finally:
            reader_boundary.set()

    with monkeypatch.context() as patch:
        patch.setattr(chain, "_lock", ObservedLock())
        patch.setattr(audit, "MerkleNode", fail_node)
        patch.setattr(AuditEntry, "verify_hash", verify_entry)
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(write)
            try:
                assert paused.wait(5), "writer did not reach the failure point"
                reader = pool.submit(read)
                assert reader_boundary.wait(5), "reader did not reach the controlled boundary"
            finally:
                release.set()
            with pytest.raises(MemoryError, match="injected tree update failure"):
                writer.result(timeout=5)
            result = reader.result(timeout=5)

    assert result == (True, None)
    assert verified == [entry.entry_id for entry in before[0]]
    assert chain._snapshot() == before
    assert log.verify_integrity() == (True, None)


def test_verify_chain_hashes_snapshot_outside_lock(monkeypatch):
    log = _log()
    chain = log._chain
    entries, _ = chain._snapshot()
    assert isinstance(chain._lock, type(Lock()))
    verify_hash = AuditEntry.verify_hash
    verified = []

    def verify_and_append(entry):
        assert chain._lock.acquire(blocking=False), "verification held the chain lock"
        chain._lock.release()
        if not verified:
            log.log("test", "did:mesh:test", "during-verification")
        verified.append(entry.entry_id)
        return verify_hash(entry)

    monkeypatch.setattr(AuditEntry, "verify_hash", verify_and_append)
    assert chain.verify_chain() == (True, None)
    assert verified == [entry.entry_id for entry in entries]
    assert len(log.query()) == len(entries) + 1


@pytest.mark.parametrize("count", [0, 1, 5])
def test_verify_chain_accepts_valid_chain(count):
    log = _log(count)
    assert log._chain.verify_chain() == (True, None)
    assert log.verify_integrity() == (True, None)


@pytest.mark.parametrize(
    ("corruption", "error"),
    [
        ("action", "Entry 2 hash mismatch"),
        ("hash", "Entry 2 hash mismatch"),
        ("link", "Entry 2 chain broken"),
    ],
)
def test_verify_chain_preserves_corruption_errors(corruption, error):
    log = _log()
    entry = log.query()[2]
    if corruption == "action":
        entry.action = "tampered"
    elif corruption == "hash":
        entry.entry_hash = "0" * 64
    else:
        entry.previous_hash = "0" * 64
        entry.entry_hash = entry.compute_hash()

    assert log._chain.verify_chain() == (False, error)
    assert log.verify_integrity() == (False, error)
