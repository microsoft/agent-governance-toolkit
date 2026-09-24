# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for ``MerkleAuditChain`` root reproducibility.

The root recorded incrementally on each :meth:`MerkleAuditChain.add_entry`
must equal a from-scratch rebuild over the same entries, so that an exported
``merkle_root`` is reproducible by an independent verifier.

Before the fix, ``add_entry`` padded *interior* tree levels with singleton
zero nodes while ``_rebuild_tree`` padded at the *leaf* level and hashed the
padding upward. The two constructions produced different roots once a real
leaf's authentication path reached an interior padding node, first observable
at five entries (and again at 6, 9, ...).
"""

from __future__ import annotations

import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Event

import pytest

from agentmesh.governance.audit import AuditEntry, AuditLog, MerkleAuditChain


def _entry(i: int) -> AuditEntry:
    return AuditEntry(
        event_type="tool_invocation",
        agent_did=f"did:mesh:agent-{i}",
        action=f"act-{i}",
        resource=f"res-{i}",
    )


def _textbook_merkle_root(leaf_hashes: list[str]) -> str | None:
    """Independent, pure-hashlib textbook Merkle root (zero-leaf padded to a
    power of two).

    Deliberately shares no code with :class:`MerkleAuditChain`, so the
    reproducibility assertions cannot pass by comparing the implementation with
    itself.
    """
    if not leaf_hashes:
        return None
    level = list(leaf_hashes)
    while len(level) & (len(level) - 1) != 0:
        level.append('0' * 64)
    while len(level) > 1:
        level = [
            hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


class TestMerkleRootReproducible:
    def test_incremental_root_matches_independent_recompute(self):
        # The incremental root must equal a from-scratch textbook recomputation
        # over the same leaves, across several capacity doublings and every size
        # that diverged before the fix (5, 6, 9-14, 17-30).
        for n in range(1, 33):
            chain = MerkleAuditChain()
            for i in range(n):
                chain.add_entry(_entry(i))
            incremental = chain.get_root_hash()
            independent = _textbook_merkle_root([e.entry_hash for e in chain._entries])
            assert incremental == independent, (
                f"n={n}: incremental root {incremental} != independent recompute {independent}"
            )

    def test_incremental_root_matches_full_rebuild(self):
        # The incremental construction and the from-scratch _rebuild_tree are
        # separate code paths that must converge on the same canonical root.
        # This deliberately calls the private _rebuild_tree: the divergence being
        # regression-tested is *between* the two internal constructions, so the
        # black-box public API alone cannot exercise it (the independent textbook
        # recompute in the sibling test covers the public-API reproducibility).
        for n in (5, 6, 9, 13, 16, 20):
            chain = MerkleAuditChain()
            for i in range(n):
                chain.add_entry(_entry(i))
            incremental = chain.get_root_hash()
            chain._rebuild_tree()
            assert chain.get_root_hash() == incremental, f"n={n}: rebuild disagrees with incremental"

    def test_incremental_root_matches_independent_recompute_large(self):
        # Larger, non-power-of-two sizes across further capacity doublings
        # (100 crosses the 64->128 doubling, 1000 crosses 512->1024). Built
        # once per size and compared against the independent recompute.
        for n in (100, 1000):
            chain = MerkleAuditChain()
            for i in range(n):
                chain.add_entry(_entry(i))
            incremental = chain.get_root_hash()
            independent = _textbook_merkle_root([e.entry_hash for e in chain._entries])
            assert incremental == independent, (
                f"n={n}: incremental root {incremental} != independent recompute {independent}"
            )

    def test_root_is_deterministic_for_identical_entries(self):
        # Two chains fed byte-identical entries must record the same root, and
        # rebuilding either from scratch must not change it.
        base = [_entry(i) for i in range(9)]
        first = MerkleAuditChain()
        second = MerkleAuditChain()
        for entry in base:
            first.add_entry(copy.deepcopy(entry))
            second.add_entry(copy.deepcopy(entry))
        assert first.get_root_hash() == second.get_root_hash()
        second._rebuild_tree()
        assert first.get_root_hash() == second.get_root_hash()

    def test_empty_chain_root_is_none(self):
        chain = MerkleAuditChain()
        assert chain.get_root_hash() is None
        assert _textbook_merkle_root([]) is None

    def test_five_entries_is_the_minimal_reproducer(self):
        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        recorded = chain.get_root_hash()
        # Feeding the same entries to a fresh chain must yield the same root.
        # Deep-copy each entry: add_entry rewrites previous_hash/entry_hash in
        # place, so passing the originals would mutate chain._entries and make
        # the independent recompute below no longer independent.
        fresh = MerkleAuditChain()
        for entry in list(chain._entries):
            fresh.add_entry(copy.deepcopy(entry))
        assert fresh.get_root_hash() == recorded
        # And an independent recompute over the recorded entries must agree.
        assert _textbook_merkle_root([e.entry_hash for e in chain._entries]) == recorded

    def test_inclusion_proofs_verify_against_recorded_root(self):
        # Proofs changed across every affected size, not just the n=5 reproducer,
        # so verify every entry's proof at several sizes that span capacity
        # doublings (6, 9, 13 and 20 all diverged before the fix).
        for n in (5, 6, 9, 13, 20):
            chain = MerkleAuditChain()
            entries = [_entry(i) for i in range(n)]
            for entry in entries:
                chain.add_entry(entry)
            root = chain.get_root_hash()
            for entry in entries:
                proof = chain.get_proof(entry.entry_id)
                assert proof is not None, f"n={n}: no proof for {entry.entry_id}"
                assert chain.verify_proof(entry.entry_hash, proof, root), (
                    f"n={n}: proof for {entry.entry_id} did not verify against the recorded root"
                )

    def test_tampered_leaf_changes_the_rebuilt_root(self):
        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        recorded = chain.get_root_hash()
        # Corrupt a stored leaf hash; a verifier that recomputes the root must
        # observe a different value, i.e. tampering remains detectable.
        chain._entries[1].entry_hash = hashlib.sha256(b"tampered").hexdigest()
        assert _textbook_merkle_root([e.entry_hash for e in chain._entries]) != recorded

    @pytest.mark.parametrize("write_method", ["add_entry", "_rebuild_tree"])
    def test_snapshot_waits_for_complete_chain_update(self, monkeypatch, write_method):
        from agentmesh.governance import audit

        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        appended = _entry(5)
        update_paused = Event()
        finish_update = Event()
        snapshot_attempted = Event()
        snapshot_blocked = []
        lock = chain._lock
        node = audit.MerkleNode

        class ObservedLock:
            def __enter__(self):
                if update_paused.is_set():
                    acquired = lock.acquire(blocking=False)
                    snapshot_blocked.append(not acquired)
                    snapshot_attempted.set()
                    if acquired:
                        return self
                lock.acquire()
                return self

            def __exit__(self, *args):
                lock.release()

        def pause_tree_update(**kwargs):
            update_paused.set()
            assert finish_update.wait(10), "tree update was not released"
            return node(**kwargs)

        monkeypatch.setattr(chain, "_lock", ObservedLock())
        monkeypatch.setattr(audit, "MerkleNode", pause_tree_update)
        with ThreadPoolExecutor(max_workers=2) as pool:
            args = (appended,) if write_method == "add_entry" else ()
            writer = pool.submit(getattr(chain, write_method), *args)
            try:
                assert update_paused.wait(10), "tree update did not reach the hook"
                reader = pool.submit(chain._snapshot)
                assert snapshot_attempted.wait(10), "snapshot did not attempt the lock"
                assert snapshot_blocked == [True]
                assert not reader.done()
            finally:
                finish_update.set()
            writer.result(timeout=10)
            entries, root = reader.result(timeout=10)

        assert len(entries) == (6 if write_method == "add_entry" else 5)
        assert root == _textbook_merkle_root([entry.entry_hash for entry in entries])
        assert chain.verify_chain() == (True, None)

    def test_snapshot_membership_is_detached_from_chain(self):
        chain = MerkleAuditChain()
        chain.add_entry(_entry(0))

        entries, root = chain._snapshot()
        entries.clear()

        current_entries, current_root = chain._snapshot()
        assert len(current_entries) == 1
        assert current_root == root


@pytest.fixture(scope="class")
def large_audit_log():
    log = AuditLog()
    entries = [
        log.log("tool_invocation", "did:mesh:test-agent", f"action-{i}")
        for i in range(10001)
    ]
    return log, entries


class TestAuditLogExport:
    @pytest.mark.parametrize("filtered", [False, True])
    def test_export_keeps_root_from_before_append(self, monkeypatch, filtered):
        log = AuditLog()
        entries = [_entry(i) for i in range(5)]
        for i, entry in enumerate(entries):
            entry.timestamp = datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC)
            log._chain.add_entry(entry)
        appended = _entry(5)
        calls = 0

        class AppendOnExportTimestamp(datetime):
            @classmethod
            def now(cls, tz=None):
                nonlocal calls
                calls += 1
                log._chain.add_entry(appended)
                return datetime.now(tz)

        # exported_at is read after entry capture and before the old root lookups.
        monkeypatch.setattr("agentmesh.governance.audit.datetime", AppendOnExportTimestamp)
        bounds = (
            {"start_time": entries[1].timestamp, "end_time": entries[3].timestamp}
            if filtered else {}
        )

        exported = log.export(**bounds)

        assert calls == 1
        assert len(log.query(limit=None)) == 6
        expected = entries[1:4] if filtered else entries
        assert exported["entries"] == [entry.model_dump() for entry in expected]
        assert exported["entry_count"] == len(expected)
        root = _textbook_merkle_root([entry.entry_hash for entry in entries])
        assert exported["merkle_root"] == exported["chain_root"] == root
        assert root != log._chain.get_root_hash()

    def test_export_includes_all_entries_and_reproducible_root(self, large_audit_log):
        log, entries = large_audit_log

        exported = log.export()

        assert exported["entry_count"] == 10001
        assert exported["entries"] == [entry.model_dump() for entry in entries]
        root = _textbook_merkle_root([entry["entry_hash"] for entry in exported["entries"]])
        assert exported["merkle_root"] == exported["chain_root"] == root
        assert log.verify_integrity() == (True, None)

    def test_cloudevents_export_includes_all_entries_and_hashes(self, large_audit_log):
        log, entries = large_audit_log

        events = log.export_cloudevents()

        assert len(events) == 10001
        assert events == [entry.to_cloudevent() for entry in entries]
        root = _textbook_merkle_root([event["agentmeshentryhash"] for event in events])
        assert root == _textbook_merkle_root([entry.entry_hash for entry in entries])
        assert root == log.export()["merkle_root"]

    @pytest.mark.parametrize("bounds", ["start", "end", "both"])
    def test_export_time_filters_preserve_full_chain_root(self, large_audit_log, bounds):
        log, entries = large_audit_log
        start = entries[2500].timestamp if bounds in ("start", "both") else None
        end = entries[7500].timestamp if bounds in ("end", "both") else None
        expected = [
            entry for entry in entries
            if (start is None or entry.timestamp >= start)
            and (end is None or entry.timestamp <= end)
        ]

        exported = log.export(start_time=start, end_time=end)
        events = log.export_cloudevents(start_time=start, end_time=end)

        assert exported["entry_count"] == len(expected)
        assert exported["entries"] == [entry.model_dump() for entry in expected]
        assert events == [entry.to_cloudevent() for entry in expected]
        root = _textbook_merkle_root([entry.entry_hash for entry in entries])
        assert exported["merkle_root"] == exported["chain_root"] == root

    def test_query_remains_bounded(self, large_audit_log):
        log, entries = large_audit_log

        assert log.query() == entries[-100:]
        assert log.query(limit=5) == entries[-5:]

    def test_query_without_limit_returns_all_entries(self, large_audit_log):
        log, entries = large_audit_log

        results = log.query(limit=None)

        assert results == entries
        results.clear()
        assert log.query(limit=None) == entries

    @pytest.mark.parametrize("export_method", ["export", "export_cloudevents"])
    def test_export_includes_entry_appended_before_snapshot(self, monkeypatch, export_method):
        log = AuditLog()
        entries = [
            log.log("tool_invocation", "did:mesh:test-agent", f"action-{i}")
            for i in range(5)
        ]
        snapshot = log._chain._snapshot

        def append_before_snapshot():
            entries.append(log.log("tool_invocation", "did:mesh:test-agent", "appended"))
            return snapshot()

        monkeypatch.setattr(log._chain, "_snapshot", append_before_snapshot)

        exported = getattr(log, export_method)()

        assert len(entries) == 6
        if export_method == "export":
            assert exported["entry_count"] == len(entries)
            assert exported["entries"] == [entry.model_dump() for entry in entries]
            root = _textbook_merkle_root([entry["entry_hash"] for entry in exported["entries"]])
            assert exported["merkle_root"] == exported["chain_root"] == root
        else:
            assert exported == [entry.to_cloudevent() for entry in entries]
            root = _textbook_merkle_root([event["agentmeshentryhash"] for event in exported])
            assert root == _textbook_merkle_root([entry.entry_hash for entry in entries])
        assert log.verify_integrity() == (True, None)

    @pytest.mark.parametrize("export_method", ["export", "export_cloudevents"])
    def test_export_serializes_snapshot_outside_lock(self, monkeypatch, export_method):
        log = AuditLog()
        entries = [
            log.log("tool_invocation", "did:mesh:test-agent", f"action-{i}")
            for i in range(5)
        ]
        serializer_name = "model_dump" if export_method == "export" else "to_cloudevent"
        serialize = getattr(AuditEntry, serializer_name)
        expected = [serialize(entry) for entry in entries]
        appended = _entry(5)
        calls = 0

        def append_during_serialization(entry):
            nonlocal calls
            calls += 1
            if calls == 1:
                assert log._chain._lock.acquire(blocking=False), "serialization holds the lock"
                log._chain._lock.release()
                log._chain.add_entry(appended)
            return serialize(entry)

        monkeypatch.setattr(AuditEntry, serializer_name, append_during_serialization)

        exported = getattr(log, export_method)()

        assert calls == 5
        assert len(log.query(limit=None)) == 6
        if export_method == "export":
            assert exported["entries"] == expected
            assert exported["entry_count"] == 5
            root = _textbook_merkle_root([entry.entry_hash for entry in entries])
            assert exported["merkle_root"] == exported["chain_root"] == root
        else:
            assert exported == expected

    def test_empty_exports(self):
        log = AuditLog()

        exported = log.export()

        assert exported["entry_count"] == 0
        assert exported["entries"] == []
        assert exported["merkle_root"] is None
        assert exported["chain_root"] is None
        assert log.export_cloudevents() == []
