# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for consistent audit reads during chain updates."""

import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from types import ModuleType

import pytest

from agentmesh.governance import audit
from agentmesh.governance.audit import AuditEntry, AuditLog
from agentmesh.governance.trace_sink import (
    TRACEAuditSink,
    TraceConfig,
    session_to_trust_record,
)


def _log(count=5):
    log = AuditLog()
    for i in range(count):
        log._chain.add_entry(AuditEntry(
            timestamp=datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC),
            event_type="tool_invocation" if i % 2 == 0 else "policy_evaluation",
            agent_did="did:mesh:test" if i % 2 == 0 else "did:mesh:other",
            action=f"action-{i}",
            outcome="success" if i % 2 == 0 else "denied",
            session_id="test-session",
        ))
    return log


def _assert_unlocked(chain):
    assert chain._lock.acquire(blocking=False), "callback executed under the chain lock"
    chain._lock.release()


@pytest.mark.parametrize("writer_method", ["append", "rebuild", "failed_append"])
@pytest.mark.parametrize(
    "reader_method", ["query", "filtered_query", "get_entry", "chain_proof", "log_proof", "trace"],
)
def test_reader_waits_for_complete_update(monkeypatch, writer_method, reader_method):
    log = _log()
    chain = log._chain
    pending = AuditEntry(event_type="tool_invocation", agent_did="did:mesh:test", action="new")
    target = chain._entries[-1] if writer_method == "rebuild" else pending
    paused = Event()
    finish = Event()
    reader_started = Event()
    reader_boundary = Event()
    blocked = []
    lock = chain._lock
    node = audit.MerkleNode

    class ObservedLock:
        def __enter__(self):
            acquired = lock.acquire(blocking=False)
            if reader_started.is_set():
                blocked.append(not acquired)
                reader_boundary.set()
            if not acquired:
                lock.acquire()
            return self

        def __exit__(self, *args):
            lock.release()

    def pause_update(**kwargs):
        paused.set()
        assert finish.wait(10), "writer was not released"
        if writer_method == "failed_append":
            raise MemoryError("injected append failure")
        return node(**kwargs)

    def read():
        reader_started.set()
        try:
            if reader_method == "query":
                return log.query()
            if reader_method == "filtered_query":
                return log.query(agent_did="did:mesh:test", limit=None)
            if reader_method == "get_entry":
                return log.get_entry(target.entry_id)
            if reader_method == "chain_proof":
                return chain.get_proof(target.entry_id)
            if reader_method == "log_proof":
                return log.get_proof(target.entry_id)
            return session_to_trust_record("did:mesh:test", log, "policy", TraceConfig("unused"))
        finally:
            reader_boundary.set()

    with monkeypatch.context() as patch:
        patch.setattr(chain, "_lock", ObservedLock())
        patch.setattr(audit, "MerkleNode", pause_update)
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(chain._rebuild_tree) if writer_method == "rebuild" else pool.submit(
                chain.add_entry, pending,
            )
            try:
                assert paused.wait(10), "writer did not reach the hook"
                reader = pool.submit(read)
                assert reader_boundary.wait(10), "reader neither locked nor returned"
                assert blocked == [True]
                assert not reader.done()
            finally:
                finish.set()
            if writer_method == "failed_append":
                with pytest.raises(MemoryError, match="injected append failure"):
                    writer.result(timeout=10)
            else:
                writer.result(timeout=10)
            result = reader.result(timeout=10)

    entries, root = chain._snapshot()
    assert len(entries) == (6 if writer_method == "append" else 5)
    if reader_method == "query":
        assert result == entries
    elif reader_method == "filtered_query":
        assert result == [entry for entry in entries if entry.agent_did == "did:mesh:test"]
    elif reader_method == "get_entry":
        assert result is (None if writer_method == "failed_append" else target)
    elif reader_method in ("chain_proof", "log_proof"):
        if writer_method == "failed_append":
            assert result is None
        elif reader_method == "chain_proof":
            assert chain.verify_proof(target.entry_hash, result, root)
        else:
            assert result["merkle_root"] == root
            assert result["verified"] is True
            assert chain.verify_proof(target.entry_hash, result["merkle_proof"], root)
    else:
        assert result["tool_transcript"]["call_count"] == len(entries)
        assert result["runtime"]["measurement"] == "sha256:" + hashlib.sha256(root.encode()).hexdigest()
        canonical = json.dumps(
            [entry.model_dump(mode="json") for entry in entries],
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode()
        assert result["tool_transcript"]["hash"] == "sha256:" + hashlib.sha256(canonical).hexdigest()
        assert result["iat"] == int(entries[-1].timestamp.timestamp())


def test_proof_uses_one_root_when_append_follows_lock_release(monkeypatch):
    log = _log()
    chain = log._chain
    entry = chain._entries[0]
    root = chain.get_root_hash()
    lock = chain._lock
    calls = 0

    class AppendAfterRead:
        def __enter__(self):
            lock.acquire()
            return self

        def __exit__(self, *args):
            nonlocal calls
            lock.release()
            if calls == 0:
                calls += 1
                log.log("test", "did:mesh:test", "append-after-read")

    monkeypatch.setattr(chain, "_lock", AppendAfterRead())
    result = log.get_proof(entry.entry_id)

    assert calls == 1
    assert len(chain._entries) == 6
    assert result["merkle_root"] == root
    assert result["verified"] is True
    assert chain.verify_proof(entry.entry_hash, result["merkle_proof"], root)


def test_proof_serialization_and_verification_are_outside_lock(monkeypatch):
    log = _log()
    chain = log._chain
    entry = chain._entries[0]
    root = chain.get_root_hash()
    serialize = AuditEntry.model_dump
    verify = chain.verify_proof
    calls = []

    def serialize_and_append(item, *args, **kwargs):
        _assert_unlocked(chain)
        calls.append("serialize")
        log.log("test", "did:mesh:test", "during-serialization")
        return serialize(item, *args, **kwargs)

    def verify_and_append(*args):
        _assert_unlocked(chain)
        calls.append("verify")
        log.log("test", "did:mesh:test", "during-verification")
        return verify(*args)

    monkeypatch.setattr(AuditEntry, "model_dump", serialize_and_append)
    monkeypatch.setattr(chain, "verify_proof", verify_and_append)
    result = log.get_proof(entry.entry_id)

    assert calls == ["serialize", "verify"]
    assert len(chain._entries) == 7
    assert result["merkle_root"] == root
    assert result["verified"] is True
    assert verify(entry.entry_hash, result["merkle_proof"], root)


@pytest.mark.parametrize("limit", [None, 0, 1, 3, 100, -1])
def test_query_preserves_limits_order_and_filters(limit):
    log = _log(6)
    entries = list(log._chain._entries)
    bounds = {"start_time": entries[2].timestamp, "end_time": entries[4].timestamp}
    cases = [
        ({}, entries),
        ({"agent_did": "did:mesh:test"}, entries[::2]),
        ({"event_type": "policy_evaluation"}, entries[1::2]),
        ({"outcome": "denied"}, entries[1::2]),
        (bounds, entries[2:5]),
        ({**bounds, "agent_did": "did:mesh:test", "event_type": "tool_invocation",
          "outcome": "success"}, [entries[2], entries[4]]),
    ]
    for filters, matching in cases:
        expected = matching if limit is None else matching[-limit:]
        result = log.query(limit=limit, **filters)
        assert isinstance(result, list)
        assert result == expected
        result.clear()
        assert log._chain._entries == entries


def test_query_filter_callbacks_run_on_snapshot_outside_lock():
    log = _log()
    expected = list(log._chain._entries[::2])
    calls = 0

    class AppendOnComparison(str):
        def __eq__(self, other):
            nonlocal calls
            _assert_unlocked(log._chain)
            if calls == 0:
                calls += 1
                log.log("tool_invocation", "did:mesh:test", "during-filter")
            return super().__eq__(other)

    result = log.query(event_type=AppendOnComparison("tool_invocation"), limit=None)

    assert calls == 1
    assert len(log._chain._entries) == 6
    assert result == expected


def test_bounded_query_does_not_copy_entire_chain():
    log = _log()

    class SliceOnlyEntries(list):
        def __iter__(self):
            pytest.fail("unfiltered bounded query copied the full chain")

    log._chain._entries = SliceOnlyEntries(log._chain._entries)
    assert log.query(limit=2) == log._chain._entries[-2:]


def test_missing_and_single_entry_behavior_is_unchanged():
    log = _log(0)
    assert log.query() == []
    assert log.get_entry("missing") is None
    assert log.get_proof("missing") is None
    assert log._chain.get_proof("missing") is None
    entry = log.log("test", "did:mesh:test", "first")
    assert log.get_entry(entry.entry_id) is entry
    assert log._chain.get_proof(entry.entry_id) == []
    assert log.get_proof(entry.entry_id) is None


def test_trace_keeps_snapshot_when_append_follows_transcript_serialization(monkeypatch):
    log = _log()
    entries, root = log._chain._snapshot()
    dumps = json.dumps
    canonical = dumps(
        [entry.model_dump(mode="json") for entry in entries],
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode()
    calls = 0

    def serialize_then_append(value, *args, **kwargs):
        nonlocal calls
        result = dumps(value, *args, **kwargs)
        if isinstance(value, list) and calls == 0:
            _assert_unlocked(log._chain)
            calls += 1
            log.log("test", "did:mesh:test", "after-transcript")
        return result

    monkeypatch.setattr(json, "dumps", serialize_then_append)
    record = session_to_trust_record("did:mesh:test", log, "policy", TraceConfig("unused"))

    assert calls == 1
    assert len(log._chain._entries) == 6
    assert record["tool_transcript"] == {
        "hash": "sha256:" + hashlib.sha256(canonical).hexdigest(), "call_count": 5,
    }
    assert record["runtime"]["measurement"] == "sha256:" + hashlib.sha256(root.encode()).hexdigest()


@pytest.mark.parametrize("emitter", [False, True])
def test_trace_uses_one_snapshot_and_runs_callbacks_outside_lock(monkeypatch, tmp_path, emitter):
    log = _log()
    entries, root = log._chain._snapshot()
    canonical = json.dumps(
        [entry.model_dump(mode="json") for entry in entries],
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode()
    expected_transcript = "sha256:" + hashlib.sha256(canonical).hexdigest()
    expected_measurement = "sha256:" + hashlib.sha256(root.encode()).hexdigest()
    config = TraceConfig(str(tmp_path) + "/")
    serialize = AuditEntry.model_dump
    snapshot = log._chain._snapshot
    write = Path.write_text
    calls = []

    def capture():
        calls.append("snapshot")
        return snapshot()

    def serialize_and_append(entry, *args, **kwargs):
        _assert_unlocked(log._chain)
        if "serialize" not in calls:
            calls.append("serialize")
            log.log("test", "did:mesh:test", "during-serialization")
        return serialize(entry, *args, **kwargs)

    def load_key():
        _assert_unlocked(log._chain)
        calls.append("key")
        log.log("test", "did:mesh:test", "during-key-loading")
        return object()

    def sign(record, key):
        _assert_unlocked(log._chain)
        calls.append("sign")
        return record

    class TrustRecord:
        @staticmethod
        def model_validate(record):
            _assert_unlocked(log._chain)
            calls.append("validate")

    def write_unlocked(path, *args, **kwargs):
        _assert_unlocked(log._chain)
        calls.append("write")
        return write(path, *args, **kwargs)

    trace = ModuleType("agentrust_trace")
    trace.load_signing_key = load_key
    trace.sign_record = sign
    trace.TrustRecord = TrustRecord
    monkeypatch.setitem(sys.modules, "agentrust_trace", trace)
    monkeypatch.setattr(log._chain, "_snapshot", capture)
    monkeypatch.setattr(AuditEntry, "model_dump", serialize_and_append)
    monkeypatch.setattr(Path, "write_text", write_unlocked)

    if emitter:
        path = TRACEAuditSink(config, "did:mesh:test", "policy").emit(log)
        assert Path(path).name == f"trace-{int(entries[-1].timestamp.timestamp())}-test-session.json"
        record = json.loads(Path(path).read_text())
    else:
        record = session_to_trust_record("did:mesh:test", log, "policy", config)

    assert record["iat"] == int(entries[-1].timestamp.timestamp())
    assert record["tool_transcript"] == {"hash": expected_transcript, "call_count": 5}
    assert record["runtime"]["measurement"] == expected_measurement
    assert record["build_provenance"]["digest"] == expected_measurement
    assert len(log._chain._entries) == (7 if emitter else 6)
    assert calls == (["snapshot", "serialize", "key", "sign", "validate", "write"]
                     if emitter else ["snapshot", "serialize"])
