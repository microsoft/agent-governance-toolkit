# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import hashlib
import json
import tempfile
from pathlib import Path

import pytest
from agent_rag_governance.audit import AuditLogger, RAGAuditEntry, make_entry


def test_query_hash_is_sha256():
    query = "what is the refund policy?"
    expected = hashlib.sha256(query.encode("utf-8")).hexdigest()
    assert RAGAuditEntry.hash_query(query) == expected


def test_query_hash_not_raw_query():
    query = "sensitive search term"
    entry = make_entry(
        agent_id="agent-1",
        collection="public_docs",
        query=query,
        num_chunks_retrieved=5,
        num_chunks_blocked=0,
        decision="allowed",
    )
    data = json.loads(entry.to_json())
    assert query not in json.dumps(data)
    assert data["query_hash"] == RAGAuditEntry.hash_query(query)


def test_entry_serializes_to_valid_json():
    entry = make_entry(
        agent_id="agent-1",
        collection="public_docs",
        query="test query",
        num_chunks_retrieved=3,
        num_chunks_blocked=1,
        decision="allowed",
        policy_triggered=None,
    )
    data = json.loads(entry.to_json())
    assert data["agent_id"] == "agent-1"
    assert data["collection"] == "public_docs"
    assert data["num_chunks_retrieved"] == 3
    assert data["num_chunks_blocked"] == 1
    assert data["decision"] == "allowed"
    assert data["policy_triggered"] is None


def test_audit_logger_writes_to_file():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = f.name

    logger = AuditLogger(log_path=log_path)
    entry = make_entry(
        agent_id="agent-1",
        collection="docs",
        query="hello",
        num_chunks_retrieved=2,
        num_chunks_blocked=0,
        decision="allowed",
    )
    logger.emit(entry)

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["agent_id"] == "agent-1"


def test_audit_logger_appends_multiple_entries():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = f.name

    logger = AuditLogger(log_path=log_path)
    for i in range(3):
        entry = make_entry(
            agent_id=f"agent-{i}",
            collection="docs",
            query="test",
            num_chunks_retrieved=1,
            num_chunks_blocked=0,
            decision="allowed",
        )
        logger.emit(entry)

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == 3


def test_audit_logger_concurrent_emits_are_well_formed():
    """Concurrent emit() calls from multiple threads must not interleave.

    Spawn N threads writing M entries each; assert every output line is
    valid JSON and the total line count matches the emit count. Without
    the in-process lock this assertion is flaky/failing — Linux's
    O_APPEND only guarantees atomic appends below PIPE_BUF, and a
    moderately-sized JSON line under thread contention can corrupt.
    """
    import threading

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = f.name

    logger = AuditLogger(log_path=log_path)
    n_threads = 8
    entries_per_thread = 50
    # Build a payload large enough to exceed any single-syscall atomicity
    # window the kernel might offer for short writes — a long fake query
    # produces a line of ~600+ bytes after JSON encoding.
    long_query = "x" * 512
    barrier = threading.Barrier(n_threads)

    def worker(worker_id: int) -> None:
        barrier.wait()  # release all threads at once
        for i in range(entries_per_thread):
            entry = make_entry(
                agent_id=f"agent-{worker_id}",
                collection="docs",
                query=f"{long_query}-{worker_id}-{i}",
                num_chunks_retrieved=1,
                num_chunks_blocked=0,
                decision="allowed",
            )
            logger.emit(entry)

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    raw = Path(log_path).read_text()
    lines = raw.strip().splitlines()

    # Every line independently parses as JSON.
    parsed = [json.loads(line) for line in lines]
    # No partial / interleaved / lost lines.
    assert len(parsed) == n_threads * entries_per_thread
    # And every entry is a fully-formed RAGAuditEntry shape.
    for record in parsed:
        assert "agent_id" in record
        assert "collection" in record
        assert "query_hash" in record
        assert "decision" in record
