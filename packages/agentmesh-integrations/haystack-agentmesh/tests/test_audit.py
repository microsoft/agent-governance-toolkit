"""Tests for AuditLogger component."""

import json
import os
import tempfile

import pytest

from haystack_agentmesh.audit import AuditLogger, _hash_entry


class TestAuditLogger:

    def test_run_returns_entry_id_and_hash(self):
        logger = AuditLogger()
        result = logger.run(action="search", agent_id="a1", decision="allow")
        assert "entry_id" in result
        assert "chain_hash" in result
        assert len(result["chain_hash"]) == 64  # SHA-256 hex

    def test_entries_accumulate(self):
        logger = AuditLogger()
        logger.run(action="search", agent_id="a1", decision="allow")
        logger.run(action="delete", agent_id="a2", decision="deny")
        assert len(logger.entries) == 2

    def test_chain_integrity(self):
        logger = AuditLogger()
        for i in range(5):
            logger.run(action=f"action-{i}", agent_id="a1", decision="allow")
        assert logger.verify_chain() is True

    def test_tampered_entry_breaks_chain(self):
        logger = AuditLogger()
        logger.run(action="a", agent_id="a1", decision="allow")
        logger.run(action="b", agent_id="a1", decision="deny")
        # Tamper with first entry
        logger._entries[0].action = "tampered"
        assert logger.verify_chain() is False

    def test_prev_hash_links(self):
        logger = AuditLogger()
        r1 = logger.run(action="x", agent_id="a1", decision="allow")
        r2 = logger.run(action="y", agent_id="a1", decision="allow")
        assert logger._entries[0].prev_hash == "genesis"
        assert logger._entries[1].prev_hash == r1["chain_hash"]

    def test_metadata_stored(self):
        logger = AuditLogger()
        meta = {"source": "test", "priority": 1}
        logger.run(action="z", agent_id="a1", decision="audit", metadata=meta)
        assert logger.entries[0].metadata == meta

    def test_export_jsonl(self):
        logger = AuditLogger()
        logger.run(action="a", agent_id="a1", decision="allow")
        logger.run(action="b", agent_id="a2", decision="deny")
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            count = logger.export_jsonl(path)
            assert count == 2
            with open(path) as fh:
                lines = fh.readlines()
            assert len(lines) == 2
            record = json.loads(lines[0])
            assert record["action"] == "a"
        finally:
            os.unlink(path)

    def test_to_jsonl_string(self):
        logger = AuditLogger()
        logger.run(action="a", agent_id="a1", decision="allow")
        output = logger.to_jsonl_string()
        record = json.loads(output.strip())
        assert record["agent_id"] == "a1"

    def test_empty_chain_verifies(self):
        logger = AuditLogger()
        assert logger.verify_chain() is True

    def test_hash_deterministic(self):
        logger = AuditLogger()
        r1 = logger.run(action="x", agent_id="a1", decision="allow")
        entry = logger.entries[0]
        assert _hash_entry(entry) == r1["chain_hash"]
