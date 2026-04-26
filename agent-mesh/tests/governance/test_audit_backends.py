# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for external append-only audit trail backends."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentmesh.governance.audit import AuditEntry, AuditLog
from agentmesh.governance.audit_backends import (
    AuditSink,
    FileAuditSink,
    HashChainVerifier,
    SignedAuditEntry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECRET_KEY = b"test-hmac-secret-key-for-audit"


def _make_entry(**overrides) -> AuditEntry:
    """Create a minimal :class:`AuditEntry` for testing."""
    defaults = {
        "event_type": "tool_invocation",
        "agent_did": "did:web:agent-1",
        "action": "read_file",
    }
    defaults.update(overrides)
    return AuditEntry(**defaults)


# ---------------------------------------------------------------------------
# SignedAuditEntry
# ---------------------------------------------------------------------------


class TestSignedAuditEntry:
    """Tests for cryptographic signing of individual entries."""

    def test_from_entry_produces_non_empty_hashes(self):
        entry = _make_entry()
        signed = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)

        assert signed.content_hash != ""
        assert signed.signature != ""
        assert signed.previous_hash == ""

    def test_content_hash_is_deterministic(self):
        entry = _make_entry(entry_id="fixed-id")
        s1 = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)
        s2 = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)

        assert s1.content_hash == s2.content_hash

    def test_verify_returns_true_for_valid_entry(self):
        entry = _make_entry()
        signed = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)

        assert signed.verify(SECRET_KEY) is True

    def test_verify_returns_false_with_wrong_key(self):
        entry = _make_entry()
        signed = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)

        assert signed.verify(b"wrong-key") is False

    def test_verify_detects_tampered_content(self):
        entry = _make_entry()
        signed = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)

        # Tamper with a field after signing
        signed.action = "TAMPERED"

        assert signed.verify(SECRET_KEY) is False

    def test_hash_chain_links_entries(self):
        e1 = _make_entry(entry_id="entry-1")
        e2 = _make_entry(entry_id="entry-2")

        s1 = SignedAuditEntry.from_entry(e1, previous_hash="", secret_key=SECRET_KEY)
        s2 = SignedAuditEntry.from_entry(
            e2, previous_hash=s1.content_hash, secret_key=SECRET_KEY
        )

        assert s2.previous_hash == s1.content_hash
        assert s2.previous_hash != ""

    def test_to_dict_includes_integrity_fields(self):
        entry = _make_entry()
        signed = SignedAuditEntry.from_entry(entry, previous_hash="abc", secret_key=SECRET_KEY)
        d = signed.to_dict()

        assert "content_hash" in d
        assert "previous_hash" in d
        assert "signature" in d
        assert d["previous_hash"] == "abc"


# ---------------------------------------------------------------------------
# FileAuditSink
# ---------------------------------------------------------------------------


class TestFileAuditSink:
    """Tests for the file-based audit sink."""

    def test_write_creates_file(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)

        sink.write(_make_entry())

        assert path.exists()
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1

    def test_write_appends_multiple_entries(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)

        for i in range(5):
            sink.write(_make_entry(entry_id=f"entry-{i}"))

        lines = path.read_text().strip().splitlines()
        assert len(lines) == 5

    def test_write_batch(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        entries = [_make_entry(entry_id=f"batch-{i}") for i in range(3)]

        sink.write_batch(entries)

        lines = path.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_entries_are_valid_json(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry())

        line = path.read_text().strip()
        data = json.loads(line)
        assert "content_hash" in data
        assert "signature" in data

    def test_verify_integrity_passes_for_valid_file(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)

        for i in range(3):
            sink.write(_make_entry(entry_id=f"e-{i}"))

        is_valid, error = sink.verify_integrity()
        assert is_valid is True
        assert error is None

    def test_verify_integrity_fails_for_tampered_file(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry())

        # Tamper with the file
        content = path.read_text()
        data = json.loads(content.strip())
        data["action"] = "TAMPERED"
        path.write_text(json.dumps(data, sort_keys=True) + "\n")

        is_valid, error = sink.verify_integrity()
        assert is_valid is False
        assert error is not None

    def test_read_entries(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="read-back"))

        entries = sink.read_entries()
        assert len(entries) == 1
        assert entries[0].entry_id == "read-back"

    def test_file_rotation(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        # Use a tiny max_file_size to trigger rotation
        sink = FileAuditSink(path, SECRET_KEY, max_file_size=50)

        sink.write(_make_entry(entry_id="before-rotation"))
        sink.write(_make_entry(entry_id="after-rotation"))

        # Should have rotated — the original path still exists with the latest
        # entry, and a rotated file should exist too.
        rotated_files = list(tmp_path.glob("audit.*.jsonl"))
        assert len(rotated_files) >= 1

    def test_resume_chain_from_existing_file(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink1 = FileAuditSink(path, SECRET_KEY)
        sink1.write(_make_entry(entry_id="first"))
        sink1.close()

        # Open a new sink on the same file — should continue the chain.
        sink2 = FileAuditSink(path, SECRET_KEY)
        sink2.write(_make_entry(entry_id="second"))

        is_valid, error = sink2.verify_integrity()
        assert is_valid is True, f"Integrity check failed: {error}"

    def test_implements_audit_sink_protocol(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)

        assert isinstance(sink, AuditSink)


# ---------------------------------------------------------------------------
# HashChainVerifier
# ---------------------------------------------------------------------------


class TestHashChainVerifier:
    """Tests for the standalone verification tool."""

    def test_verify_valid_file(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        for i in range(5):
            sink.write(_make_entry(entry_id=f"v-{i}"))

        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(path, SECRET_KEY)

        assert is_valid is True
        assert errors == []

    def test_detect_chain_break(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="c-0"))
        sink.write(_make_entry(entry_id="c-1"))

        # Read lines, swap order → chain break
        lines = path.read_text().strip().splitlines()
        path.write_text(lines[1] + "\n" + lines[0] + "\n")

        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(path, SECRET_KEY)

        assert is_valid is False
        assert any("chain break" in e for e in errors)

    def test_detect_tampered_entry(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="t-0"))

        # Tamper with the stored JSON
        data = json.loads(path.read_text().strip())
        data["agent_did"] = "did:web:evil-agent"
        path.write_text(json.dumps(data, sort_keys=True) + "\n")

        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(path, SECRET_KEY)

        assert is_valid is False
        assert len(errors) >= 1

    def test_detect_wrong_secret_key(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry())

        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(path, b"wrong-key")

        assert is_valid is False
        assert any("HMAC" in e or "signature" in e for e in errors)

    def test_nonexistent_file(self, tmp_path: Path):
        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(tmp_path / "nope.jsonl", SECRET_KEY)

        assert is_valid is False
        assert any("does not exist" in e for e in errors)


# ---------------------------------------------------------------------------
# AuditLog + Sink Integration
# ---------------------------------------------------------------------------


class TestAuditLogSinkIntegration:
    """Tests for AuditLog with an external FileAuditSink."""

    def test_audit_log_without_sink_still_works(self):
        log = AuditLog()
        entry = log.log(
            event_type="tool_invocation",
            agent_did="did:web:a",
            action="read",
        )
        assert entry.entry_id is not None
        assert log.get_entry(entry.entry_id) is not None

    def test_audit_log_with_sink_writes_to_file(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        log = AuditLog(sink=sink)

        log.log(
            event_type="tool_invocation",
            agent_did="did:web:a",
            action="read_file",
            resource="/etc/passwd",
        )

        # Entry is in memory
        assert len(log.query()) == 1

        # Entry is also on disk
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1

    def test_audit_log_sink_integrity_after_multiple_logs(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        log = AuditLog(sink=sink)

        for i in range(10):
            log.log(
                event_type="tool_invocation",
                agent_did=f"did:web:agent-{i % 3}",
                action=f"action-{i}",
            )

        is_valid, error = sink.verify_integrity()
        assert is_valid is True, f"Integrity failed: {error}"
