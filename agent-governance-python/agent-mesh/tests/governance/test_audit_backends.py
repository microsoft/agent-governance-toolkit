# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for external append-only audit trail backends."""

from __future__ import annotations

import json
import os
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

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
    def test_write_tightens_permissions_on_a_pre_existing_file(self, tmp_path: Path):
        """os.open(..., O_CREAT, 0o600)'s mode only applies if the call
        creates the file; one that already exists at a looser mode (e.g.
        world-readable) used to keep it, silently, for every subsequent
        write of an entry that can carry call arguments."""
        path = tmp_path / "audit.jsonl"
        path.touch()
        path.chmod(0o644)

        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry())

        assert (path.stat().st_mode & 0o777) == 0o600

    @pytest.mark.skipif(not hasattr(os, "fchmod"), reason="fchmod is POSIX-only")
    def test_fchmod_failure_does_not_leak_the_descriptor(self, tmp_path: Path, monkeypatch):
        """fchmod runs inside the fdopen block, on the file object's own
        descriptor, specifically so a failing fchmod (e.g. EPERM: the file
        is owned by another user) still closes it via the same path a
        failing write would - not after os.open but before fdopen, where
        an exception would skip the close entirely."""
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)

        captured_fd = {}
        real_open = os.open

        def spy_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            captured_fd["fd"] = fd
            return fd

        monkeypatch.setattr(os, "open", spy_open)
        monkeypatch.setattr(
            os, "fchmod",
            lambda fd, mode: (_ for _ in ()).throw(PermissionError("EPERM")),
        )

        with pytest.raises(PermissionError):
            sink.write(_make_entry())

        # A bad-descriptor error on fstat is proof the descriptor was
        # actually closed; a leak would instead succeed.
        with pytest.raises(OSError):
            os.fstat(captured_fd["fd"])

    def test_corrupted_middle_line_does_not_break_resume_or_reads(self, tmp_path: Path):
        """A single trailing corrupt line was already tolerated; a
        corrupt line followed by a resumed write (e.g. crash mid-append,
        then process restart) used to leave verify_integrity()/
        read_entries() permanently broken from that point on."""
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="first"))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"not": "valid json"\n')  # simulates a crash mid-write
        sink.close()

        sink2 = FileAuditSink(path, SECRET_KEY)
        sink2.write(_make_entry(entry_id="second"))

        entries = sink2.read_entries()
        assert [e.entry_id for e in entries] == ["first", "second"]

        is_valid, error = sink2.verify_integrity()
        assert is_valid is True, f"Integrity check failed: {error}"


class TestFileAuditSinkConstructionValidation:
    """A bad path used to construct fine and fail lazily on the first
    write() (FileNotFoundError / IsADirectoryError / ELOOP for a symlink) -
    now checked eagerly, at construction, like the secret key already is."""

    def test_path_is_a_directory_raises(self, tmp_path: Path):
        with pytest.raises(IsADirectoryError):
            FileAuditSink(tmp_path, SECRET_KEY)

    def test_parent_directory_missing_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            FileAuditSink(tmp_path / "no-such-dir" / "audit.jsonl", SECRET_KEY)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks only")
    def test_path_is_a_symlink_raises(self, tmp_path: Path):
        target = tmp_path / "real.jsonl"
        target.write_text("")
        link = tmp_path / "audit.jsonl"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="symlink"):
            FileAuditSink(link, SECRET_KEY)

    def test_existing_file_signed_with_a_different_key_raises(self, tmp_path: Path):
        """Opening a sink on a file that already has entries - just not
        ones this key can verify - must fail at construction, not go on
        to silently extend that chain as if it were this sink's own."""
        path = tmp_path / "audit.jsonl"
        FileAuditSink(path, b"a-completely-different-key-32by").write(_make_entry())

        with pytest.raises(ValueError, match="does not verify"):
            FileAuditSink(path, SECRET_KEY)


class TestFileAuditSinkExternalRotation:
    """logrotate-style external rotation (rename the file away, a fresh one
    appears at the same path) used to leave a long-lived sink's in-memory
    previous_hash pointing at a chain that no longer exists at that path -
    verify_integrity() on the replacement file then broke at entry 0."""

    def test_write_after_external_rename_starts_a_fresh_chain(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="before-rotation"))

        # Simulate an external log rotator: move the file away, nothing
        # left at `path` until the sink's next write recreates it.
        (path).rename(tmp_path / "audit.jsonl.1")

        sink.write(_make_entry(entry_id="after-rotation"))

        is_valid, error = sink.verify_integrity()
        assert is_valid is True, f"Integrity check failed: {error}"
        assert len(sink.read_entries()) == 1

    def test_write_after_external_replace_with_same_key_resyncs(self, tmp_path: Path):
        """Replacement by a *different* sink/process using the *same* key
        (not just a rename-away) is a legitimate resync: the file at
        `path` changes identity even though a file exists there the
        whole time, but the chain is still authentically ours."""
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="original"))

        other = FileAuditSink(tmp_path / "other.jsonl", SECRET_KEY)
        other.write(_make_entry(entry_id="unrelated"))
        (tmp_path / "other.jsonl").replace(path)

        sink.write(_make_entry(entry_id="after-replace"))

        entries = sink.read_entries()
        assert len(entries) == 2
        assert entries[0].entry_id == "unrelated"
        assert entries[1].entry_id == "after-replace"

    def test_write_after_external_replace_with_different_key_fails_closed(
        self, tmp_path: Path
    ):
        """A file swapped in under a *different* key must not be silently
        extended as if it were this sink's own chain - see the docstring
        on FileAuditSink._read_last_hash."""
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="original"))

        other_key = b"a-completely-different-key-32by"
        other = FileAuditSink(tmp_path / "other.jsonl", other_key)
        other.write(_make_entry(entry_id="unrelated"))
        (tmp_path / "other.jsonl").replace(path)

        with pytest.raises(ValueError, match="does not verify"):
            sink.write(_make_entry(entry_id="after-replace"))


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

    def test_skips_unparsable_line_instead_of_failing_the_whole_file(self, tmp_path: Path):
        """A corrupt line does not, on its own, make the surrounding
        genuine entries unverifiable - only a real chain break or bad
        signature among what parses should."""
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry(entry_id="before"))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("not json at all\n")
        sink.write(_make_entry(entry_id="after"))

        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(path, SECRET_KEY)

        assert is_valid is True, errors


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
