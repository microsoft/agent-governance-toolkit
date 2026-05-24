# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for StdoutAuditSink and AuditEntry execution-context enrichment."""

from __future__ import annotations

import io
import json
import threading
from pathlib import Path
from unittest.mock import patch

from agentmesh.governance.audit import AuditEntry, AuditLog
from agentmesh.governance.audit_backends import (
    AuditSink,
    FileAuditSink,
    HashChainVerifier,
    SignedAuditEntry,
    StdoutAuditSink,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECRET_KEY = b"test-hmac-secret-key-for-stdout-tests"


def _make_entry(**overrides) -> AuditEntry:
    """Create a minimal :class:`AuditEntry` for testing."""
    defaults: dict = {
        "event_type": "tool_invocation",
        "agent_did": "did:web:agent-stdout-test",
        "action": "read_file",
    }
    defaults.update(overrides)
    return AuditEntry(**defaults)


def _capture_stdout(sink: StdoutAuditSink, fn) -> list[dict]:
    """Run *fn(sink)*, capture stdout output, and return parsed JSONL records."""
    buf = io.StringIO()
    with patch("sys.stdout", buf):
        fn(sink)
    output = buf.getvalue()
    records = []
    for line in output.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# StdoutAuditSink — JSONL correctness
# ---------------------------------------------------------------------------


class TestStdoutAuditSinkJsonl:
    """Verify JSONL output format and per-line correctness."""

    def test_write_single_entry_produces_one_line(self):
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            sink.write(_make_entry())
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 1

    def test_write_single_entry_is_valid_json(self):
        sink = StdoutAuditSink()
        records = _capture_stdout(sink, lambda s: s.write(_make_entry()))
        assert len(records) == 1
        assert isinstance(records[0], dict)

    def test_write_multiple_entries_each_on_own_line(self):
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            for i in range(5):
                sink.write(_make_entry(entry_id=f"e-{i}"))
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 5

    def test_output_lines_contain_required_fields(self):
        sink = StdoutAuditSink()
        records = _capture_stdout(sink, lambda s: s.write(_make_entry()))
        rec = records[0]
        assert "event_type" in rec
        assert "agent_did" in rec
        assert "action" in rec
        assert "entry_id" in rec
        assert "timestamp" in rec
        assert "outcome" in rec

    def test_output_timestamp_is_iso_string(self):
        sink = StdoutAuditSink()
        records = _capture_stdout(sink, lambda s: s.write(_make_entry()))
        ts = records[0]["timestamp"]
        # Must be a string, parseable as ISO-8601
        assert isinstance(ts, str)
        from datetime import datetime
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert parsed is not None

    def test_output_is_compact_not_pretty_printed(self):
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            sink.write(_make_entry())
        line = buf.getvalue().strip()
        # No leading whitespace inside the JSON body (no indentation)
        assert "\n" not in line

    def test_output_keys_are_sorted(self):
        """Keys must be in sorted order for stable machine-readable output."""
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            sink.write(_make_entry())
        line = buf.getvalue().strip()
        parsed = json.loads(line)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_unicode_payload_preserved_verbatim(self):
        """Non-ASCII characters must not be escaped to \\uXXXX sequences."""
        entry = _make_entry(
            action="read_文件",
            data={"message": "café résumé 日本語", "emoji": "🔒"},
        )
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            sink.write(entry)
        raw_line = buf.getvalue().strip()
        # The raw bytes must contain the literal characters, not \u escapes.
        assert "文件" in raw_line
        assert "café" in raw_line
        assert "🔒" in raw_line
        # Also confirm round-trip correctness.
        rec = json.loads(raw_line)
        assert rec["action"] == "read_文件"
        assert rec["data"]["message"] == "café résumé 日本語"
        assert rec["data"]["emoji"] == "🔒"


# ---------------------------------------------------------------------------
# StdoutAuditSink — flush behaviour
# ---------------------------------------------------------------------------


class TestStdoutAuditSinkFlush:
    """Verify that writes are flushed immediately for container log drivers."""

    def test_write_calls_flush(self):
        sink = StdoutAuditSink()
        mock_stdout = io.StringIO()
        flush_called = []
        original_flush = mock_stdout.flush

        def tracking_flush():
            flush_called.append(True)
            original_flush()

        mock_stdout.flush = tracking_flush  # type: ignore[method-assign]
        with patch("sys.stdout", mock_stdout):
            sink.write(_make_entry())
        assert flush_called, "flush() must be called after write()"

    def test_write_batch_calls_flush_once(self):
        sink = StdoutAuditSink()
        mock_stdout = io.StringIO()
        flush_calls: list[bool] = []
        original_flush = mock_stdout.flush

        def tracking_flush():
            flush_calls.append(True)
            original_flush()

        mock_stdout.flush = tracking_flush  # type: ignore[method-assign]
        entries = [_make_entry(entry_id=f"b-{i}") for i in range(4)]
        with patch("sys.stdout", mock_stdout):
            sink.write_batch(entries)
        # Should flush once per batch, not once per entry
        assert len(flush_calls) == 1

    def test_close_flushes_stdout(self):
        sink = StdoutAuditSink()
        mock_stdout = io.StringIO()
        flush_called = []
        original_flush = mock_stdout.flush

        def tracking_flush():
            flush_called.append(True)
            original_flush()

        mock_stdout.flush = tracking_flush  # type: ignore[method-assign]
        with patch("sys.stdout", mock_stdout):
            sink.close()
        assert flush_called


# ---------------------------------------------------------------------------
# StdoutAuditSink — write_batch
# ---------------------------------------------------------------------------


class TestStdoutAuditSinkWriteBatch:
    """Verify write_batch semantics."""

    def test_write_batch_produces_correct_line_count(self):
        sink = StdoutAuditSink()
        entries = [_make_entry(entry_id=f"batch-{i}") for i in range(7)]
        records = _capture_stdout(sink, lambda s: s.write_batch(entries))
        assert len(records) == 7

    def test_write_batch_records_are_valid_json(self):
        sink = StdoutAuditSink()
        entries = [_make_entry(entry_id=f"bv-{i}") for i in range(3)]
        records = _capture_stdout(sink, lambda s: s.write_batch(entries))
        for rec in records:
            assert isinstance(rec, dict)
            assert "entry_id" in rec

    def test_write_batch_empty_list_writes_nothing(self):
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            sink.write_batch([])
        assert buf.getvalue() == ""

    def test_write_batch_preserves_entry_order(self):
        sink = StdoutAuditSink()
        ids = [f"ordered-{i}" for i in range(5)]
        entries = [_make_entry(entry_id=eid) for eid in ids]
        records = _capture_stdout(sink, lambda s: s.write_batch(entries))
        assert [r["entry_id"] for r in records] == ids


# ---------------------------------------------------------------------------
# StdoutAuditSink — protocol compliance
# ---------------------------------------------------------------------------


class TestStdoutAuditSinkProtocol:
    """Verify StdoutAuditSink implements the AuditSink protocol."""

    def test_implements_audit_sink_protocol(self):
        sink = StdoutAuditSink()
        assert isinstance(sink, AuditSink)

    def test_verify_integrity_returns_true_none(self):
        sink = StdoutAuditSink()
        ok, err = sink.verify_integrity()
        assert ok is True
        assert err is None

    def test_close_does_not_raise(self):
        sink = StdoutAuditSink()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            sink.close()  # must not raise


# ---------------------------------------------------------------------------
# StdoutAuditSink — thread safety
# ---------------------------------------------------------------------------


class TestStdoutAuditSinkThreadSafety:
    """Verify concurrent writes produce one valid JSONL record per entry.

    StdoutAuditSink uses a class-level lock so that separate instances
    cannot interleave their writes on the process-global stdout.
    """

    def test_concurrent_writes_produce_correct_line_count(self):
        sink = StdoutAuditSink()
        buf = io.StringIO()
        n = 50

        def _write(i: int) -> None:
            sink.write(_make_entry(entry_id=f"thread-{i}"))

        with patch("sys.stdout", buf):
            threads = [threading.Thread(target=_write, args=(i,)) for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        assert len(lines) == n
        # Every line must be valid JSON
        for line in lines:
            json.loads(line)

    def test_lock_is_shared_across_instances(self):
        """All StdoutAuditSink instances must share the same lock object."""
        sink_a = StdoutAuditSink()
        sink_b = StdoutAuditSink()
        assert sink_a._stdout_lock is sink_b._stdout_lock

    def test_concurrent_writes_from_two_instances_produce_correct_line_count(self):
        """Two separate sink instances writing concurrently must not corrupt JSONL."""
        sink_a = StdoutAuditSink()
        sink_b = StdoutAuditSink()
        buf = io.StringIO()
        n = 25

        def _write_a(i: int) -> None:
            sink_a.write(_make_entry(entry_id=f"inst-a-{i}"))

        def _write_b(i: int) -> None:
            sink_b.write(_make_entry(entry_id=f"inst-b-{i}"))

        with patch("sys.stdout", buf):
            threads = (
                [threading.Thread(target=_write_a, args=(i,)) for i in range(n)]
                + [threading.Thread(target=_write_b, args=(i,)) for i in range(n)]
            )
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        assert len(lines) == n * 2
        for line in lines:
            json.loads(line)


# ---------------------------------------------------------------------------
# AuditEntry — optional execution-context fields
# ---------------------------------------------------------------------------


class TestAuditEntryContextFields:
    """Verify new optional fields on AuditEntry."""

    def test_default_values_are_none(self):
        entry = _make_entry()
        assert entry.sandbox_id is None
        assert entry.environment is None
        assert entry.compute_driver is None

    def test_fields_can_be_set_explicitly(self):
        entry = _make_entry(
            sandbox_id="sb-123",
            environment="production",
            compute_driver="docker",
        )
        assert entry.sandbox_id == "sb-123"
        assert entry.environment == "production"
        assert entry.compute_driver == "docker"

    def test_context_fields_do_not_affect_hash(self):
        """Hash must remain stable when context fields differ."""
        base = _make_entry(entry_id="hash-test")
        with_ctx = _make_entry(
            entry_id="hash-test",
            sandbox_id="sb-999",
            environment="staging",
            compute_driver="k8s",
        )
        # Freeze timestamps so only the context differs
        base.timestamp = with_ctx.timestamp
        assert base.compute_hash() == with_ctx.compute_hash()

    def test_context_fields_serialised_in_model_dump(self):
        entry = _make_entry(sandbox_id="sb-x", environment="test", compute_driver="vm")
        d = entry.model_dump(mode="json")
        assert d["sandbox_id"] == "sb-x"
        assert d["environment"] == "test"
        assert d["compute_driver"] == "vm"

    def test_stdout_sink_includes_context_fields_in_output(self):
        entry = _make_entry(
            sandbox_id="sb-out",
            environment="staging",
            compute_driver="containerd",
        )
        sink = StdoutAuditSink()
        records = _capture_stdout(sink, lambda s: s.write(entry))
        rec = records[0]
        assert rec["sandbox_id"] == "sb-out"
        assert rec["environment"] == "staging"
        assert rec["compute_driver"] == "containerd"

    def test_missing_context_fields_omitted_from_stdout(self):
        entry = _make_entry()
        sink = StdoutAuditSink()
        records = _capture_stdout(sink, lambda s: s.write(entry))
        rec = records[0]
        assert "sandbox_id" not in rec
        assert "environment" not in rec
        assert "compute_driver" not in rec


# ---------------------------------------------------------------------------
# SignedAuditEntry — context fields propagation
# ---------------------------------------------------------------------------


class TestSignedAuditEntryContextFields:
    """Context fields must be stored in SignedAuditEntry but excluded from hash."""

    def test_from_entry_propagates_context_fields(self):
        entry = _make_entry(
            sandbox_id="sb-signed",
            environment="prod",
            compute_driver="firecracker",
        )
        signed = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)
        assert signed.sandbox_id == "sb-signed"
        assert signed.environment == "prod"
        assert signed.compute_driver == "firecracker"

    def test_context_fields_excluded_from_canonical_payload(self):
        """Hash must be identical regardless of context field values."""
        e1 = _make_entry(entry_id="same-id", sandbox_id="sb-a", environment="prod")
        e2 = _make_entry(entry_id="same-id", sandbox_id="sb-b", environment="dev")
        e1.timestamp = e2.timestamp  # normalise timestamps

        s1 = SignedAuditEntry.from_entry(e1, previous_hash="", secret_key=SECRET_KEY)
        s2 = SignedAuditEntry.from_entry(e2, previous_hash="", secret_key=SECRET_KEY)
        assert s1.content_hash == s2.content_hash

    def test_verify_still_passes_with_context_fields(self):
        entry = _make_entry(sandbox_id="sb-verify", environment="ci")
        signed = SignedAuditEntry.from_entry(entry, previous_hash="", secret_key=SECRET_KEY)
        assert signed.verify(SECRET_KEY) is True

    def test_file_sink_stores_context_fields(self, tmp_path: Path):
        path = tmp_path / "ctx_audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        entry = _make_entry(sandbox_id="sb-file", environment="prod", compute_driver="crun")
        sink.write(entry)

        entries = sink.read_entries()
        assert len(entries) == 1
        stored = entries[0]
        assert stored.sandbox_id == "sb-file"
        assert stored.environment == "prod"
        assert stored.compute_driver == "crun"

    def test_file_sink_integrity_unaffected_by_context_fields(self, tmp_path: Path):
        path = tmp_path / "ctx_integrity.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        for i in range(3):
            sink.write(
                _make_entry(
                    entry_id=f"ci-{i}",
                    sandbox_id=f"sb-{i}",
                    environment="test",
                )
            )
        is_valid, error = sink.verify_integrity()
        assert is_valid is True, f"Integrity check failed: {error}"


# ---------------------------------------------------------------------------
# AuditLog — environment auto-detection
# ---------------------------------------------------------------------------


class TestAuditLogEnvAutoDetection:
    """Verify AuditLog reads environment context once at init."""

    def test_sandbox_id_from_sandbox_id_var(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_ID", "sb-primary")
        monkeypatch.delenv("OPENSHELL_SANDBOX_ID", raising=False)
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.sandbox_id == "sb-primary"

    def test_sandbox_id_from_openshell_var(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_ID", raising=False)
        monkeypatch.setenv("OPENSHELL_SANDBOX_ID", "sb-openshell")
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.sandbox_id == "sb-openshell"

    def test_sandbox_id_openshell_wins_over_bare(self, monkeypatch):
        monkeypatch.setenv("OPENSHELL_SANDBOX_ID", "sb-wins")
        monkeypatch.setenv("SANDBOX_ID", "sb-loses")
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.sandbox_id == "sb-wins"

    def test_environment_from_agt_environment(self, monkeypatch):
        monkeypatch.setenv("AGT_ENVIRONMENT", "production")
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.environment == "production"

    def test_compute_driver_from_openshell_compute_driver(self, monkeypatch):
        monkeypatch.setenv("OPENSHELL_COMPUTE_DRIVER", "gvisor")
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.compute_driver == "gvisor"

    def test_all_fields_auto_populated(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_ID", "sb-all")
        monkeypatch.setenv("AGT_ENVIRONMENT", "staging")
        monkeypatch.setenv("OPENSHELL_COMPUTE_DRIVER", "runc")
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.sandbox_id == "sb-all"
        assert entry.environment == "staging"
        assert entry.compute_driver == "runc"

    def test_missing_env_vars_produce_none(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_ID", raising=False)
        monkeypatch.delenv("OPENSHELL_SANDBOX_ID", raising=False)
        monkeypatch.delenv("AGT_ENVIRONMENT", raising=False)
        monkeypatch.delenv("OPENSHELL_COMPUTE_DRIVER", raising=False)
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.sandbox_id is None
        assert entry.environment is None
        assert entry.compute_driver is None

    def test_empty_string_env_var_treated_as_absent(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_ID", "")
        monkeypatch.setenv("OPENSHELL_SANDBOX_ID", "")
        monkeypatch.setenv("AGT_ENVIRONMENT", "")
        monkeypatch.setenv("OPENSHELL_COMPUTE_DRIVER", "")
        log = AuditLog()
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        assert entry.sandbox_id is None
        assert entry.environment is None
        assert entry.compute_driver is None

    def test_env_context_captured_at_init_not_per_call(self, monkeypatch):
        """Changing env vars after init must not affect subsequent log() calls."""
        monkeypatch.setenv("SANDBOX_ID", "sb-at-init")
        log = AuditLog()
        monkeypatch.setenv("SANDBOX_ID", "sb-changed-later")
        entry = log.log(
            event_type="test",
            agent_did="did:web:a1",
            action="ping",
        )
        # Must see the value captured at init, not the changed value
        assert entry.sandbox_id == "sb-at-init"

    def test_context_consistent_across_multiple_log_calls(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_ID", "sb-consistent")
        log = AuditLog()
        entries = [
            log.log(event_type="test", agent_did="did:web:a1", action=f"action-{i}")
            for i in range(5)
        ]
        for e in entries:
            assert e.sandbox_id == "sb-consistent"


# ---------------------------------------------------------------------------
# Regression — FileAuditSink unaffected
# ---------------------------------------------------------------------------


class TestFileAuditSinkRegression:
    """Ensure existing FileAuditSink behaviour is unchanged."""

    def test_write_creates_file(self, tmp_path: Path):
        path = tmp_path / "reg_audit.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(_make_entry())
        assert path.exists()

    def test_write_multiple_entries(self, tmp_path: Path):
        path = tmp_path / "reg_multi.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        for i in range(5):
            sink.write(_make_entry(entry_id=f"reg-{i}"))
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 5

    def test_verify_integrity_passes(self, tmp_path: Path):
        path = tmp_path / "reg_integrity.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        for i in range(3):
            sink.write(_make_entry(entry_id=f"ri-{i}"))
        ok, err = sink.verify_integrity()
        assert ok is True
        assert err is None

    def test_chain_unbroken_without_context_fields(self, tmp_path: Path):
        """Entries without context fields must still form a valid chain."""
        path = tmp_path / "reg_plain.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        sink.write(AuditEntry(event_type="e", agent_did="did:web:a", action="a1"))
        sink.write(AuditEntry(event_type="e", agent_did="did:web:a", action="a2"))
        verifier = HashChainVerifier()
        ok, errors = verifier.verify_file(path, SECRET_KEY)
        assert ok is True
        assert errors == []

    def test_chain_unbroken_with_context_fields(self, tmp_path: Path):
        """Entries WITH context fields must also form a valid chain."""
        path = tmp_path / "reg_ctx.jsonl"
        sink = FileAuditSink(path, SECRET_KEY)
        for i in range(4):
            sink.write(
                AuditEntry(
                    event_type="e",
                    agent_did="did:web:a",
                    action=f"a{i}",
                    sandbox_id="sb-reg",
                    environment="prod",
                    compute_driver="runc",
                )
            )
        verifier = HashChainVerifier()
        ok, errors = verifier.verify_file(path, SECRET_KEY)
        assert ok is True
        assert errors == []
