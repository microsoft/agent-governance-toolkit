# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for StdoutAuditSink and AuditEntry sandbox context fields."""

from __future__ import annotations

import io
import json
import os
from unittest.mock import patch

import pytest

from agentmesh.governance.audit import AuditEntry
from agentmesh.governance.audit_backends import AuditSink, StdoutAuditSink


# ── AuditEntry sandbox context fields ────────────────────────


class TestAuditEntrySandboxContext:
    """Tests for auto-populating sandbox context from env vars."""

    def test_fields_default_none_without_env(self):
        env_keys = ("SANDBOX_ID", "OPENSHELL_SANDBOX_ID", "AGT_ENVIRONMENT", "OPENSHELL_COMPUTE_DRIVER")
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
            )
            assert entry.sandbox_id is None
            assert entry.environment is None
            assert entry.compute_driver is None

    def test_sandbox_id_from_env(self):
        with patch.dict(os.environ, {"SANDBOX_ID": "sb-12345"}, clear=False):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
            )
            assert entry.sandbox_id == "sb-12345"

    def test_openshell_sandbox_id_fallback(self):
        env_keys = ("SANDBOX_ID",)
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        clean_env["OPENSHELL_SANDBOX_ID"] = "os-99"
        with patch.dict(os.environ, clean_env, clear=True):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
            )
            assert entry.sandbox_id == "os-99"

    def test_sandbox_id_prefers_sandbox_id_over_openshell(self):
        env = {"SANDBOX_ID": "primary", "OPENSHELL_SANDBOX_ID": "fallback"}
        with patch.dict(os.environ, env, clear=False):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
            )
            assert entry.sandbox_id == "primary"

    def test_environment_from_env(self):
        with patch.dict(os.environ, {"AGT_ENVIRONMENT": "production"}, clear=False):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
            )
            assert entry.environment == "production"

    def test_compute_driver_from_env(self):
        with patch.dict(os.environ, {"OPENSHELL_COMPUTE_DRIVER": "docker"}, clear=False):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
            )
            assert entry.compute_driver == "docker"

    def test_explicit_value_not_overridden_by_env(self):
        with patch.dict(os.environ, {"SANDBOX_ID": "from-env"}, clear=False):
            entry = AuditEntry(
                event_type="tool_invocation",
                agent_did="did:mesh:test",
                action="read",
                sandbox_id="explicit-value",
            )
            assert entry.sandbox_id == "explicit-value"


# ── StdoutAuditSink ──────────────────────────────────────────


class TestStdoutAuditSink:
    """Tests for the stdout JSONL audit sink."""

    def _make_entry(self, **kwargs) -> AuditEntry:
        defaults = {
            "event_type": "tool_invocation",
            "agent_did": "did:mesh:test123",
            "action": "read_file",
        }
        defaults.update(kwargs)
        # Prevent env var auto-population from polluting tests
        defaults.setdefault("sandbox_id", None)
        defaults.setdefault("environment", None)
        defaults.setdefault("compute_driver", None)
        env_keys = ("SANDBOX_ID", "OPENSHELL_SANDBOX_ID", "AGT_ENVIRONMENT", "OPENSHELL_COMPUTE_DRIVER")
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True):
            return AuditEntry(**defaults)

    def test_implements_audit_sink_protocol(self):
        sink = StdoutAuditSink(stream=io.StringIO())
        assert isinstance(sink, AuditSink)

    def test_write_produces_valid_jsonl(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        entry = self._make_entry()
        sink.write(entry)

        line = output.getvalue().strip()
        parsed = json.loads(line)
        assert parsed["event_type"] == "tool_invocation"
        assert parsed["agent_did"] == "did:mesh:test123"
        assert parsed["action"] == "read_file"
        assert parsed["outcome"] == "success"

    def test_write_flushes_immediately(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        entry = self._make_entry()
        sink.write(entry)
        assert len(output.getvalue()) > 0

    def test_write_batch(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        entries = [self._make_entry(action=f"action_{i}") for i in range(3)]
        sink.write_batch(entries)

        lines = output.getvalue().strip().split("\n")
        assert len(lines) == 3
        for i, line in enumerate(lines):
            parsed = json.loads(line)
            assert parsed["action"] == f"action_{i}"

    def test_each_write_is_single_line(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        entry = self._make_entry(data={"key": "value\nwith\nnewlines"})
        sink.write(entry)

        lines = output.getvalue().split("\n")
        non_empty = [l for l in lines if l.strip()]
        assert len(non_empty) == 1

    def test_includes_sandbox_context_fields(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output, include_context=True)
        entry = self._make_entry(
            sandbox_id="sb-001",
            environment="staging",
            compute_driver="docker",
        )
        sink.write(entry)

        parsed = json.loads(output.getvalue().strip())
        assert parsed["sandbox_id"] == "sb-001"
        assert parsed["environment"] == "staging"
        assert parsed["compute_driver"] == "docker"

    def test_excludes_context_when_disabled(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output, include_context=False)
        entry = self._make_entry(
            sandbox_id="sb-001",
            environment="staging",
            compute_driver="docker",
        )
        sink.write(entry)

        parsed = json.loads(output.getvalue().strip())
        assert "sandbox_id" not in parsed
        assert "environment" not in parsed
        assert "compute_driver" not in parsed

    def test_omits_none_fields(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        entry = self._make_entry()
        sink.write(entry)

        parsed = json.loads(output.getvalue().strip())
        assert "sandbox_id" not in parsed
        assert "resource" not in parsed
        assert "target_did" not in parsed

    def test_includes_optional_fields_when_set(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        entry = self._make_entry(
            resource="/data/secrets.yaml",
            target_did="did:mesh:target",
            trace_id="trace-abc",
            session_id="sess-123",
            policy_decision="deny",
            matched_rule="block_secrets",
        )
        sink.write(entry)

        parsed = json.loads(output.getvalue().strip())
        assert parsed["resource"] == "/data/secrets.yaml"
        assert parsed["target_did"] == "did:mesh:target"
        assert parsed["trace_id"] == "trace-abc"
        assert parsed["session_id"] == "sess-123"
        assert parsed["policy_decision"] == "deny"
        assert parsed["matched_rule"] == "block_secrets"

    def test_close_stops_writing(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        sink.close()
        entry = self._make_entry()
        sink.write(entry)
        assert output.getvalue() == ""

    def test_verify_integrity_always_true(self):
        sink = StdoutAuditSink(stream=io.StringIO())
        valid, error = sink.verify_integrity()
        assert valid is True
        assert error is None

    def test_output_parseable_by_jq(self):
        """Each line should be independently valid JSON (jq-compatible)."""
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        for i in range(5):
            sink.write(self._make_entry(action=f"action_{i}"))

        for line in output.getvalue().strip().split("\n"):
            parsed = json.loads(line)
            assert "entry_id" in parsed
            assert "timestamp" in parsed

    def test_timestamp_format_iso8601(self):
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)
        sink.write(self._make_entry())

        parsed = json.loads(output.getvalue().strip())
        ts = parsed["timestamp"]
        assert ts.endswith("Z")
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_env_vars_flow_through_to_output(self):
        """End-to-end: env vars -> AuditEntry -> StdoutAuditSink -> JSONL."""
        env = {
            "SANDBOX_ID": "container-xyz",
            "AGT_ENVIRONMENT": "production",
            "OPENSHELL_COMPUTE_DRIVER": "openshell",
        }
        output = io.StringIO()
        sink = StdoutAuditSink(stream=output)

        with patch.dict(os.environ, env, clear=False):
            entry = AuditEntry(
                event_type="policy_evaluation",
                agent_did="did:mesh:agent1",
                action="deploy",
            )
            sink.write(entry)

        parsed = json.loads(output.getvalue().strip())
        assert parsed["sandbox_id"] == "container-xyz"
        assert parsed["environment"] == "production"
        assert parsed["compute_driver"] == "openshell"
