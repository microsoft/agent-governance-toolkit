# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for TRACE Trust Record emission (ADR-0032)."""

import json
import re
from pathlib import Path

import pytest

from agentmesh.governance.audit import AuditLog
from agentmesh.governance.govern import govern
from agentmesh.governance.trace_sink import (
    TRACEAuditSink,
    TraceConfig,
    session_to_trust_record,
)

_POLICY_YAML = """
apiVersion: governance.toolkit/v1
version: "1.0"
name: test-policy
agents:
  - did:web:example.org/agent/test
rules:
  - name: allow-all
    condition: "action.type != 'deny'"
    action: allow
"""

_AGENT_DID = "did:web:example.org/agent/test"
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


def _make_audit_log() -> AuditLog:
    log = AuditLog()
    log.log(
        event_type="tool_invocation",
        agent_did=_AGENT_DID,
        action="read_file",
        resource="/data/report.txt",
        outcome="success",
    )
    log.log(
        event_type="policy_evaluation",
        agent_did=_AGENT_DID,
        action="read_file",
        outcome="allow",
        policy_decision="allow",
    )
    return log


def _policy_hash(policy_yaml: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(policy_yaml.encode()).hexdigest()


class TestSessionToTrustRecord:
    def test_required_fields_present(self):
        log = _make_audit_log()
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        for field in ("eat_profile", "iat", "subject", "model", "runtime",
                      "policy", "data_class", "tool_transcript",
                      "build_provenance", "appraisal", "transparency"):
            assert field in record, f"missing field: {field}"

    def test_eat_profile_sentinel(self):
        log = _make_audit_log()
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        assert record["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"

    def test_subject_is_agent_did(self):
        log = _make_audit_log()
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        assert record["subject"] == _AGENT_DID

    def test_iat_is_from_last_entry(self):
        log = _make_audit_log()
        last_ts = int(log._chain._entries[-1].timestamp.timestamp())
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        assert record["iat"] == last_ts

    def test_runtime_is_software_only(self):
        log = _make_audit_log()
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        assert record["runtime"]["platform"] == "software-only"
        assert _DIGEST_RE.match(record["runtime"]["measurement"])

    def test_policy_bundle_hash_is_passed_through(self):
        log = _make_audit_log()
        ph = _policy_hash(_POLICY_YAML)
        record = session_to_trust_record(_AGENT_DID, log, ph, TraceConfig("./out/"))
        assert record["policy"]["bundle_hash"] == ph

    def test_tool_transcript_digest_and_count(self):
        log = _make_audit_log()
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        assert _DIGEST_RE.match(record["tool_transcript"]["hash"])
        assert record["tool_transcript"]["call_count"] == 2

    def test_build_provenance_slsa_level_0(self):
        log = _make_audit_log()
        record = session_to_trust_record(
            _AGENT_DID, log, _policy_hash(_POLICY_YAML), TraceConfig("./out/")
        )
        assert record["build_provenance"]["slsa_level"] == 0

    def test_custom_model_provider(self):
        log = _make_audit_log()
        cfg = TraceConfig("./out/", model_provider="anthropic", model_id="claude-sonnet-4-6")
        record = session_to_trust_record(_AGENT_DID, log, _policy_hash(_POLICY_YAML), cfg)
        assert record["model"]["provider"] == "anthropic"
        assert record["model"]["model_id"] == "claude-sonnet-4-6"

    def test_model_version_included_when_set(self):
        log = _make_audit_log()
        cfg = TraceConfig("./out/", model_version="20251001")
        record = session_to_trust_record(_AGENT_DID, log, _policy_hash(_POLICY_YAML), cfg)
        assert record["model"]["version"] == "20251001"

    def test_model_version_absent_when_not_set(self):
        log = _make_audit_log()
        cfg = TraceConfig("./out/")
        record = session_to_trust_record(_AGENT_DID, log, _policy_hash(_POLICY_YAML), cfg)
        assert "version" not in record["model"]

    def test_custom_build_provenance_digest(self):
        log = _make_audit_log()
        bp_digest = "sha256:" + "a" * 64
        cfg = TraceConfig("./out/", build_provenance_digest=bp_digest)
        record = session_to_trust_record(_AGENT_DID, log, _policy_hash(_POLICY_YAML), cfg)
        assert record["build_provenance"]["digest"] == bp_digest

    def test_build_provenance_digest_falls_back_to_measurement(self):
        log = _make_audit_log()
        cfg = TraceConfig("./out/")  # no explicit bp_digest
        record = session_to_trust_record(_AGENT_DID, log, _policy_hash(_POLICY_YAML), cfg)
        assert record["build_provenance"]["digest"] == record["runtime"]["measurement"]

class TestTRACEAuditSinkEmit:
    def test_emit_writes_json_file(self, tmp_path):
        log = _make_audit_log()
        cfg = TraceConfig(str(tmp_path) + "/", model_provider="anthropic", model_id="claude-sonnet-4-6")
        sink = TRACEAuditSink(cfg, _AGENT_DID, _policy_hash(_POLICY_YAML))
        path = sink.emit(log)
        assert path is not None
        out = Path(path)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["subject"] == _AGENT_DID
        for field in ("eat_profile", "iat", "model", "runtime", "policy",
                      "data_class", "build_provenance", "appraisal", "tool_transcript"):
            assert field in data, f"missing TRACE field: {field}"

    def test_emit_file_is_valid_trust_record(self, tmp_path):
        log = _make_audit_log()
        cfg = TraceConfig(str(tmp_path) + "/")
        sink = TRACEAuditSink(cfg, _AGENT_DID, _policy_hash(_POLICY_YAML))
        path = sink.emit(log)
        data = json.loads(Path(path).read_text())
        assert data["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"
        assert data["subject"] == _AGENT_DID

    def test_emit_returns_none_for_empty_log(self, tmp_path):
        log = AuditLog()
        cfg = TraceConfig(str(tmp_path) + "/")
        sink = TRACEAuditSink(cfg, _AGENT_DID, _policy_hash(_POLICY_YAML))
        assert sink.emit(log) is None

    def test_emit_returns_none_for_none_log(self, tmp_path):
        cfg = TraceConfig(str(tmp_path) + "/")
        sink = TRACEAuditSink(cfg, _AGENT_DID, _policy_hash(_POLICY_YAML))
        assert sink.emit(None) is None

    def test_emit_warns_and_returns_none_for_bare_agent_id(self, tmp_path):
        log = _make_audit_log()
        cfg = TraceConfig(str(tmp_path) + "/")
        sink = TRACEAuditSink(cfg, "*", _policy_hash(_POLICY_YAML))
        with pytest.warns(UserWarning, match="not a SPIFFE URI or DID"):
            result = sink.emit(log)
        assert result is None

    def test_emit_specific_file_path(self, tmp_path):
        log = _make_audit_log()
        out_file = str(tmp_path / "my-record.json")
        cfg = TraceConfig(out_file)
        sink = TRACEAuditSink(cfg, _AGENT_DID, _policy_hash(_POLICY_YAML))
        path = sink.emit(log)
        assert path == out_file
        assert Path(out_file).exists()


class TestGovernedCallableCloseSession:
    def test_close_session_returns_none_without_trace_config(self):
        agent = govern(lambda: None, policy=_POLICY_YAML, agent_id=_AGENT_DID)
        assert agent.close_session() is None

    def test_close_session_writes_trust_record(self, tmp_path):
        def tool(action, resource=None):
            return "ok"

        agent = govern(
            tool,
            policy=_POLICY_YAML,
            agent_id=_AGENT_DID,
            trace=TraceConfig(
                str(tmp_path) + "/",
                model_provider="anthropic",
                model_id="claude-sonnet-4-6",
            ),
        )
        agent(action="read", resource="report.txt")
        path = agent.close_session()

        assert path is not None
        data = json.loads(Path(path).read_text())
        assert data["subject"] == _AGENT_DID
        assert data["policy"]["enforcement_mode"] == "enforce"
        assert data["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"

    def test_close_session_returns_none_for_empty_audit(self, tmp_path):
        # Audit is empty because the tool is never called
        agent = govern(
            lambda: None,
            policy=_POLICY_YAML,
            agent_id=_AGENT_DID,
            audit=False,
            trace=TraceConfig(str(tmp_path) + "/"),
        )
        assert agent.close_session() is None
