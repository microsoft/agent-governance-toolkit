# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for TRACE v0.2 Trust Record model and session mapping."""

from __future__ import annotations

from agentmesh.governance.audit import AuditEntry
from agentmesh.governance.trace_model import (
    TraceModelConfig,
    TraceSession,
    session_to_trust_record,
)

_ZEROS = "0" * 64

_CONFIG = TraceModelConfig(
    model={
        "provider": "anthropic",
        "model_id": "claude-opus-4",
        "version": "1.0",
        "weights_digest": f"sha256:{_ZEROS}",
    },
    runtime={"platform": "software-only", "measurement": f"sha256:{_ZEROS}"},
    enforcement_mode="enforce",
    build_provenance={
        "slsa_level": 2,
        "builder": "github-actions",
        "digest": f"sha256:{_ZEROS}",
    },
    verifier="https://verifier.agentrust.io",
)


def _entry(**kwargs) -> AuditEntry:
    defaults = {
        "event_type": "tool_invocation",
        "agent_did": "did:mesh:test-agent",
        "action": "read_file",
    }
    defaults.update(kwargs)
    return AuditEntry(**defaults)


class TestSessionToTrustRecord:
    def test_golden_path_fields_present(self):
        session = TraceSession(
            agent_did="did:mesh:spiffe://cluster/ns/default/sa/agent-1",
            audit_entries=[_entry()],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)

        assert record["eat_profile"] == "tag:agentrust.io,2026:trace-v0.1"
        assert record["subject"] == "did:mesh:spiffe://cluster/ns/default/sa/agent-1"
        assert record["data_class"] == "public"
        assert isinstance(record["iat"], int) and record["iat"] > 0
        assert record["transparency"] == ""
        assert record["appraisal"]["status"] == "affirming"
        assert record["appraisal"]["verifier"] == "https://verifier.agentrust.io"
        assert record["tool_transcript"]["call_count"] == 1
        assert record["tool_transcript"]["hash"].startswith("sha256:")

    def test_affirming_when_no_denials(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[_entry(), _entry(event_type="session_start", action="start")],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["appraisal"]["status"] == "affirming"

    def test_contraindicated_on_denied_outcome(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[_entry(outcome="denied")],
            data_class="confidential",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["appraisal"]["status"] == "contraindicated"

    def test_contraindicated_on_tool_blocked(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[_entry(event_type="tool_blocked")],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["appraisal"]["status"] == "contraindicated"

    def test_contraindicated_on_policy_violation(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[_entry(event_type="policy_violation")],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["appraisal"]["status"] == "contraindicated"

    def test_call_count_only_counts_tool_invocations(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[
                _entry(event_type="tool_invocation"),
                _entry(event_type="tool_invocation"),
                _entry(event_type="session_start", action="start"),
                _entry(event_type="policy_check", action="check"),
            ],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["tool_transcript"]["call_count"] == 2

    def test_policy_bundle_hash_forwarded(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[_entry()],
            data_class="public",
            policy_bundle_hash="deadbeef1234",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["policy"]["bundle_hash"] == "deadbeef1234"

    def test_missing_policy_bundle_hash_defaults_to_empty(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[_entry()],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["policy"]["bundle_hash"] == ""

    def test_empty_entries_iat_is_zero(self):
        session = TraceSession(
            agent_did="did:mesh:test",
            audit_entries=[],
            data_class="public",
        )
        record = session_to_trust_record(session, _CONFIG)
        assert record["iat"] == 0
        assert record["appraisal"]["status"] == "affirming"
        assert record["tool_transcript"]["call_count"] == 0

    def test_transcript_hash_is_deterministic(self):
        entries = [_entry(entry_id="fixed-id-1"), _entry(entry_id="fixed-id-2")]
        session = TraceSession(agent_did="did:mesh:test", audit_entries=entries, data_class="public")
        r1 = session_to_trust_record(session, _CONFIG)
        r2 = session_to_trust_record(session, _CONFIG)
        assert r1["tool_transcript"]["hash"] == r2["tool_transcript"]["hash"]
