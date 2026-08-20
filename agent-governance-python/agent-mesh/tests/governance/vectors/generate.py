# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regenerate the FileAuditSink test vectors from the reference implementation.

Run from the repository root:

    python agent-governance-python/agent-mesh/tests/governance/vectors/generate.py

The vectors are produced by ``FileAuditSink`` itself rather than by an
independent reimplementation of the algorithm. That is the point: a fixture
computed by second code is only evidence that two readings of the source agree,
which is precisely the assumption an external verifier should not have to make.

Everything that would otherwise vary per run (entry ids, timestamps, the HMAC
key) is pinned here, so regenerating on an unchanged implementation produces a
byte-identical file and a real change shows up as a diff rather than as noise.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from agentmesh.governance.audit import AuditEntry
from agentmesh.governance.audit_backends import FileAuditSink

#: Fixture, not a secret. Committed so an external implementer can recompute
#: every signature below without asking anyone for anything.
SECRET_KEY = b"agt-file-audit-sink-test-vectors-v1"

VECTORS_PATH = Path(__file__).with_name("file_audit_sink_v1.jsonl")


def _ts(seconds: int) -> datetime:
    return datetime(2026, 1, 1, 0, 0, seconds, tzinfo=timezone.utc)


def _entries() -> list[AuditEntry]:
    """Four entries chosen to pin the parts an implementer cannot guess."""
    return [
        # 1. Genesis. previous_hash is "" rather than a hash of nothing, and an
        #    implementer who seeds the chain with sha256(b"") gets a mismatch on
        #    entry 2 rather than on entry 1, which is a confusing place to start
        #    debugging.
        AuditEntry(
            entry_id="audit_vector_0001",
            timestamp=_ts(0),
            event_type="tool_invocation",
            agent_did="did:web:agent-alpha",
            action="read_file",
            resource="/etc/hosts",
            outcome="success",
        ),
        # 2. Chained, and carrying every optional field, so the canonical field
        #    order is exercised with nothing left at its default.
        AuditEntry(
            entry_id="audit_vector_0002",
            timestamp=_ts(1),
            event_type="policy_decision",
            agent_did="did:web:agent-alpha",
            action="network_egress",
            resource="https://example.invalid/upload",
            target_did="did:web:agent-beta",
            data={"bytes": 4096, "nested": {"b": 2, "a": 1}},
            outcome="denied",
            policy_decision="deny",
            matched_rule="rule-egress-01",
            trace_id="trace-abc-123",
            session_id="session-xyz-789",
        ),
        # 3. Optional fields left as None. They are present in the hashed payload
        #    as JSON null, not omitted, and an implementer who drops null keys
        #    before serialising gets a different digest.
        AuditEntry(
            entry_id="audit_vector_0003",
            timestamp=_ts(2),
            event_type="tool_invocation",
            agent_did="did:web:agent-gamma",
            action="noop",
        ),
        # 4. The trap the vectors exist for. sandbox_id, environment and
        #    compute_driver are written to the file and excluded from the hashed
        #    payload, so this entry's content_hash must equal what entry 3's
        #    shape would produce with these fields absent. An implementer who
        #    hashes the fields they can see fails here and only here.
        AuditEntry(
            entry_id="audit_vector_0004",
            timestamp=_ts(3),
            event_type="tool_invocation",
            agent_did="did:web:agent-gamma",
            action="noop",
            sandbox_id="sandbox-42",
            environment="staging",
            compute_driver="firecracker",
        ),
    ]


def main() -> int:
    with TemporaryDirectory() as tmp:
        sink = FileAuditSink(Path(tmp) / "audit.jsonl", secret_key=SECRET_KEY)
        sink.write_batch(_entries())
        sink.close()
        produced = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8")

    # Rewritten with sorted keys so the committed file has a stable field order
    # and a diff means a value changed, not that a dict iterated differently.
    lines = [
        json.dumps(json.loads(line), sort_keys=True)
        for line in produced.splitlines()
        if line.strip()
    ]
    VECTORS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} vectors -> {VECTORS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
