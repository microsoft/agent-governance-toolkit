# Tutorial 04 — Audit Logging & Compliance

> **Package:** `agent-governance-toolkit` · **Time:** 25 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- Append-only audit logs with cryptographic integrity
- Hash chains for tamper-evident event recording
- OWASP ASI 2026 compliance mapping and verification

---

Every action an AI agent takes — tool calls, policy decisions, trust
handshakes — must be recorded in a **tamper-proof** log.Without it,
you cannot answer the question every auditor will ask: *"What exactly did
this agent do, and who authorised it?"*

The Agent Governance Toolkit gives you two complementary pieces:

| Package | Install | Purpose |
|---------|---------|---------|
| `agentmesh-platform` | `pip install agentmesh-platform` | `AuditLog` with Merkle-chain integrity |
| `agent-governance-toolkit` | `pip install agent-governance-toolkit` | OWASP ASI 2026 compliance CLI |

This tutorial walks through both, from a single log call to a CI/CD
compliance gate.

---

## 1 — Quick Start

```python
from agentmesh.governance.audit import AuditLog

# Create an in-memory audit log
audit = AuditLog()

# Record a tool invocation
entry = audit.log(
    event_type="tool_invocation",
    agent_did="did:web:sales-assistant.example.com",
    action="allow",
    resource="/crm/contacts",
    data={"tool": "crm_lookup", "query": "acme corp"},
    outcome="success",
    trace_id="trace-7f3a",
)

print(entry.entry_id)     # unique UUID
print(entry.entry_hash)   # SHA-256 hash of the entry
print(entry.timestamp)    # UTC datetime

# Verify nothing has been tampered with
is_valid, error = audit.verify_integrity()
assert is_valid, f"Chain broken: {error}"
print("✅ Audit chain intact")
```

Run it:

```bash
pip install agentmesh-platform
python quickstart_audit.py
```

---

## 2 — AuditLog API Reference

### 2.1 Creating an AuditLog

```python
from agentmesh.governance.audit import AuditLog

# In-memory only
audit = AuditLog()

# With an external sink (see §6)
from agentmesh.governance.audit_backends import FileAuditSink

sink = FileAuditSink(path="audit.jsonl", secret_key=b"my-hmac-secret")
audit = AuditLog(sink=sink)
```

### 2.2 `log()` — Record an Event

```python
entry = audit.log(
    event_type="tool_invocation",   # see event types below
    agent_did="did:web:agent.example.com",
    action="allow",                 # allow | deny | audit | quarantine | warning
    resource="/api/users",          # what the agent accessed
    data={"method": "GET"},         # arbitrary metadata (secrets are stripped)
    outcome="success",              # success | failure | denied | error
    policy_decision="allowed",      # human-readable policy result
    trace_id="trace-abc123",        # correlation ID for distributed tracing
)
```

**Event types:**

| Event Type | When |
|---|---|
| `tool_invocation` | Agent successfully called a tool |
| `tool_blocked` | Policy denied a tool call |
| `policy_evaluation` | Policy engine evaluated a request |
| `policy_violation` | Agent violated a governance policy |
| `rogue_detection` | Anomaly detection flagged an agent |
| `agent_invocation` | Agent-to-agent delegation occurred |

**Outcomes:** `success`, `failure`, `denied`, `error`

**Actions:** `allow`, `deny`, `audit`, `quarantine`, `warning`

### 2.3 `query()` — Search the Audit Trail

```python
from datetime import datetime, timezone, timedelta

now = datetime.now(timezone.utc)
one_hour_ago = now - timedelta(hours=1)

entries = audit.query(
    agent_did="did:web:agent.example.com",  # filter by agent
    event_type="tool_invocation",           # filter by event type
    start_time=one_hour_ago,                # time range start
    end_time=now,                           # time range end
    outcome="success",                      # filter by outcome
    limit=50,                               # max results (default 100)
)

for e in entries:
    print(f"{e.timestamp} | {e.action} | {e.resource}")
```

### 2.4 `get_entry()` — Look Up a Single Entry

```python
entry = audit.get_entry(entry_id="some-uuid-here")
print(entry.event_type, entry.outcome)
```

### 2.5 `get_entries_for_agent()` and `get_entries_by_type()`

Convenience shortcuts when you only need one filter:

```python
# Everything agent X did (last 100 by default)
agent_entries = audit.get_entries_for_agent("did:web:agent.example.com", limit=200)

# All policy violations
violations = audit.get_entries_by_type("policy_violation", limit=50)
```

### 2.6 `verify_integrity()` — Full Chain Verification

```python
is_valid, error_msg = audit.verify_integrity()

if not is_valid:
    raise RuntimeError(f"Audit trail tampered: {error_msg}")
```

This verifies the entire Merkle chain and every entry hash. Call it
periodically or before exporting data.

### 2.7 `get_proof()` — Merkle Inclusion Proof

```python
proof = audit.get_proof(entry.entry_id)

print(proof["entry"])         # the AuditEntry
print(proof["merkle_root"])   # current Merkle root hash
print(proof["merkle_proof"])  # list of (hash, position) tuples
print(proof["verified"])      # True if the proof checks out
```

A third party can verify the proof against the published root hash
without needing the full log.

### 2.8 `export()` and `export_cloudevents()`

```python
# Plain dict export (entries + metadata)
data = audit.export(start_time=one_hour_ago, end_time=now)
print(data["entries"])   # list of entry dicts
print(data["metadata"])  # chain metadata

# CloudEvents v1.0 JSON envelopes
events = audit.export_cloudevents(start_time=one_hour_ago)
for ce in events:
    print(ce["type"])    # e.g. "ai.agentmesh.tool.invoked"
    print(ce["source"])  # agent DID
```

---

## 3 — Merkle Chain Integrity

### How It Works

Every entry that enters `AuditLog` is added to an internal
`MerkleAuditChain`. The chain builds a **Merkle tree** over all
entries:

```
        Root Hash
       /         \
    H(AB)       H(CD)
   /    \      /    \
  H(A)  H(B) H(C)  H(D)   ← leaf = SHA-256 of entry
```

Key properties:

* **Append-only** — entries cannot be removed or reordered.
* **Tamper-evident** — changing any entry changes the root hash.
* **Efficient proofs** — proving an entry exists requires only
  O(log n) hashes, not the full log.

### Verifying the Chain Programmatically

```python
from agentmesh.governance.audit import AuditLog

audit = AuditLog()

# Log several events
for i in range(100):
    audit.log(
        event_type="tool_invocation",
        agent_did=f"did:web:agent-{i % 5}.example.com",
        action="allow",
        resource=f"/api/resource/{i}",
        outcome="success",
    )

# Full integrity check
is_valid, error = audit.verify_integrity()
print(f"Chain valid: {is_valid}")  # True

# Get the Merkle root (publish this for external auditors)
root = audit._chain.get_root_hash()
print(f"Merkle root: {root}")

# Prove a specific entry is in the log
proof = audit.get_proof(entry.entry_id)
assert proof["verified"], "Proof failed"
```

### Verifying a Proof Externally

A verifier who only has the root hash can confirm inclusion:

```python
from agentmesh.governance.audit import MerkleAuditChain

# Auditor receives: entry_hash, proof, and published root_hash
verified = MerkleAuditChain.verify_proof(
    entry_hash="abc123...",
    proof=[("def456...", "left"), ("789aaa...", "right")],
    root_hash="expected-root...",
)
print(f"Entry in log: {verified}")
```

---

## 4 — Querying the Audit Trail

### Find All Denied Tool Calls in the Last 24 Hours

```python
from datetime import datetime, timezone, timedelta

yesterday = datetime.now(timezone.utc) - timedelta(days=1)

denied = audit.query(
    event_type="tool_blocked",
    outcome="denied",
    start_time=yesterday,
    limit=200,
)

print(f"Blocked {len(denied)} tool calls in the last 24h")
for e in denied:
    print(f"  {e.agent_did} tried {e.resource} — {e.policy_decision}")
```

### Investigate a Specific Agent

```python
agent = "did:web:support-bot.example.com"

# Everything this agent did
all_actions = audit.get_entries_for_agent(agent, limit=500)

# Only violations
violations = audit.query(
    agent_did=agent,
    event_type="policy_violation",
)

# Rogue detection alerts
alerts = audit.query(
    agent_did=agent,
    event_type="rogue_detection",
)

print(f"Agent {agent}:")
print(f"  Total actions:  {len(all_actions)}")
print(f"  Violations:     {len(violations)}")
print(f"  Rogue alerts:   {len(alerts)}")
```

### Trace a Request Across Agents

Use `trace_id` to correlate entries across a multi-agent workflow:

```python
trace = "trace-7f3a-b2c1"

# query() doesn't filter by trace_id directly, so export and filter
all_entries = audit.export()["entries"]
trace_entries = [e for e in all_entries if e.get("trace_id") == trace]

for e in trace_entries:
    print(f"{e['timestamp']} | {e['agent_did']} | {e['action']} | {e['resource']}")
```

---

## 5 — External Sinks

In-memory audit is fine for development. In production you need
durable storage. The toolkit provides `FileAuditSink` out of the box
and defines the `AuditSink` protocol so you can write your own.

### 5.1 FileAuditSink — JSON-Lines on Disk

```python
from agentmesh.governance.audit import AuditLog
from agentmesh.governance.audit_backends import FileAuditSink

# Every entry is HMAC-signed and hash-chained
sink = FileAuditSink(
    path="audit_trail.jsonl",
    secret_key=b"change-me-to-a-real-secret",
    max_file_size=50 * 1024 * 1024,  # rotate at 50 MB (0 = no rotation)
)

audit = AuditLog(sink=sink)

# Log events as normal — they're persisted automatically
audit.log(
    event_type="tool_invocation",
    agent_did="did:web:agent.example.com",
    action="allow",
    resource="/api/data",
    outcome="success",
)

# Verify the on-disk chain independently
is_valid, error = sink.verify_integrity()
print(f"File chain valid: {is_valid}")

# Read back signed entries
signed_entries = sink.read_entries()
for se in signed_entries:
    print(f"{se.entry_id}: hash={se.content_hash[:16]}... sig={se.signature[:16]}...")

# Always close when done
sink.close()
```

The output file (`audit_trail.jsonl`) contains one JSON object per
line. Each entry includes `content_hash`, `previous_hash`, and
an HMAC `signature`.

### 5.2 Writing a Custom Sink

Implement the `AuditSink` protocol to push entries to a database,
message queue, or cloud service:

```python
from agentmesh.governance.audit import AuditEntry
from agentmesh.governance.audit_backends import AuditSink

class PostgresSink:
    """Push audit entries to a PostgreSQL table."""

    def __init__(self, dsn: str):
        import psycopg2
        self._conn = psycopg2.connect(dsn)

    def write(self, entry: AuditEntry) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_log
                    (entry_id, timestamp, event_type, agent_did,
                     action, resource, outcome, entry_hash, trace_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.event_type,
                    entry.agent_did,
                    entry.action,
                    entry.resource,
                    entry.outcome,
                    entry.entry_hash,
                    entry.trace_id,
                ),
            )
            self._conn.commit()

    def write_batch(self, entries: list[AuditEntry]) -> None:
        for entry in entries:
            self.write(entry)

    def verify_integrity(self) -> tuple[bool, str | None]:
        # Implement chain verification against DB rows
        return True, None

    def close(self) -> None:
        self._conn.close()


# Use it
sink = PostgresSink(dsn=os.environ["DATABASE_URL"])  # e.g., postgresql://user:***@host/agents
audit = AuditLog(sink=sink)
```

> **Tip:** The protocol is defined with `@runtime_checkable`, so you
> can verify your sink with `isinstance(my_sink, AuditSink)`.

---

## 6 — OWASP ASI 2026 Compliance Checking

The `agent-governance-toolkit` package verifies that your deployment covers
all 10 OWASP ASI 2026 security controls.

### 6.1 Install

```bash
pip install agent-governance-toolkit
```

### 6.2 Verify Governance Coverage

```bash
# Human-readable summary
agt verify
```

Output:

```
OWASP ASI 2026 Governance Verification
=======================================
✅ ASI-01  Prompt Injection         PolicyInterceptor
✅ ASI-02  Insecure Tool Use        ToolAliasRegistry
✅ ASI-03  Excessive Agency          GovernancePolicy
✅ ASI-04  Unauthorized Escalation   EscalationPolicy
✅ ASI-05  Trust Boundary Violation  CardRegistry
✅ ASI-06  Insufficient Logging      AuditChain
✅ ASI-07  Insecure Identity         AgentIdentity
✅ ASI-08  Policy Bypass             PolicyConflictResolver
✅ ASI-09  Supply Chain Integrity    IntegrityVerifier
✅ ASI-10  Behavioral Anomaly        ComplianceEngine

Coverage: 10/10 (100%)
```

```bash
# Machine-readable JSON
agt verify --json
```

```bash
# Shields.io badge for your README
agt verify --badge
```

### Secure Audit Handling

The CLI is hardened against information disclosure. If a command fails in machine-readable mode, it returns a sanitized error:

```json
{
  "status": "error",
  "message": "Audit log processing failed",
  "type": "InternalError"
}
```

This prevents leaking internal system details in CI/CD pipeline logs.

Output:

```markdown
[![OWASP ASI 2026](https://img.shields.io/badge/OWASP%20ASI%202026-10%2F10-brightgreen)](https://owaspai.org/asi/)
```

### 6.3 The 10 ASI Controls

| Control | Risk | Governance Component |
|---------|------|---------------------|
| ASI-01 | Prompt Injection | `PolicyInterceptor` in `agent_os.integrations.base` |
| ASI-02 | Insecure Tool Use | `ToolAliasRegistry` in `agent_os.integrations.tool_aliases` |
| ASI-03 | Excessive Agency | `GovernancePolicy` in `agent_os.integrations.base` |
| ASI-04 | Unauthorized Escalation | `EscalationPolicy` in `agent_os.integrations.escalation` |
| ASI-05 | Trust Boundary Violation | `CardRegistry` in `agentmesh.trust.cards` |
| ASI-06 | Insufficient Logging | `AuditChain` in `agentmesh.governance.audit` |
| ASI-07 | Insecure Identity | `AgentIdentity` in `agentmesh.identity.agent_id` |
| ASI-08 | Policy Bypass | `PolicyConflictResolver` in `agentmesh.governance.conflict_resolution` |
| ASI-09 | Supply Chain Integrity | `IntegrityVerifier` in `agent_compliance.integrity` |
| ASI-10 | Behavioral Anomaly | `ComplianceEngine` in `agentmesh.governance.compliance` |

### 6.4 Verify Supply-Chain Integrity

Check that governance module source files and critical functions haven't
been tampered with:

```bash
# Generate a baseline manifest
agt integrity --generate integrity.json

# Later, verify against it
agt integrity --manifest integrity.json
```

```bash
# JSON output for automation
agt integrity --manifest integrity.json --json
```

The integrity checker verifies:

* **File hashes** — SHA-256 of every governance module source file.
* **Function bytecode hashes** — critical functions like
  `PolicyEngine.evaluate`, `AuditChain.add_entry`, and
  `CardRegistry.is_verified` are bytecode-hashed to detect patches.

### 6.5 Programmatic Verification

```python
from agent_compliance.verify import GovernanceVerifier
from agent_compliance.integrity import IntegrityVerifier

# OWASP ASI coverage
verifier = GovernanceVerifier()
attestation = verifier.verify()

print(f"Passed:   {attestation.passed}")
print(f"Coverage: {attestation.coverage_pct()}%")
print(f"Hash:     {attestation.attestation_hash}")

# Print per-control results
print(attestation.summary())

# Get JSON for storage or CI artifacts
report_json = attestation.to_json()

# Supply chain integrity
integrity = IntegrityVerifier(manifest_path="integrity.json")
report = integrity.verify()

print(report.summary())
print(f"Modules checked: {report.modules_checked}")
print(f"Missing modules: {report.modules_missing}")
```

---

## 7 — Compliance Reporting

### 7.1 Generate an Audit Report for Auditors

Combine audit export with compliance attestation into a single report:

```python
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from agentmesh.governance.audit import AuditLog
from agentmesh.governance.audit_backends import FileAuditSink
from agent_compliance.verify import GovernanceVerifier
from agent_compliance.integrity import IntegrityVerifier


def generate_compliance_report(
    audit: AuditLog,
    output_path: str = "compliance_report.json",
    days: int = 30,
) -> dict:
    """Generate a compliance report covering the last N days."""

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    # 1. Audit trail summary
    export = audit.export(start_time=start, end_time=now)
    entries = export["entries"]

    event_counts = {}
    outcome_counts = {}
    for e in entries:
        event_counts[e["event_type"]] = event_counts.get(e["event_type"], 0) + 1
        outcome_counts[e["outcome"]] = outcome_counts.get(e["outcome"], 0) + 1

    # 2. Chain integrity
    chain_valid, chain_error = audit.verify_integrity()

    # 3. OWASP ASI attestation
    attestation = GovernanceVerifier().verify()

    # 4. Supply chain integrity
    try:
        integrity = IntegrityVerifier(manifest_path="integrity.json")
        integrity_report = integrity.verify()
        integrity_passed = integrity_report.passed
    except FileNotFoundError:
        integrity_passed = None  # no manifest on file

    # Assemble report
    report = {
        "report_generated": now.isoformat(),
        "period_start": start.isoformat(),
        "period_end": now.isoformat(),
        "audit_trail": {
            "total_entries": len(entries),
            "events_by_type": event_counts,
            "events_by_outcome": outcome_counts,
            "chain_integrity_valid": chain_valid,
            "chain_integrity_error": chain_error,
            "merkle_root": audit._chain.get_root_hash(),
        },
        "owasp_asi_2026": {
            "passed": attestation.passed,
            "controls_passed": attestation.controls_passed,
            "controls_total": attestation.controls_total,
            "coverage_pct": attestation.coverage_pct(),
            "attestation_hash": attestation.attestation_hash,
        },
        "supply_chain_integrity": {
            "passed": integrity_passed,
        },
    }

    Path(output_path).write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    print(f"📄 Report written to {output_path}")
    return report


# Usage
audit = AuditLog()
# ... after logging events ...
report = generate_compliance_report(audit, days=30)
```

### 7.2 CI/CD Compliance Gate

Add compliance checks to your GitHub Actions pipeline so a failing
check blocks deployment:

```yaml
# .github/workflows/compliance.yml
name: Governance Compliance

on:
  push:
    branches: [main]
  pull_request:

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install governance packages
        run: |
          pip install agentmesh-platform agent-governance

      - name: Generate integrity manifest
        run: agt integrity --generate integrity.json

      - name: Verify OWASP ASI 2026 coverage
        run: agt verify --json > asi_report.json

      - name: Verify supply-chain integrity
        run: agt integrity --manifest integrity.json --json > integrity_report.json

      - name: Upload compliance artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: |
            asi_report.json
            integrity_report.json
            integrity.json
```

> **Tip:** `agt verify` exits with code **1** if any
> control is missing, so the pipeline step will fail automatically.

---

## 8 — AuditEntry Reference

Every call to `audit.log()` returns an `AuditEntry` with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `entry_id` | `str` | Unique UUID |
| `timestamp` | `datetime` | UTC timestamp |
| `event_type` | `str` | One of the event types above |
| `agent_did` | `str` | DID of the acting agent |
| `action` | `str` | Policy action taken |
| `resource` | `str \| None` | Resource accessed |
| `target_did` | `str \| None` | DID of the target agent (for delegation) |
| `data` | `dict` | Arbitrary metadata |
| `outcome` | `str` | success / failure / denied / error |
| `policy_decision` | `str \| None` | Human-readable policy result |
| `matched_rule` | `str \| None` | ID of the policy rule that matched |
| `previous_hash` | `str` | Hash of the prior entry in the chain |
| `entry_hash` | `str` | SHA-256 hash of this entry |
| `trace_id` | `str \| None` | Distributed tracing correlation ID |
| `session_id` | `str \| None` | Session identifier |

Key methods on `AuditEntry`:

```python
entry.compute_hash()    # recompute SHA-256
entry.verify_hash()     # True if stored hash matches computed hash
entry.to_cloudevent()   # CloudEvents v1.0 JSON envelope
```

---

## Next Steps

* **Tutorial 01–03** — Identity, trust, and policy (prerequisites for
  a full governance stack).
* **[OWASP ASI 2026](https://owaspai.org/asi/)** — Read the full
  specification for context on each control.
* **`examples/quickstart.py`** and **`examples/governed_agent.py`** in
  `agent-governance-python/agent-compliance/` — runnable demos you can adapt.
