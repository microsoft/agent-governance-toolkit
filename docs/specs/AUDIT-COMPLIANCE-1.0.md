<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->
<!-- Status: DRAFT | Version: 1.0 | Last updated: 2025-05-17 -->

# AGT Audit and Compliance Specification

## 1. Front Matter

### 1.1 Title

Agent Governance Toolkit -- Audit and Compliance System Specification

### 1.2 Version

1.0-DRAFT

### 1.3 Abstract

This document specifies the audit, compliance, and observability architecture of the
Agent Governance Toolkit (AGT). It defines the canonical data models, service provider
interfaces (SPIs), event processing pipelines, cryptographic integrity mechanisms,
compliance framework engines, and cross-component correlation strategies that comprise
the AGT audit subsystem.

The specification spans five AGT components:

- **Agent OS** -- Core audit logging, governance event processing, and OpenTelemetry integration
- **Agent Mesh** -- Merkle-chained audit log, compliance engine, decision BOM reconstruction, and audit collector REST API
- **Agent Hypervisor** -- Event bus, semantic delta engine, and commitment engine
- **Agent SRE** -- SRE-specific observability events and OTel conventions
- **Agent Lightning** -- Flight recorder emission and RL environment violation tracking

### 1.4 Conformance Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when,
and only when, they appear in ALL CAPITALS, as shown here.

### 1.5 Document Conventions

- Sections marked **[Pure Specification]** define normative requirements that all
  conforming implementations MUST satisfy regardless of implementation language or
  deployment topology.
- Sections marked **[Default Implementation]** describe the reference implementation
  provided by AGT. Conforming implementations MAY substitute alternative implementations
  provided they satisfy the corresponding pure specification requirements.
- Code examples use Python syntax consistent with the AGT reference implementation.
- All timestamps in this document and in conforming implementations MUST use ISO 8601
  format in UTC (e.g., `2025-05-17T14:30:00Z`).

---

## 2. Terminology & Definitions

### 2.1 Core Terms

| Term | Definition |
|------|-----------|
| **Audit Entry** | An immutable record of a governance-relevant event captured by the audit subsystem. |
| **Audit Backend** | A pluggable storage destination that receives and persists audit entries. |
| **Governance Event** | A structured event representing a policy evaluation, security finding, or compliance-relevant action within AGT. |
| **Event Sink** | A destination that receives batches of governance events for export or processing. |
| **Event Processor** | A background worker that batches governance events and exports them to registered sinks. |
| **Merkle Audit Chain** | A hash-linked chain of audit entries providing cryptographic integrity verification. |
| **Compliance Framework** | A regulatory or industry standard (e.g., SOC 2, HIPAA, EU AI Act, GDPR) against which agent behavior is assessed. |
| **Compliance Control** | A specific requirement within a compliance framework that agents MUST satisfy. |
| **Decision BOM** | A Bill of Materials reconstructing all inputs, context, and outputs of a governance decision. |
| **Semantic Delta** | A cryptographically-chained record of VFS changes within a hypervisor session turn. |
| **Commitment Record** | A summary commitment anchoring a session's delta chain for external verification. |
| **Event Bus** | The hypervisor's internal pub/sub system for distributing observability events. |
| **Flight Recorder** | A circular buffer of recent agent activity in Agent Lightning, convertible to spans. |
| **Governed Environment** | A Gym-compatible RL environment wrapper that tracks policy violations during agent training. |

### 2.2 Identity Terms

| Term | Definition |
|------|-----------|
| **Agent DID** | A Decentralized Identifier uniquely identifying an agent within the mesh. |
| **Agent ID** | A local identifier for an agent within Agent OS scope. |
| **Session ID** | A unique identifier for a governance session or conversation scope. |
| **Trace ID** | An OpenTelemetry-compatible trace identifier for distributed tracing correlation. |
| **Span ID** | An OpenTelemetry-compatible span identifier within a trace. |

### 2.3 Severity Levels

| Level | Description |
|-------|-------------|
| **critical** | Immediate action required; agent operation SHOULD be halted. |
| **high** | Significant risk; requires prompt remediation. |
| **medium** | Moderate risk; standard remediation timeline. |
| **low** | Informational; monitor and address as resources permit. |
| **info** | No risk; recorded for audit completeness. |

### 2.4 Decision Outcomes

| Outcome | Description |
|---------|-------------|
| **allow** | The requested action is permitted by all evaluated policies. |
| **deny** | The requested action is blocked by one or more policies. |
| **escalate** | The action requires human approval before proceeding. |
| **warn** | The action is permitted but flagged for review. |

---

## 3. Architectural Overview

### 3.1 System Context [Pure Specification]

The AGT Audit and Compliance system MUST provide:

1. **Universal audit capture** -- Every governance-relevant event across all AGT components
   MUST be captured in a structured, queryable format.
2. **Cryptographic integrity** -- Audit chains MUST be tamper-evident through hash-linking.
3. **Multi-framework compliance** -- The system MUST support concurrent assessment against
   multiple regulatory frameworks.
4. **Cross-component correlation** -- Events from different AGT components MUST be
   correlatable via shared identifiers (trace IDs, session IDs, agent DIDs).
5. **Pluggable export** -- Audit data MUST be exportable to arbitrary backends without
   modifying core logic.
6. **Non-blocking operation** -- Audit capture MUST NOT block the critical path of
   governance decisions.

### 3.2 Component Responsibilities

```
+------------------+     +------------------+     +---------------------+
|    Agent OS      |     |   Agent Mesh     |     | Agent Hypervisor    |
|                  |     |                  |     |                     |
| - AuditEntry     |     | - MerkleChain    |     | - EventBus          |
| - AuditBackend   |     | - Compliance     |     | - DeltaEngine       |
| - EventSink SPI  |     | - DecisionBOM    |     | - CommitmentEngine  |
| - EventProcessor |     | - AuditCollector |     |                     |
| - OTel Backend   |     |                  |     |                     |
+--------+---------+     +--------+---------+     +---------+-----------+
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
                    +--------------+--------------+
                    |                             |
           +-------+-------+           +---------+---------+
           |   Agent SRE   |           | Agent Lightning   |
           |               |           |                   |
           | - EventLogger |           | - FlightRecorder  |
           | - Conventions |           | - GovernedEnv     |
           +---------------+           +-------------------+
```

### 3.3 Data Flow [Pure Specification]

1. A governance-relevant action occurs (policy check, tool call, identity verification).
2. The originating component creates an audit entry or governance event.
3. The entry is dispatched to registered backends/sinks.
4. Backends persist the entry (file, OTel, in-memory, remote API).
5. If Merkle chaining is active, the entry is hash-linked to the previous entry.
6. Compliance assessments consume audit entries to evaluate control satisfaction.
7. Decision BOMs reconstruct the full context of individual decisions on demand.

### 3.4 Threading Model [Pure Specification]

- Audit entry creation MUST be thread-safe.
- Backend writes MUST be serialized per-backend (implementations MAY use locks, queues, or
  actor patterns).
- The event processor MUST use a dedicated background thread for batch export.
- Event sink `emit()` calls MUST NOT raise exceptions to the caller.
- All shared state access MUST be protected against concurrent modification.

### 3.5 Failure Semantics [Pure Specification]

- Individual backend failures MUST NOT prevent other backends from receiving entries.
- The event processor MUST implement circuit-breaker semantics to avoid cascading failures.
- When queue capacity is reached, the processor MUST apply DROP_OLDEST backpressure policy.
- Dropped events SHOULD be counted and reported via metrics.

---

## 4. Audit Entry Canonical Schema

### 4.1 Agent OS Audit Entry [Pure Specification]

An Audit Entry MUST contain the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string (ISO 8601 UTC) | REQUIRED | When the event occurred. MUST be UTC. |
| `event_type` | string | REQUIRED | Category of the audit event. |
| `agent_id` | string | REQUIRED | Identifier of the agent that triggered the event. |
| `action` | string | REQUIRED | The action being audited. |
| `decision` | string | REQUIRED | The governance decision outcome (allow, deny, escalate, warn). |
| `reason` | string | OPTIONAL | Human-readable explanation of the decision. Defaults to empty string. |
| `latency_ms` | float | OPTIONAL | Time in milliseconds to reach the decision. Defaults to 0.0. |
| `metadata` | dict | OPTIONAL | Arbitrary key-value pairs for extension data. Defaults to empty dict. |

### 4.2 Default Implementation -- Agent OS `AuditEntry` [Default Implementation]

```python
@dataclass
class AuditEntry:
    timestamp: str        # ISO 8601 UTC
    event_type: str
    agent_id: str
    action: str
    decision: str
    reason: str = ""
    latency_ms: float = 0.0
    metadata: dict = field(default_factory=dict)
```

The `GovernanceAuditLogger.log_decision()` convenience method MUST set `event_type` to
`"governance_decision"` and populate `timestamp` automatically using the current UTC time.

### 4.3 Agent Mesh Audit Entry [Pure Specification]

The Agent Mesh audit entry extends the base schema with mesh-specific fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entry_id` | string | REQUIRED | Unique identifier. Format: `audit_{uuid4_hex[:16]}`. |
| `timestamp` | datetime (UTC) | REQUIRED | When the event occurred. |
| `event_type` | string | REQUIRED | Category of the audit event. |
| `agent_did` | string | REQUIRED | DID of the agent. |
| `action` | string | REQUIRED | The action being audited. |
| `arguments_hash` | string | OPTIONAL | SHA-256 hash (hex, lowercase) of the canonical-JSON serialization of the action arguments. Defends against silent mutation of recorded arguments. See §4.3.1. |
| `resource` | string | OPTIONAL | Target resource of the action. |
| `target_did` | string | OPTIONAL | DID of the target agent (for inter-agent actions). |
| `approver_did` | string | OPTIONAL | DID of the principal whose approval authorized this action. Surfaces approval-chain identity in the audit row itself. See §4.3.1. |
| `data` | dict | OPTIONAL | Additional structured data. |
| `outcome` | string | OPTIONAL | Result of the action. Default: "success". |
| `policy_decision` | string | OPTIONAL | Policy engine decision. |
| `matched_rule` | string | OPTIONAL | Rule that matched. |
| `policy_version` | string | OPTIONAL | Version identifier of the policy bundle that produced this decision. Defends against silent policy downgrade. See §4.3.1. |
| `previous_hash` | string | OPTIONAL | Hash of the previous entry in the chain. |
| `entry_hash` | string | OPTIONAL | SHA-256 hash of this entry's canonical form. |
| `trace_id` | string | OPTIONAL | OTel trace ID for correlation. |
| `session_id` | string | OPTIONAL | Session scope identifier. |
| `sandbox_id` | string | OPTIONAL | Sandbox/container identifier. |
| `environment` | string | OPTIONAL | Deployment environment name. |
| `compute_driver` | string | OPTIONAL | Compute driver identifier. |

### 4.3.1 Additive Tamper-Evidence Fields [Pure Specification]

The fields `arguments_hash`, `approver_did`, and `policy_version` are OPTIONAL
in spec v1.0 and serve verifiability purposes that are not yet covered by the
canonical entry hash defined in §4.4. In spec v1.0:

- Implementations MAY populate these fields. Verifiers MUST NOT treat their
  presence or absence as a conformance signal.
- The canonical hash field set in §4.4 is intentionally unchanged from spec
  v1.0.0 to preserve chain verification of previously-persisted entries.
- Because these fields are not in the canonical hash, a tampering party can
  mutate them without invalidating `entry_hash`. Implementations and verifiers
  MUST NOT rely on these fields for tamper detection in v1.0.

Spec v1.1 will extend the §4.4 canonical field set to include these fields under
an explicit schema-version selector, providing tamper-evident coverage while
preserving v1.0 verification semantics for legacy chains.

### 4.4 Entry Hash Computation [Pure Specification]

Implementations MUST compute entry hashes using the following algorithm:

1. Construct a dictionary containing exactly: `entry_id`, `timestamp` (ISO format string),
   `event_type`, `agent_did`, `action`, `resource`, `data`, `outcome`, `previous_hash`.
2. Serialize to JSON with keys sorted alphabetically and no extra whitespace.
3. Compute SHA-256 hash of the UTF-8 encoded JSON bytes.
4. Encode the hash as a lowercase hexadecimal string.

Hash verification MUST use timing-safe comparison (e.g., `hmac.compare_digest`) to prevent
timing side-channel attacks.

### 4.5 Environment Auto-Population [Default Implementation]

The Agent Mesh audit entry SHOULD auto-populate contextual fields from environment variables:

| Field | Environment Variable(s) | Fallback |
|-------|------------------------|----------|
| `sandbox_id` | `SANDBOX_ID`, `OPENSHELL_SANDBOX_ID` | None |
| `environment` | `AGT_ENVIRONMENT` | None |
| `compute_driver` | `OPENSHELL_COMPUTE_DRIVER` | None |

---

## 5. Audit Backend SPI

### 5.1 Backend Protocol [Pure Specification]

An Audit Backend MUST implement the following interface:

```python
class AuditBackend(Protocol):
    def write(self, entry: AuditEntry) -> None:
        """Persist a single audit entry.

        Implementations MUST NOT raise exceptions to the caller.
        Implementations MUST be thread-safe.
        """
        ...

    def flush(self) -> None:
        """Flush any buffered entries to persistent storage.

        Implementations SHOULD ensure all previously written entries
        are durable after flush() returns.
        """
        ...
```

### 5.2 Backend Requirements [Pure Specification]

- A backend `write()` method MUST NOT raise exceptions. Failures MUST be handled internally
  (logged, counted, retried -- implementation-defined).
- A backend `write()` method MUST be thread-safe. Multiple concurrent callers MUST NOT
  corrupt internal state or produce garbled output.
- A backend `flush()` method SHOULD ensure durability of all previously accepted entries.
- Backends SHOULD implement a `close()` method for graceful resource cleanup.

### 5.3 JSONL File Backend [Default Implementation]

The default file-based backend writes one JSON object per line to a `.jsonl` file.

**Requirements:**

- The backend MUST use a threading lock to serialize write access.
- On POSIX systems, the backend MUST create audit files with permission mode `0o600`
  (owner read/write only).
- The backend MUST create parent directories automatically if they do not exist.
- Each line MUST be a complete, valid JSON object terminated by a newline character.
- The backend MUST implement `close()` to flush and close the underlying file handle.

### 5.4 In-Memory Backend [Default Implementation]

The in-memory backend stores entries in a Python list for testing and development.

- Entries MUST be appended to an internal `entries: list[AuditEntry]` attribute.
- The `flush()` method is a no-op.
- This backend is NOT RECOMMENDED for production use.

### 5.5 Logging Backend [Default Implementation]

The logging backend emits audit entries via Python's standard logging framework.

- Entries MUST be logged at INFO level.
- The default logger name MUST be `"agent_os.audit"`.
- Implementations MAY configure an alternative logger name.

### 5.6 Multi-Backend Fan-Out [Pure Specification]

The audit logger MUST support dispatching entries to multiple backends simultaneously.

- The `add_backend()` method MUST register additional backends at runtime.
- The `log()` method MUST write to ALL registered backends.
- Failure in one backend MUST NOT prevent delivery to other backends.
- The `flush()` method MUST flush ALL registered backends.

---

## 6. Governance Event Envelope

### 6.1 Schema Version [Pure Specification]

All governance events MUST carry a `schema_version` field. The current schema version
is `"1"`. Consumers MUST reject events with unrecognized schema versions.

### 6.2 Governance Event Kind Enumeration [Pure Specification]

Implementations MUST support the following event kinds:

| Kind | Description |
|------|-------------|
| `POLICY_CHECK` | A policy evaluation was performed. |
| `POLICY_VIOLATION` | A policy violation was detected and enforcement applied. |
| `TOOL_CALL_BLOCKED` | A tool invocation was blocked by policy. |
| `PROMPT_INJECTION_DETECTED` | A prompt injection attempt was identified. |
| `IDENTITY_VERIFIED` | An agent identity was successfully verified. |
| `IDENTITY_REJECTED` | An agent identity verification failed. |
| `RESOURCE_ACCESS` | An agent accessed a governed resource. |
| `ESCALATION_REQUESTED` | An action was escalated for human review. |
| `CHECKPOINT_CREATED` | A governance checkpoint was created. |
| `ANOMALY_DETECTED` | Anomalous agent behavior was detected. |
| `MCP_TOOL_POISONING` | A Model Context Protocol tool poisoning attempt was detected. |
| `CONTENT_VIOLATION` | Content policy violation detected in agent output or input. |

Implementations MAY extend this enumeration with additional kinds but MUST NOT remove
or rename existing kinds.

### 6.3 Governance Event Schema [Pure Specification]

A Governance Event MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | REQUIRED | Schema version. Currently "1". |
| `event_id` | string | REQUIRED | Unique identifier. Default: uuid4 hex. |
| `occurred_at` | string (ISO 8601 UTC) | REQUIRED | When the event occurred. |
| `kind` | GovernanceEventKind | REQUIRED | Event classification. |
| `severity` | string | OPTIONAL | Event severity. Default: "info". |
| `agent_id` | string | OPTIONAL | Local agent identifier. |
| `agent_did` | string | OPTIONAL | Agent DID for mesh-level correlation. |
| `session_id` | string | OPTIONAL | Session scope identifier. |
| `action` | string | OPTIONAL | Action that triggered the event. |
| `resource` | string | OPTIONAL | Target resource. |
| `decision` | string | OPTIONAL | Governance decision outcome. |
| `reason` | string | OPTIONAL | Human-readable explanation. |
| `policy_name` | string | OPTIONAL | Name of the evaluated policy. |
| `latency_ms` | float | OPTIONAL | Decision latency in milliseconds. |
| `trace_id` | string | OPTIONAL | OTel trace ID. |
| `span_id` | string | OPTIONAL | OTel span ID. |
| `parent_span_id` | string | OPTIONAL | Parent span ID for trace hierarchy. |
| `attributes` | dict | OPTIONAL | Extension attributes. Default: empty dict. |

### 6.4 Event Immutability [Pure Specification]

Governance events MUST be immutable after creation. Implementations MUST use frozen
dataclasses, immutable records, or equivalent language constructs to enforce this.

### 6.5 Event Identity [Pure Specification]

- Each event MUST have a globally unique `event_id`.
- The default generation strategy MUST use UUID v4 (hex encoding without hyphens).
- Implementations MAY use alternative unique ID schemes provided they guarantee
  global uniqueness.

---

## 7. Governance Event Sink SPI

### 7.1 Sink Protocol [Pure Specification]

A Governance Event Sink MUST implement the following interface:

```python
@runtime_checkable
class GovernanceEventSink(Protocol):
    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        """Export a batch of governance events.

        MUST NOT raise exceptions.
        MUST be thread-safe.
        Returns SinkExportResult indicating success, failure, or drop.
        """
        ...

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        """Gracefully shut down the sink.

        SHOULD flush any buffered events before returning.
        Returns True if shutdown completed within timeout.
        """
        ...

    def force_flush(self, timeout_ms: int = 30000) -> bool:
        """Force immediate flush of all buffered events.

        Returns True if flush completed within timeout.
        """
        ...
```

### 7.2 Export Result Codes [Pure Specification]

| Code | Value | Description |
|------|-------|-------------|
| `SUCCESS` | 0 | Events were successfully exported. |
| `FAILURE` | 1 | Export failed; events MAY be retried. |
| `DROPPED` | 2 | Events were intentionally dropped (e.g., circuit breaker open). |

### 7.3 Sink Behavioral Requirements [Pure Specification]

- `emit()` MUST NOT raise exceptions under any circumstances. All errors MUST be
  handled internally and indicated via the return code.
- `emit()` MUST be thread-safe. Multiple threads MAY call emit() concurrently.
- `shutdown()` SHOULD flush buffered events before returning.
- `shutdown()` MUST return within the specified timeout. If flush cannot complete
  in time, the implementation SHOULD return `False` and abandon remaining events.
- `force_flush()` MUST attempt immediate export of all buffered events.

### 7.4 Sink Base Class [Default Implementation]

AGT provides a `GovernanceEventSinkBase` convenience class that implements default
no-op behavior for `shutdown()` and `force_flush()`. Implementations extending this
base class need only implement `emit()`.

### 7.5 Legacy Bridge -- AuditBackendSinkAdapter [Default Implementation]

The `AuditBackendSinkAdapter` bridges the legacy `AuditBackend` protocol to the
`GovernanceEventSink` interface.

- The adapter MUST convert each `GovernanceEvent` to an `AuditEntry` for the wrapped backend.
- Field mapping: `event_id` -> `metadata["event_id"]`, `kind` -> `event_type`,
  `agent_id` -> `agent_id`, `action` -> `action`, `decision` -> `decision`,
  `reason` -> `reason`, `latency_ms` -> `latency_ms`.
- The adapter MUST return `SinkExportResult.SUCCESS` after successful write.

---

## 8. Governance Event Processor

### 8.1 Processing Model [Pure Specification]

The Governance Event Processor MUST implement a BatchSpanProcessor-style pattern:

1. Events are submitted to an internal queue.
2. A dedicated background thread drains the queue in batches.
3. Each batch is exported to all registered sinks.
4. Failed exports trigger circuit-breaker evaluation.

### 8.2 Configuration [Pure Specification]

The processor MUST support the following configuration parameters:

| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Max Queue Size | `AGT_GSP_MAX_QUEUE_SIZE` | 1024 | Maximum events in the internal queue. |
| Schedule Delay | `AGT_GSP_SCHEDULE_DELAY_MS` | 2000 | Milliseconds between batch export cycles. |
| Max Batch Size | `AGT_GSP_MAX_BATCH_SIZE` | 100 | Maximum events per export batch. |
| Export Timeout | `AGT_GSP_EXPORT_TIMEOUT_MS` | 10000 | Timeout for sink export calls. |

### 8.3 Backpressure Policy [Pure Specification]

When the internal queue reaches `max_queue_size`:

- The processor MUST apply a DROP_OLDEST policy, removing the oldest event from the
  queue to make room for the new event.
- Dropped events MUST be counted.
- Implementations SHOULD expose a metric for dropped event count.
- The processor MUST NOT block the caller when the queue is full.

### 8.4 Circuit Breaker [Pure Specification]

The processor MUST implement circuit-breaker semantics for sink exports:

- **Threshold**: After N consecutive export failures (default: 5), the circuit breaker
  MUST open.
- **Cooldown**: While open, the circuit breaker MUST skip export attempts for a
  cooldown period (default: 60 seconds).
- **Half-Open**: After cooldown expires, the next export attempt MUST be allowed.
  If successful, the circuit breaker closes. If failed, it remains open for another
  cooldown period.

### 8.5 Worker Thread [Default Implementation]

- The worker thread MUST be named `"agt-governance-event-processor"`.
- The worker thread MUST be a daemon thread (does not prevent process exit).
- The worker thread MUST wake on either: schedule delay expiry, or queue reaching
  max batch size.
- On shutdown, the worker thread MUST attempt to flush remaining queued events
  within the export timeout.

### 8.6 Lifecycle [Pure Specification]

- `start()` -- Starts the background worker thread.
- `emit(event)` -- Enqueues a single event for batch processing.
- `shutdown(timeout_ms)` -- Signals shutdown, flushes remaining events, stops the worker.
- `force_flush(timeout_ms)` -- Immediately exports all queued events.

---

## 9. Merkle Audit Chain

### 9.1 Purpose [Pure Specification]

The Merkle Audit Chain provides tamper-evident audit logging. Any modification to a
historical audit entry MUST be detectable through hash verification.

### 9.2 Chain Structure [Pure Specification]

Each audit entry in the chain MUST include:

- `previous_hash` -- The `entry_hash` of the immediately preceding entry (or empty
  string for the first entry).
- `entry_hash` -- Computed per Section 4.4.

The chain forms a singly-linked list through hash references, where each entry
cryptographically commits to all preceding entries.

### 9.3 Merkle Tree Construction [Pure Specification]

In addition to the linear chain, implementations MUST maintain a Merkle tree over
entry hashes for efficient proof generation:

- Leaf nodes correspond to individual entry hashes.
- Internal nodes are computed as `SHA-256(left_child_hash || right_child_hash)`.
- The tree MUST be built incrementally as entries are added.

### 9.4 Merkle Node Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hash` | string | REQUIRED | SHA-256 hex digest of the node. |
| `left_child` | string or None | REQUIRED | Hash of the left child node. |
| `right_child` | string or None | REQUIRED | Hash of the right child node. |
| `is_leaf` | bool | REQUIRED | Whether this is a leaf node. |
| `entry_id` | string or None | OPTIONAL | Entry ID (leaf nodes only). |

### 9.5 Proof Generation [Pure Specification]

The `get_proof(entry_id)` method MUST return an inclusion proof consisting of a list
of `(hash, position)` tuples where position is either `"left"` or `"right"`, indicating
which sibling hash to combine at each tree level.

### 9.6 Proof Verification [Pure Specification]

To verify an inclusion proof:

1. Start with the entry's hash.
2. For each `(sibling_hash, position)` in the proof:
   - If position is `"left"`: compute `SHA-256(sibling_hash || current_hash)`
   - If position is `"right"`: compute `SHA-256(current_hash || sibling_hash)`
   - Set current_hash to the result.
3. Compare the final hash against the known root hash.
4. The proof is valid if and only if they match.

### 9.7 Chain Verification [Pure Specification]

The `verify_chain()` method MUST:

1. Iterate all entries in insertion order.
2. For each entry, recompute the hash per Section 4.4.
3. Verify the computed hash matches the stored `entry_hash`.
4. Verify the `previous_hash` matches the preceding entry's `entry_hash`.
5. Return `(True, None)` if the chain is valid.
6. Return `(False, description)` with a human-readable error if verification fails.

### 9.8 Audit Log Wrapper [Default Implementation]

The `AuditLog` class wraps `MerkleAuditChain` and provides:

- Indexing by agent DID and event type for efficient queries.
- Optional `AuditSink` integration for real-time export.
- Methods: `log()`, `get_entry()`, `get_entries_for_agent()`, `get_entries_by_type()`,
  `query()`, `verify_integrity()`, `get_proof()`, `export()`, `export_cloudevents()`.

---

## 10. Compliance Framework Engine

### 10.1 Supported Frameworks [Pure Specification]

Implementations MUST support the following compliance frameworks:

| Framework | Identifier | Description |
|-----------|-----------|-------------|
| EU AI Act | `EU_AI_ACT` | European Union Artificial Intelligence Act |
| SOC 2 | `SOC2` | Service Organization Control 2 |
| HIPAA | `HIPAA` | Health Insurance Portability and Accountability Act |
| GDPR | `GDPR` | General Data Protection Regulation |

Implementations MAY support additional frameworks.

### 10.2 Compliance Control Schema [Pure Specification]

Each compliance control MUST define:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `control_id` | string | REQUIRED | Unique identifier for the control. |
| `framework` | ComplianceFramework | REQUIRED | Parent framework. |
| `name` | string | REQUIRED | Human-readable control name. |
| `description` | string | REQUIRED | Detailed description of the requirement. |
| `category` | string | REQUIRED | Control category (e.g., "Access Control"). |
| `subcategory` | string | OPTIONAL | Control subcategory. |
| `requirements` | list[string] | REQUIRED | Specific requirements that MUST be met. |
| `evidence_types` | list[string] | REQUIRED | Types of evidence that satisfy this control. |

### 10.3 Default Controls [Default Implementation]

The reference implementation includes the following default controls:

**SOC 2:**
- `SOC2-CC6.1` -- Logical and Physical Access Controls
- `SOC2-CC7.2` -- System Monitoring

**HIPAA:**
- `HIPAA-164.312(a)(1)` -- Access Control
- `HIPAA-164.312(b)` -- Audit Controls

**EU AI Act:**
- `EUAI-ART9` -- Risk Management System
- `EUAI-ART13` -- Transparency and Provision of Information

**GDPR:**
- `GDPR-ART5` -- Principles Relating to Processing of Personal Data
- `GDPR-ART22` -- Automated Individual Decision-Making

### 10.4 Compliance Mapping [Pure Specification]

A compliance mapping associates an action type with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action_type` | string | REQUIRED | The type of action (e.g., "agent_registration"). |
| `controls` | list[string] | REQUIRED | Control IDs that apply to this action type. |
| `evidence_generated` | list[string] | REQUIRED | Evidence types produced when this action occurs. |
| `evidence_required` | list[string] | REQUIRED | Evidence types required for compliance. |

### 10.5 Default Mappings [Default Implementation]

| Action Type | Controls | Evidence Generated |
|-------------|----------|-------------------|
| `agent_registration` | SOC2-CC6.1, HIPAA-164.312(a)(1), EUAI-ART9 | identity_verification, access_control_log |
| `data_access` | SOC2-CC7.2, HIPAA-164.312(b), GDPR-ART5 | access_log, data_classification |
| `automated_decision` | EUAI-ART13, GDPR-ART22 | decision_explanation, risk_assessment |
| `supply_chain_audit` | SOC2-CC6.1, EUAI-ART9 | provenance_record, integrity_check |

### 10.6 Compliance Violation [Pure Specification]

A compliance violation MUST record:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `violation_id` | string | REQUIRED | Unique identifier. |
| `timestamp` | datetime (UTC) | REQUIRED | When the violation was detected. |
| `agent_did` | string | REQUIRED | DID of the violating agent. |
| `action_type` | string | REQUIRED | Action type that triggered the violation. |
| `control_id` | string | REQUIRED | Control that was violated. |
| `framework` | ComplianceFramework | REQUIRED | Framework the control belongs to. |
| `severity` | string | OPTIONAL | One of: critical, high, medium, low. Default: "medium". |
| `description` | string | REQUIRED | Human-readable violation description. |
| `evidence` | dict | OPTIONAL | Supporting evidence. |
| `remediated` | bool | OPTIONAL | Whether the violation has been remediated. Default: False. |
| `remediated_at` | datetime or None | OPTIONAL | When remediation occurred. |
| `remediation_notes` | string | OPTIONAL | Notes about the remediation. |

### 10.7 Compliance Report [Pure Specification]

A compliance report MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `report_id` | string | REQUIRED | Unique report identifier. |
| `generated_at` | datetime (UTC) | REQUIRED | Report generation timestamp. |
| `framework` | ComplianceFramework | REQUIRED | Framework being assessed. |
| `period_start` | datetime | REQUIRED | Start of assessment period. |
| `period_end` | datetime | REQUIRED | End of assessment period. |
| `organization_id` | string | OPTIONAL | Organization being assessed. |
| `agents_covered` | list[string] | REQUIRED | Agent DIDs included in assessment. |
| `total_controls` | int | REQUIRED | Total number of controls assessed. |
| `controls_met` | int | REQUIRED | Controls fully satisfied. |
| `controls_partial` | int | REQUIRED | Controls partially satisfied. |
| `controls_failed` | int | REQUIRED | Controls not satisfied. |
| `compliance_score` | float | REQUIRED | Overall score (0--100). |
| `violations` | list[ComplianceViolation] | REQUIRED | Violations during the period. |
| `evidence_items` | list[dict] | REQUIRED | Evidence collected. |
| `recommendations` | list[string] | REQUIRED | Improvement recommendations (max 10). |

### 10.8 Score Calculation [Pure Specification]

The compliance score MUST be computed as:

```
compliance_score = (controls_met / total_controls) * 100
```

Where `controls_met = total_controls - count(violated_controls)`.

A control is considered violated if ANY violation references that control's `control_id`
during the assessment period.

### 10.9 Compliance Check [Pure Specification]

The `check_compliance(action_type, evidence)` method MUST:

1. Look up the compliance mapping for the given action type.
2. Determine which evidence types are required.
3. Check if the provided evidence satisfies all requirements.
4. Return a list of violations for any unsatisfied requirements.

### 10.10 Violation Remediation [Pure Specification]

The `remediate_violation(violation_id, notes)` method MUST:

1. Look up the violation by ID.
2. Set `remediated = True`.
3. Set `remediated_at` to the current UTC timestamp.
4. Set `remediation_notes` to the provided notes.
5. Return the updated violation object.

If the violation ID is not found, the method MUST raise an appropriate error.

---

## 11. Decision Bill of Materials (BOM)

### 11.1 Purpose [Pure Specification]

The Decision BOM enables post-hoc reconstruction of all inputs, context, and outputs
that contributed to a governance decision. This supports regulatory audits, incident
investigation, and compliance evidence generation.

### 11.2 Data Source Protocols [Pure Specification]

The BOM reconstructor MUST interact with four data source types:

#### 11.2.1 AuditSource

```python
@runtime_checkable
class AuditSource(Protocol):
    def query_by_trace(self, trace_id: str, window: tuple) -> list: ...
    def query_by_agent(self, agent_id: str, window: tuple) -> list: ...
```

#### 11.2.2 TrustSource

```python
@runtime_checkable
class TrustSource(Protocol):
    def get_score_at(self, agent_id: str, timestamp: datetime) -> float: ...
    def get_score_history(self, agent_id: str, window: tuple) -> list: ...
```

#### 11.2.3 PolicySource

```python
@runtime_checkable
class PolicySource(Protocol):
    def get_evaluations(self, trace_id: str) -> list: ...
    def get_active_policies_at(self, timestamp: datetime) -> list: ...
```

#### 11.2.4 TraceSource

```python
@runtime_checkable
class TraceSource(Protocol):
    def get_spans(self, trace_id: str) -> list: ...
```

### 11.3 BOM Field Categories [Pure Specification]

Each field in the BOM MUST be classified into one of:

| Category | Description |
|----------|-------------|
| `IDENTITY` | Agent identity and authentication information. |
| `TRUST` | Trust scores, reputation, and vouching data. |
| `POLICY` | Policy rules, evaluations, and configurations. |
| `ACTION` | The requested action and its parameters. |
| `CONTEXT` | Environmental context (session, trace, resources). |
| `OUTCOME` | Decision result and enforcement actions. |
| `LINEAGE` | Causal chain and delegation history. |

### 11.4 BOM Field Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | REQUIRED | Field identifier. |
| `category` | BOMFieldCategory | REQUIRED | Classification category. |
| `value` | any | REQUIRED | The field value. |
| `source` | string | REQUIRED | Which data source provided this value. |
| `confidence` | float | REQUIRED | Confidence score (0.0--1.0). |
| `inferred` | bool | REQUIRED | Whether the value was inferred vs. directly observed. |

### 11.5 Required BOM Fields [Pure Specification]

Every Decision BOM MUST include these fields (completeness score is affected by their presence):

| Field Name | Category | Description |
|------------|----------|-------------|
| `agent_identity` | IDENTITY | The verified identity of the acting agent. |
| `trust_score_at_decision` | TRUST | The agent's trust score at decision time. |
| `policy_rules_evaluated` | POLICY | List of policy rules that were evaluated. |
| `action_type` | ACTION | The type of action requested. |
| `decision_outcome` | OUTCOME | The final governance decision. |

### 11.6 Optional BOM Fields [Pure Specification]

Implementations SHOULD include when available:

| Field Name | Category | Description |
|------------|----------|-------------|
| `delegation_chain` | LINEAGE | Chain of agent delegations leading to this action. |
| `trust_score_trend` | TRUST | Historical trend of the agent's trust score. |
| `similar_past_decisions` | CONTEXT | Related historical decisions for comparison. |
| `resource_target` | ACTION | Specific resource targeted by the action. |
| `session_context` | CONTEXT | Session metadata and state. |
| `cost_incurred` | OUTCOME | Computational or financial cost of the decision. |
| `latency_ms` | OUTCOME | Time taken to reach the decision. |
| `otel_trace_id` | CONTEXT | OpenTelemetry trace ID for distributed correlation. |
| `parent_intent_id` | LINEAGE | Parent intent or goal that spawned this action. |

### 11.7 Decision BOM Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `decision_id` | string | REQUIRED | Unique identifier for this BOM. |
| `timestamp` | datetime (UTC) | REQUIRED | When the decision was made. |
| `agent_id` | string | REQUIRED | Agent that requested the action. |
| `action_requested` | string | REQUIRED | What action was requested. |
| `outcome` | string | REQUIRED | Decision outcome (allow/deny/escalate/warn). |
| `fields` | list[BOMField] | REQUIRED | All collected BOM fields. |
| `reconstructed_at` | datetime (UTC) | REQUIRED | When this BOM was reconstructed. |
| `sources_queried` | list[string] | REQUIRED | Data sources that were consulted. |
| `completeness_score` | float | REQUIRED | Score (0.0--1.0) indicating data completeness. |

### 11.8 Reconstruction Algorithm [Pure Specification]

The `DecisionBOMReconstructor` MUST implement a 4-phase reconstruction:

1. **Phase 1 -- Audit Query**: Query the `AuditSource` for events within a time window
   (default: +/- 5.0 seconds) around the decision timestamp, filtered by trace ID or
   agent ID.

2. **Phase 2 -- Trust Enrichment**: Query the `TrustSource` for the agent's trust score
   at decision time and recent score history.

3. **Phase 3 -- Policy Enrichment**: Query the `PolicySource` for policy evaluations
   associated with the trace, and active policies at the time.

4. **Phase 4 -- Trace Enrichment**: Query the `TraceSource` for OTel spans associated
   with the trace ID.

After all phases, compute the `completeness_score` as the fraction of REQUIRED_FIELDS
that were successfully populated.

### 11.9 Batch Reconstruction [Pure Specification]

The `reconstruct_batch(decisions)` method MUST:

- Accept a list of decision references.
- Reconstruct each BOM independently.
- Return a list of `DecisionBOM` objects.
- Individual failures MUST NOT prevent reconstruction of other BOMs in the batch.

---

## 12. Hypervisor Event Bus

### 12.1 Purpose [Pure Specification]

The Hypervisor Event Bus provides a centralized pub/sub mechanism for distributing
observability events within the Agent Hypervisor. All hypervisor subsystems (session
management, ring security, saga coordination, VFS operations) MUST publish events
through this bus.

### 12.2 Event Types [Pure Specification]

The event bus MUST support the following event type categories:

#### 12.2.1 Session Events

| Event Type | Description |
|------------|-------------|
| `SESSION_CREATED` | A new session was created. |
| `SESSION_JOINED` | An agent joined an existing session. |
| `SESSION_ACTIVATED` | A session became active. |
| `SESSION_TERMINATED` | A session was terminated. |
| `SESSION_ARCHIVED` | A session was archived for long-term storage. |

#### 12.2.2 Ring Security Events

| Event Type | Description |
|------------|-------------|
| `RING_ASSIGNED` | An agent was assigned a security ring level. |
| `RING_ELEVATED` | An agent's ring level was elevated (more privileges). |
| `RING_DEMOTED` | An agent's ring level was demoted (fewer privileges). |
| `RING_ELEVATION_EXPIRED` | A temporary ring elevation expired. |
| `RING_BREACH_DETECTED` | An agent attempted to exceed ring boundaries. |

#### 12.2.3 Trust Events

| Event Type | Description |
|------------|-------------|
| `VOUCH_CREATED` | A trust vouch was created between agents. |
| `VOUCH_RELEASED` | A trust vouch was released/revoked. |
| `SLASH_EXECUTED` | A trust penalty was applied to an agent. |
| `FAULT_ATTRIBUTED` | A fault was attributed to a specific agent. |

#### 12.2.4 Quarantine Events

| Event Type | Description |
|------------|-------------|
| `QUARANTINE_ENTERED` | An agent was quarantined. |
| `QUARANTINE_RELEASED` | An agent was released from quarantine. |

#### 12.2.5 Saga Coordination Events

| Event Type | Description |
|------------|-------------|
| `SAGA_CREATED` | A new saga was created. |
| `SAGA_STEP_STARTED` | A saga step began execution. |
| `SAGA_STEP_COMMITTED` | A saga step was committed. |
| `SAGA_STEP_FAILED` | A saga step failed. |
| `SAGA_COMPENSATING` | A saga entered compensation mode. |
| `SAGA_COMPLETED` | A saga completed successfully. |
| `SAGA_ESCALATED` | A saga was escalated for human intervention. |
| `SAGA_FANOUT_STARTED` | A saga fan-out operation began. |
| `SAGA_FANOUT_RESOLVED` | A saga fan-out operation resolved. |
| `SAGA_CHECKPOINT_SAVED` | A saga checkpoint was saved. |
| `SAGA_HANDOFF` | A saga step was handed off to another agent. |

#### 12.2.6 VFS Events

| Event Type | Description |
|------------|-------------|
| `VFS_WRITE` | A file was written in the virtual filesystem. |
| `VFS_DELETE` | A file was deleted from the virtual filesystem. |
| `VFS_SNAPSHOT` | A VFS snapshot was taken. |
| `VFS_RESTORE` | A VFS state was restored from snapshot. |
| `VFS_CONFLICT` | A VFS write conflict was detected. |

#### 12.2.7 Enforcement Events

| Event Type | Description |
|------------|-------------|
| `RATE_LIMITED` | An agent was rate-limited. |
| `AGENT_KILLED` | An agent process was forcefully terminated. |

#### 12.2.8 Audit Events

| Event Type | Description |
|------------|-------------|
| `AUDIT_DELTA_CAPTURED` | A semantic delta was captured. |
| `AUDIT_DELTA_COMMITTED` | A delta was committed to the chain. |
| `AUDIT_GC_COLLECTED` | Old audit data was garbage-collected. |

#### 12.2.9 Behavioral Events

| Event Type | Description |
|------------|-------------|
| `BEHAVIOR_DRIFT` | Behavioral drift was detected in an agent. |
| `HISTORY_VERIFIED` | Agent history was cryptographically verified. |
| `IDENTITY_VERIFIED` | Agent identity was verified. |

### 12.3 Hypervisor Event Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_id` | string | REQUIRED | Unique ID. Format: uuid4 hex truncated to 16 chars. |
| `event_type` | EventType | REQUIRED | Event classification. |
| `timestamp` | float | REQUIRED | Unix timestamp (time.time()). |
| `session_id` | string | OPTIONAL | Associated session. |
| `agent_did` | string | OPTIONAL | Associated agent DID. |
| `causal_trace_id` | string | OPTIONAL | Causal trace for event correlation. |
| `parent_event_id` | string | OPTIONAL | ID of the event that caused this event. |
| `payload` | dict | OPTIONAL | Event-specific data. |

### 12.4 Event Immutability [Pure Specification]

Hypervisor events MUST be frozen/immutable after creation. The implementation MUST
use frozen dataclasses or equivalent.

### 12.5 Event Bus Capacity [Pure Specification]

- The event bus MUST maintain a bounded event history.
- The default maximum event count MUST be 100,000.
- When capacity is reached, oldest events MUST be evicted (circular buffer semantics).
- Implementations MUST use thread-safe data structures (e.g., RLock + deque).

### 12.6 Subscription Model [Pure Specification]

- Subscribers register a callback for specific event types.
- The bus MUST support wildcard subscriptions (receive all events).
- Callbacks MUST be invoked synchronously in the publishing thread.
- Callback exceptions MUST NOT prevent delivery to other subscribers.
- Callbacks MUST NOT block for extended periods (best-effort guidance).

### 12.7 Query Interface [Pure Specification]

The event bus MUST support the following query methods:

| Method | Parameters | Description |
|--------|-----------|-------------|
| `query_by_type(event_type)` | EventType | Return all events of a given type. |
| `query_by_session(session_id)` | string | Return all events for a session. |
| `query_by_agent(agent_did)` | string | Return all events for an agent. |
| `query_by_time_range(start, end)` | float, float | Return events within a time window. |
| `query(filters)` | dict | Multi-filter query combining any of the above. |

---

## 13. Semantic Delta Engine

### 13.1 Purpose [Pure Specification]

The Semantic Delta Engine captures cryptographically-chained records of all VFS
(Virtual File System) changes within a hypervisor session. Each turn produces a
delta that chains to the previous turn's delta, forming a verifiable history of
all file modifications made by governed agents.

### 13.2 VFS Change Record [Pure Specification]

Each individual file change MUST record:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | REQUIRED | VFS path of the affected file. |
| `operation` | string | REQUIRED | Type of operation (write, delete, rename, etc.). |
| `content_hash` | string | REQUIRED | SHA-256 hash of the new file content. |
| `previous_hash` | string | OPTIONAL | SHA-256 hash of the previous content (for writes). |
| `agent_did` | string | REQUIRED | DID of the agent that made the change. |

### 13.3 Semantic Delta Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `delta_id` | string | REQUIRED | Unique identifier for this delta. |
| `turn_id` | int | REQUIRED | Monotonically increasing turn counter within the session. |
| `session_id` | string | REQUIRED | Session scope. |
| `agent_did` | string | REQUIRED | Agent that produced this delta. |
| `timestamp` | float | REQUIRED | Unix timestamp of delta creation. |
| `changes` | list[VFSChange] | REQUIRED | List of file changes in this turn. |
| `parent_hash` | string | REQUIRED | Hash of the previous delta (empty for first). |
| `delta_hash` | string | REQUIRED | Hash of this delta's canonical form. |

### 13.4 Delta Hash Computation [Pure Specification]

The delta hash MUST be computed as:

1. Construct a dictionary with: `delta_id`, `turn_id`, `session_id`, `agent_did`,
   `timestamp`, `changes` (serialized), `parent_hash`.
2. Serialize to JSON with sorted keys.
3. Compute SHA-256 of the UTF-8 encoded JSON.
4. Encode as lowercase hex string.

### 13.5 Chain Integrity [Pure Specification]

- Each delta MUST reference the hash of the immediately preceding delta via `parent_hash`.
- The first delta in a session MUST have `parent_hash` set to empty string.
- `verify_chain()` MUST recompute all hashes and verify parent references.
- `verify_chain()` MUST return `(True, None)` on success or `(False, description)` on failure.

### 13.6 Turn Counter [Pure Specification]

- The turn counter MUST start at 0 or 1 (implementation-defined) and increment by 1
  for each `capture()` call.
- The counter is session-scoped and MUST reset for each new session.
- Implementations MUST NOT allow gaps in the turn sequence.

---

## 14. Commitment Engine

### 14.1 Purpose [Pure Specification]

The Commitment Engine produces summary records that anchor a session's delta chain,
enabling third-party verification without requiring access to the full delta history.

### 14.2 Commitment Record Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | string | REQUIRED | The session being committed. |
| `hash_chain_root` | string | REQUIRED | Root hash of the session's delta chain. |
| `participant_dids` | list[string] | REQUIRED | DIDs of all agents in the session. |
| `delta_count` | int | REQUIRED | Number of deltas in the committed chain. |
| `committed_at` | datetime (UTC) | REQUIRED | Timestamp of commitment creation. |
| `blockchain_tx_id` | string or None | OPTIONAL | External blockchain transaction ID. |
| `committed_to` | string | REQUIRED | Where the commitment was anchored. Default: "local". |

### 14.3 Commitment Operations [Pure Specification]

#### 14.3.1 commit(session_id, delta_engine)

- Extracts the current chain root hash from the delta engine.
- Collects participant DIDs from the delta chain.
- Creates and stores a `CommitmentRecord`.
- Returns the commitment record.

#### 14.3.2 verify(session_id, delta_engine)

- Retrieves the stored commitment for the session.
- Recomputes the chain root hash from the current delta engine state.
- Compares against the stored `hash_chain_root`.
- Returns `True` if they match, `False` otherwise.
- MUST return `False` if no commitment exists for the session.

#### 14.3.3 queue_for_batch()

- Queues the commitment for batch external anchoring.
- Implementations MAY batch multiple commitments for efficiency.

#### 14.3.4 flush_batch()

- Attempts to anchor all queued commitments to the configured external store.
- In the current implementation (Public Preview), this is a no-op that sets
  `committed_to = "local"`.

### 14.4 External Anchoring [Pure Specification]

- Implementations MAY anchor commitments to external systems (blockchains, timestamping
  services, transparency logs).
- When external anchoring succeeds, `blockchain_tx_id` MUST be set to the transaction
  identifier and `committed_to` MUST identify the external system.
- External anchoring failure MUST NOT invalidate the local commitment.
- The current AGT implementation (Public Preview) does NOT perform external anchoring.

---

## 15. Audit Collector REST API

### 15.1 Purpose [Pure Specification]

The Audit Collector provides an HTTP REST API for centralized audit log ingestion,
querying, and verification. It serves as the network-accessible entry point for
audit data from distributed AGT components.

### 15.2 Base Configuration [Default Implementation]

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| Data Directory | `AGENTMESH_AUDIT_DATA_DIR` | `/data/audit` | Storage location for audit data. |
| Retention Days | `AGENTMESH_AUDIT_RETENTION_DAYS` | 90 | Days to retain audit entries. |
| Port | (deployment config) | 8445 | Default listening port. |

### 15.3 API Endpoints [Pure Specification]

#### 15.3.1 POST /api/v1/audit/log

Submit a single audit entry.

**Request Body:**
```json
{
  "event_type": "string (required)",
  "agent_did": "string (required)",
  "action": "string (required)",
  "resource": "string (optional)",
  "target_did": "string (optional)",
  "data": "object (optional)",
  "outcome": "string (optional, default: 'success')",
  "policy_decision": "string (optional)",
  "matched_rule": "string (optional)",
  "trace_id": "string (optional)",
  "session_id": "string (optional)"
}
```

**Response (201 Created):**
```json
{
  "entry_id": "audit_<hex16>",
  "entry_hash": "<sha256_hex>",
  "timestamp": "<ISO 8601 UTC>"
}
```

**Requirements:**
- The server MUST assign an `entry_id` and compute the `entry_hash`.
- The server MUST chain the entry to the previous entry's hash.
- The server MUST return 201 on successful creation.
- The server MUST return 422 if required fields are missing.

#### 15.3.2 POST /api/v1/audit/batch

Submit multiple audit entries in a single request.

**Request Body:**
```json
{
  "entries": [
    { /* same schema as /log */ },
    { /* ... */ }
  ]
}
```

**Response (201 Created):**
```json
{
  "results": [
    { "entry_id": "...", "entry_hash": "...", "timestamp": "..." },
    { /* ... */ }
  ],
  "count": 5
}
```

**Requirements:**
- Entries MUST be processed in order.
- Each entry MUST be chained to the previous.
- Partial failures SHOULD be reported per-entry.

#### 15.3.3 POST /api/v1/audit/query

Query audit entries with filters.

**Request Body:**
```json
{
  "agent_did": "string (optional)",
  "event_type": "string (optional)",
  "start_time": "ISO 8601 (optional)",
  "end_time": "ISO 8601 (optional)",
  "session_id": "string (optional)",
  "limit": "int (optional, default: 100)",
  "offset": "int (optional, default: 0)"
}
```

**Response (200 OK):**
```json
{
  "entries": [ /* array of AuditEntry objects */ ],
  "total": 42,
  "limit": 100,
  "offset": 0
}
```

#### 15.3.4 GET /api/v1/audit/verify

Verify the integrity of the audit chain.

**Response (200 OK):**
```json
{
  "valid": true,
  "entries_verified": 1000,
  "root_hash": "<sha256_hex>",
  "verified_at": "<ISO 8601 UTC>"
}
```

**Response (409 Conflict -- integrity violation):**
```json
{
  "valid": false,
  "entries_verified": 500,
  "error": "Hash mismatch at entry audit_abc123",
  "failed_entry_id": "audit_abc123"
}
```

#### 15.3.5 GET /api/v1/audit/summary

Retrieve summary statistics for the audit log.

**Response (200 OK):**
```json
{
  "total_entries": 10000,
  "agents_tracked": 25,
  "event_types": ["tool_invocation", "policy_evaluation", "..."],
  "earliest_entry": "<ISO 8601>",
  "latest_entry": "<ISO 8601>",
  "chain_valid": true
}
```

### 15.4 Authentication and Authorization [Pure Specification]

- The API SHOULD require authentication for all endpoints.
- Implementations MUST support bearer token authentication.
- Write endpoints (log, batch) SHOULD require a role with audit-write permissions.
- Read endpoints (query, verify, summary) SHOULD require a role with audit-read permissions.
- The specific authentication mechanism is deployment-defined.

### 15.5 Rate Limiting [Pure Specification]

- Implementations SHOULD implement rate limiting on all endpoints.
- Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
  SHOULD be included in responses.
- When rate-limited, the server MUST return HTTP 429.

---

## 16. OpenTelemetry Integration

### 16.1 Purpose [Pure Specification]

AGT MUST integrate with OpenTelemetry (OTel) to enable standard observability
tooling, distributed tracing, and log correlation. The OTel integration provides
a bridge between AGT's governance-specific audit model and the broader observability
ecosystem.

### 16.2 OTel Logs Backend [Pure Specification]

The OTel Logs Backend MUST:

- Emit audit entries as OTel LogRecords.
- Use severity level INFO for standard audit entries.
- Be a no-op when the OpenTelemetry SDK is not installed (graceful degradation).
- Conform to the `AuditBackend` protocol.

### 16.3 Attribute Namespace [Pure Specification]

All AGT-specific OTel attributes MUST use the `agt.*` namespace prefix:

| Attribute Key | Source Field | Description |
|---------------|-------------|-------------|
| `agt.audit.event_type` | event_type | Audit event type. |
| `agt.audit.action` | action | The audited action. |
| `agt.audit.decision` | decision | Governance decision. |
| `agt.audit.reason` | reason | Decision reason. |
| `agt.audit.latency_ms` | latency_ms | Decision latency. |
| `agt.agent.id` | agent_id | Agent identifier. |
| `agt.audit.meta.*` | metadata[key] | Promoted metadata keys. |

### 16.4 Event Domain and Name [Pure Specification]

OTel LogRecords emitted by the audit backend MUST set:

- `event.domain` = `"agent_os.governance"`
- `event.name` = `"audit_entry"`

### 16.5 Logger and Service Configuration [Default Implementation]

| Setting | Default Value | Description |
|---------|--------------|-------------|
| Logger Name | `"agent_os.governance.audit"` | OTel logger provider name. |
| Service Name | `"agent-governance-toolkit"` | OTel resource service name. |

### 16.6 Metadata Promotion [Pure Specification]

Metadata keys from the audit entry MUST be promoted to OTel attributes using the
pattern `agt.audit.meta.{key}`. For example, a metadata entry `{"request_id": "abc"}`
MUST be emitted as attribute `agt.audit.meta.request_id = "abc"`.

### 16.7 Conditional Import [Default Implementation]

The OTel backend MUST handle the absence of the `opentelemetry` package gracefully:

- If `opentelemetry` is not installed, the backend MUST be a no-op.
- No import errors MUST propagate to calling code.
- The backend MAY log a warning on first use indicating OTel is unavailable.

---

## 17. Structured Logging

### 17.1 Purpose [Pure Specification]

AGT MUST provide structured JSON logging for all governance events. Structured logs
enable machine parsing, log aggregation, and correlation with the broader audit trail.

### 17.2 JSON Log Format [Pure Specification]

Each log line MUST be a valid JSON object containing at minimum:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string (ISO 8601) | REQUIRED | When the log was emitted. |
| `level` | string | REQUIRED | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). |
| `logger` | string | REQUIRED | Logger name / source component. |
| `message` | string | REQUIRED | Human-readable log message. |

### 17.3 Governance Extension Fields [Pure Specification]

Governance-specific log entries SHOULD include:

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Acting agent identifier. |
| `action` | string | Action being performed. |
| `decision` | string | Governance decision. |
| `policy_name` | string | Evaluated policy name. |
| `duration_ms` | float | Operation duration. |
| `request_id` | string | Request correlation ID. |
| `error_code` | string | Error classification code. |

### 17.4 Governance Logger Methods [Pure Specification]

A conforming Governance Logger MUST provide methods for common governance events:

| Method | Description |
|--------|-------------|
| `policy_decision()` | Log a policy evaluation result. |
| `policy_violation()` | Log a policy violation. |
| `budget_warning()` | Log a resource budget warning. |
| `adapter_call()` | Log an LLM adapter invocation. |
| `audit_event()` | Log a generic audit event. |
| `error()` | Log an error with governance context. |

### 17.5 Logger Factory [Pure Specification]

- Implementations MUST provide a `get_logger(name)` factory function.
- The factory MUST return cached logger instances (same name = same instance).
- Logger creation MUST be thread-safe.

### 17.6 JSON Formatter [Default Implementation]

The reference implementation provides a `JSONFormatter` class that:

- Formats Python LogRecords as single-line JSON.
- Extracts governance extension fields from the LogRecord's extra dictionary.
- Omits None/empty fields to reduce log volume.
- Is compatible with Python's standard `logging` module.

---

## 18. Agent Lightning Observability

### 18.1 Purpose [Pure Specification]

Agent Lightning provides real-time observability of agent execution through flight
recording and span emission. The system captures policy checks, signals, and tool
calls during agent runs, converting them into a trace-compatible format.

### 18.2 Lightning Span Schema [Pure Specification]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `span_id` | string | REQUIRED | Unique span identifier. |
| `trace_id` | string | REQUIRED | Trace identifier for correlation. |
| `name` | string | REQUIRED | Span name (operation description). |
| `start_time` | float | REQUIRED | Unix timestamp of span start. |
| `end_time` | float | OPTIONAL | Unix timestamp of span end. |
| `attributes` | dict | OPTIONAL | Span attributes. |
| `events` | list | OPTIONAL | Span events (annotations). |

### 18.3 Flight Recorder Emitter [Pure Specification]

The emitter MUST:

- Adapt flight recorder entries to the Lightning Span format.
- Support filtering by entry type: policy checks, signals, tool calls.
- Provide a cursor-based `get_new_spans()` method for incremental consumption.
- Support async streaming via `stream()` (async iterator).
- Compute violation summaries via `get_violation_summary()`.
- Compute execution statistics via `get_stats()`.

### 18.4 Emitter Configuration [Pure Specification]

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_policy_checks` | bool | True | Include policy check spans. |
| `include_signals` | bool | True | Include signal spans. |
| `include_tool_calls` | bool | True | Include tool call spans. |
| `trace_id_prefix` | string | "agentos" | Prefix for generated trace IDs. |

### 18.5 Attribute Namespace [Pure Specification]

Agent Lightning spans MUST use the `agent_os.*` attribute namespace for
AGT-specific attributes.

### 18.6 Export Methods [Pure Specification]

| Method | Description |
|--------|-------------|
| `get_spans()` | Return all spans since emitter creation. |
| `get_new_spans()` | Return spans since last cursor position. |
| `stream()` | Async iterator yielding spans as they arrive. |
| `emit_to_store()` | Write spans to a configured store. |
| `export_to_file()` | Export spans to a file. |
| `get_violation_summary()` | Summarize violations by type and severity. |
| `get_stats()` | Return execution statistics. |

---

## 19. RL Environment Violation Tracking

### 19.1 Purpose [Pure Specification]

The Governed Environment integrates policy enforcement with reinforcement learning
training loops. Violations of governance policies during RL training MUST be tracked,
penalized, and reported to enable safe agent learning.

### 19.2 Environment Configuration [Pure Specification]

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_steps` | int | 100 | Maximum steps per episode before termination. |
| `violation_penalty` | float | -10.0 | Base penalty for policy violations. |
| `terminate_on_critical` | bool | True | Whether critical violations terminate the episode. |
| `step_penalty` | float | -0.1 | Per-step penalty to encourage efficiency. |
| `success_bonus` | float | 10.0 | Bonus reward for successful episode completion. |
| `reset_kernel_state` | bool | True | Whether to reset state on episode reset. |

### 19.3 Violation Handling [Pure Specification]

When a policy violation occurs during a step:

1. The environment MUST record the violation with: `policy` name, `description`,
   `severity`, `blocked` status, `step` number, and `timestamp`.
2. The environment MUST apply a penalty to the reward signal.
3. Penalty scaling by severity:
   - **critical**: `violation_penalty * 10`
   - **high**: `violation_penalty * 5`
   - **medium**: `violation_penalty * 1` (base penalty)
   - **low**: `violation_penalty * 0.5` (RECOMMENDED)
4. If `terminate_on_critical` is True and severity is "critical", the episode
   MUST be terminated immediately.
5. Blocked violations (where the action was prevented) SHOULD receive a reduced
   penalty compared to unblocked violations that succeeded.

### 19.4 Gym-Compatible Interface [Pure Specification]

The Governed Environment MUST implement:

- `step(action) -> (observation, reward, terminated, truncated, info)` -- Execute one
  step with governance checks.
- `reset() -> (observation, info)` -- Reset the environment to initial state, clearing
  violation history for the new episode.

### 19.5 Metrics Collection [Pure Specification]

The environment MUST track and report:

| Metric | Description |
|--------|-------------|
| `total_episodes` | Total number of episodes completed. |
| `total_steps` | Total steps across all episodes. |
| `total_violations` | Total policy violations across all episodes. |
| `successful_episodes` | Episodes that completed without critical violations. |
| `success_rate` | Fraction of successful episodes. |
| `violations_per_episode` | Average violations per episode. |
| `steps_per_episode` | Average steps per episode. |

### 19.6 Violation Record Schema [Pure Specification]

Each violation MUST be stored as a dictionary with:

```json
{
  "policy": "string -- name of the violated policy",
  "description": "string -- human-readable violation description",
  "severity": "string -- critical|high|medium|low",
  "blocked": "bool -- whether the action was prevented",
  "step": "int -- step number when violation occurred",
  "timestamp": "float -- Unix timestamp"
}
```

---

## 20. Cross-Component Correlation

### 20.1 Purpose [Pure Specification]

Events from different AGT components MUST be correlatable to reconstruct complete
governance narratives across component boundaries. This section specifies the
correlation identifiers and strategies.

### 20.2 Primary Correlation Identifiers [Pure Specification]

| Identifier | Scope | Components | Description |
|------------|-------|------------|-------------|
| `trace_id` | Distributed | All | OTel trace ID linking related operations. |
| `session_id` | Session | OS, Mesh, Hypervisor | Governance session scope. |
| `agent_did` | Agent | Mesh, Hypervisor | Decentralized agent identity. |
| `agent_id` | Agent (local) | OS, Lightning | Local agent identifier. |
| `causal_trace_id` | Causal chain | Hypervisor | Links causally-related events. |
| `parent_event_id` | Event chain | Hypervisor | Direct causal parent. |

### 20.3 Correlation Strategies [Pure Specification]

#### 20.3.1 Trace-Based Correlation

- All components that create governance events SHOULD propagate the OTel trace ID.
- When a governance decision spans multiple components, all resulting events MUST
  share the same trace ID.
- Decision BOMs MUST be reconstructable from a single trace ID.

#### 20.3.2 Session-Based Correlation

- All events within a governance session MUST carry the same `session_id`.
- Session IDs MUST be unique across the system.
- Cross-session references SHOULD use the trace ID rather than session ID.

#### 20.3.3 Agent-Based Correlation

- Agent Mesh and Hypervisor MUST use `agent_did` for cross-component agent correlation.
- Agent OS and Lightning MUST use `agent_id` (local scope).
- Implementations SHOULD maintain a mapping between `agent_id` and `agent_did`.

#### 20.3.4 Causal Correlation

- The Hypervisor event bus MUST support causal tracing via `causal_trace_id` and
  `parent_event_id`.
- Events that directly cause other events MUST populate `parent_event_id`.
- Events that share a causal chain MUST share the same `causal_trace_id`.

### 20.4 CloudEvents Mapping [Pure Specification]

Agent Mesh audit entries MUST be exportable as CloudEvents (specversion 1.0) with:

| CloudEvents Field | Source | Description |
|-------------------|--------|-------------|
| `specversion` | "1.0" | CloudEvents version. |
| `type` | Mapped from event_type | See type mapping table below. |
| `source` | Component URI | Originating component. |
| `id` | entry_id | Unique event identifier. |
| `time` | timestamp | ISO 8601 timestamp. |
| `datacontenttype` | "application/json" | Payload format. |
| `data` | Entry data | Serialized entry content. |

#### CloudEvents Type Mapping [Default Implementation]

| Event Type | CloudEvents Type |
|------------|-----------------|
| `tool_invocation` | `ai.agentmesh.tool.invoked` |
| `tool_blocked` | `ai.agentmesh.tool.blocked` |
| `policy_evaluation` | `ai.agentmesh.policy.evaluation` |
| `identity_verification` | `ai.agentmesh.identity.verified` |
| `data_access` | `ai.agentmesh.data.accessed` |
| `delegation` | `ai.agentmesh.delegation.created` |

#### CloudEvents Extensions [Pure Specification]

| Extension | Source | Description |
|-----------|--------|-------------|
| `agentmeshentryhash` | entry_hash | Cryptographic hash of the entry. |
| `agentmeshprevioushash` | previous_hash | Hash chain link. |
| `traceid` | trace_id | OTel trace correlation (optional). |
| `sessionid` | session_id | Session correlation (optional). |

---

## 21. Security & Threat Model

### 21.1 Audit System Security Properties [Pure Specification]

The AGT audit system MUST provide:

1. **Tamper Evidence** -- Any modification to historical audit entries MUST be
   detectable through hash chain verification.
2. **Non-Repudiation** -- Audit entries MUST cryptographically bind to agent identities.
3. **Completeness** -- All governance-relevant actions MUST be audited.
4. **Availability** -- Audit capture MUST NOT be bypassable by governed agents.
5. **Confidentiality** -- Audit data MUST be protected against unauthorized access.

### 21.2 Threat Categories

#### 21.2.1 Audit Tampering

**Threat**: An adversary modifies historical audit entries to conceal malicious activity.

**Mitigations**:
- Hash chain (Section 9) provides tamper evidence.
- Merkle proofs enable efficient verification of individual entries.
- Commitment engine (Section 14) enables external anchoring for third-party verification.
- File permissions (`0o600`) restrict local file access.

#### 21.2.2 Audit Evasion

**Threat**: A governed agent performs actions without generating audit entries.

**Mitigations**:
- Audit logging is integrated into the governance decision path -- actions cannot
  be authorized without audit capture.
- The event processor operates in the governance critical path.
- Gap detection via sequential entry IDs and turn counters.

#### 21.2.3 Audit Flooding

**Threat**: An adversary generates excessive audit events to exhaust storage or mask
real events.

**Mitigations**:
- Bounded event queues with DROP_OLDEST policy (Section 8.3).
- Rate limiting on the audit collector API (Section 15.5).
- Circuit breaker prevents cascade failures (Section 8.4).
- Event bus capacity limits (Section 12.5).

#### 21.2.4 Timing Attacks on Verification

**Threat**: An adversary uses timing differences in hash comparison to forge entries.

**Mitigations**:
- Hash verification MUST use timing-safe comparison (`hmac.compare_digest`).
- All hash comparisons in the Merkle chain MUST be constant-time.

#### 21.2.5 Replay Attacks

**Threat**: An adversary replays legitimate audit entries to create false records.

**Mitigations**:
- Unique `entry_id` / `event_id` per entry prevents exact replays.
- Hash chain binding means replayed entries break chain continuity.
- Monotonic turn counters in the delta engine detect insertions.

#### 21.2.6 Denial of Service on Audit Pipeline

**Threat**: An adversary overwhelms the audit pipeline to prevent legitimate auditing.

**Mitigations**:
- Non-blocking audit capture (Section 3.6).
- Circuit breaker on export failures (Section 8.4).
- Bounded queues prevent memory exhaustion (Section 8.3).
- Backend isolation -- one backend failure does not affect others (Section 5.6).

### 21.3 Cryptographic Requirements [Pure Specification]

- All hash computations MUST use SHA-256.
- All hash comparisons MUST be timing-safe.
- JSON canonicalization for hashing MUST use sorted keys with no extra whitespace.
- Implementations MUST NOT use MD5, SHA-1, or other deprecated hash algorithms
  for audit integrity purposes.

### 21.4 Access Control [Pure Specification]

- Audit files on disk MUST have restrictive permissions (POSIX: `0o600`).
- Audit API endpoints MUST require authentication (Section 15.4).
- Write access to audit data MUST be limited to the audit subsystem itself.
- Governed agents MUST NOT have direct write access to audit storage.

### 21.5 Data Protection [Pure Specification]

- Audit entries MAY contain sensitive information (action parameters, decision reasons).
- Implementations SHOULD support field-level encryption for sensitive metadata.
- Retention policies (Section 15.2) MUST be enforced automatically.
- Data purging MUST maintain chain integrity (e.g., by retaining hashes even when
  content is purged).

---

## 22. Deployment & Operations

### 22.1 Deployment Topologies [Pure Specification]

AGT audit components MAY be deployed in the following topologies:

#### 22.1.1 Embedded (Single-Process)

All audit components run within the same process as the governed agent.

- RECOMMENDED for development and testing.
- Uses in-memory backends and local file storage.
- No network dependencies.

#### 22.1.2 Sidecar

The audit collector runs as a sidecar container alongside the agent.

- RECOMMENDED for container-based deployments.
- Provides network isolation between agent and audit storage.
- Supports independent scaling of audit collection.

#### 22.1.3 Centralized

A dedicated audit service receives events from multiple agents.

- RECOMMENDED for production multi-agent deployments.
- Enables centralized verification and compliance reporting.
- Requires network connectivity between agents and the collector.

### 22.2 Storage Backends [Pure Specification]

Implementations MUST support at least one persistent storage backend. The following
backends are defined:

| Backend | Persistence | Use Case |
|---------|------------|----------|
| JSONL File | Local disk | Development, single-node production. |
| In-Memory | None (volatile) | Testing only. |
| OTel Export | External (via OTel) | Integration with observability platforms. |
| REST API | Remote | Centralized multi-agent deployments. |

### 22.3 Retention Management [Pure Specification]

- Implementations MUST support configurable retention periods.
- The default retention period MUST be 90 days.
- Expired entries MUST be purged automatically.
- Purging MUST NOT break hash chain integrity (retain chain hashes).
- Implementations SHOULD support archival to cold storage before purging.

### 22.4 Monitoring [Pure Specification]

Operators MUST be able to monitor:

| Metric | Description |
|--------|-------------|
| `agt.audit.entries_written` | Total audit entries written (counter). |
| `agt.audit.entries_dropped` | Entries dropped due to backpressure (counter). |
| `agt.audit.queue_depth` | Current event processor queue depth (gauge). |
| `agt.audit.export_latency_ms` | Time to export a batch to sinks (histogram). |
| `agt.audit.chain_valid` | Whether the chain is currently valid (gauge, 0/1). |
| `agt.audit.circuit_breaker_state` | Circuit breaker state (gauge: 0=closed, 1=open). |
| `agt.compliance.score` | Current compliance score per framework (gauge). |
| `agt.compliance.violations` | Total compliance violations (counter). |

### 22.5 High Availability [Pure Specification]

For production deployments:

- The audit collector SHOULD support horizontal scaling behind a load balancer.
- Multiple collector instances MUST coordinate to maintain a single, consistent
  hash chain (implementation-defined coordination mechanism).
- Implementations SHOULD support write-ahead logging or equivalent durability
  mechanisms.
- Audit capture MUST NOT be a single point of failure for the governance system.

### 22.6 Performance Requirements [Pure Specification]

- Audit entry creation MUST complete in under 1 millisecond (excluding backend I/O).
- The event processor MUST handle at least 10,000 events per second throughput.
- Hash computation MUST complete in under 100 microseconds per entry.
- API response times for single-entry log SHOULD be under 50 milliseconds (p99).
- Compliance report generation MAY take longer for large datasets (no strict bound).

### 22.7 Disaster Recovery [Pure Specification]

- Implementations SHOULD support audit data backup and restore.
- Chain verification MUST succeed after restore from backup.
- Commitment records enable verification without the full chain (Section 14).
- External anchoring provides additional recovery evidence.

---

## 23. Conformance Levels

### 23.1 Level Definitions [Pure Specification]

This specification defines three conformance levels:

#### 23.1.1 Level 1 -- Basic Audit

An implementation at Level 1 MUST:

- Implement the `AuditBackend` protocol (Section 5).
- Produce audit entries conforming to the canonical schema (Section 4).
- Support at least one persistent backend.
- Implement the `GovernanceAuditLogger` multi-backend fan-out (Section 5.6).
- Provide structured JSON logging (Section 17).

#### 23.1.2 Level 2 -- Governance Events

An implementation at Level 2 MUST satisfy Level 1 AND:

- Implement the `GovernanceEventSink` SPI (Section 7).
- Implement the `GovernanceEventProcessor` with batching and circuit breaker (Section 8).
- Support all `GovernanceEventKind` values (Section 6.2).
- Provide OpenTelemetry integration (Section 16).
- Support cross-component correlation via trace IDs (Section 20).

#### 23.1.3 Level 3 -- Full Compliance

An implementation at Level 3 MUST satisfy Level 2 AND:

- Implement the Merkle Audit Chain (Section 9).
- Implement the Compliance Framework Engine (Section 10).
- Implement the Decision BOM reconstruction (Section 11).
- Implement the Semantic Delta Engine (Section 13).
- Implement the Commitment Engine (Section 14).
- Provide the Audit Collector REST API (Section 15).
- Support all four compliance frameworks (Section 10.1).

### 23.2 Conformance Declaration [Pure Specification]

Implementations claiming conformance MUST:

1. State their conformance level (1, 2, or 3).
2. Pass all applicable conformance tests (when available).
3. Document any OPTIONAL features implemented.
4. Document any extensions to the specification.

### 23.3 Extension Guidelines [Pure Specification]

- Extensions MUST NOT alter the semantics of existing fields or interfaces.
- Extension event kinds MUST use a vendor-specific prefix (e.g., `VENDOR_CUSTOM_EVENT`).
- Extension attributes MUST use a vendor-specific namespace (e.g., `vendor.custom.*`).
- Extensions SHOULD be documented in the implementation's conformance declaration.

---

## 24. Appendices

### Appendix A: Audit Entry Schema Samples

#### A.1 Agent OS Audit Entry (Governance Decision)

```json
{
  "timestamp": "2025-05-17T14:30:00.123456Z",
  "event_type": "governance_decision",
  "agent_id": "agent-alpha-001",
  "action": "execute_tool:web_search",
  "decision": "allow",
  "reason": "Tool is in allowed list for this agent's policy",
  "latency_ms": 2.45,
  "metadata": {
    "policy_name": "default-web-access",
    "tool_args_hash": "sha256:abc123...",
    "request_id": "req-789"
  }
}
```

#### A.2 Agent OS Audit Entry (Policy Violation)

```json
{
  "timestamp": "2025-05-17T14:31:00.654321Z",
  "event_type": "governance_decision",
  "agent_id": "agent-beta-002",
  "action": "execute_tool:file_write",
  "decision": "deny",
  "reason": "Tool file_write is blocked by policy 'restricted-tools'",
  "latency_ms": 1.12,
  "metadata": {
    "policy_name": "restricted-tools",
    "violation_category": "BLOCKED_TOOL",
    "matched_rule": "deny_list:file_write"
  }
}
```

#### A.3 Agent Mesh Audit Entry

```json
{
  "entry_id": "audit_a1b2c3d4e5f67890",
  "timestamp": "2025-05-17T14:32:00Z",
  "event_type": "tool_invocation",
  "agent_did": "did:web:mesh.example.com:agents:alpha",
  "action": "invoke_tool",
  "resource": "knowledge_base:search",
  "target_did": null,
  "data": {
    "tool_name": "search",
    "arguments": {"query": "latest governance policies"},
    "result_status": "success"
  },
  "outcome": "success",
  "policy_decision": "allow",
  "matched_rule": "tool_allowlist_v2",
  "previous_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "entry_hash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "session_id": "session-2025-05-17-001",
  "sandbox_id": "sandbox-east-42",
  "environment": "production",
  "compute_driver": "azure-container-instances"
}
```

#### A.4 Agent Mesh Audit Entry as CloudEvent

```json
{
  "specversion": "1.0",
  "type": "ai.agentmesh.tool.invoked",
  "source": "urn:agentmesh:audit",
  "id": "audit_a1b2c3d4e5f67890",
  "time": "2025-05-17T14:32:00Z",
  "datacontenttype": "application/json",
  "agentmeshentryhash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  "agentmeshprevioushash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "traceid": "4bf92f3577b34da6a3ce929d0e0e4736",
  "sessionid": "session-2025-05-17-001",
  "data": {
    "event_type": "tool_invocation",
    "agent_did": "did:web:mesh.example.com:agents:alpha",
    "action": "invoke_tool",
    "resource": "knowledge_base:search",
    "outcome": "success"
  }
}
```

### Appendix B: Governance Event Catalog

#### B.1 Complete Event Kind Reference

| Kind | Typical Severity | Typical Decision | Description |
|------|-----------------|------------------|-------------|
| `POLICY_CHECK` | info | allow/deny | Routine policy evaluation. |
| `POLICY_VIOLATION` | high | deny | Policy violation detected. |
| `TOOL_CALL_BLOCKED` | medium | deny | Tool invocation prevented. |
| `PROMPT_INJECTION_DETECTED` | critical | deny | Prompt injection attempt. |
| `IDENTITY_VERIFIED` | info | allow | Successful identity check. |
| `IDENTITY_REJECTED` | high | deny | Failed identity check. |
| `RESOURCE_ACCESS` | info | allow/deny | Resource access attempt. |
| `ESCALATION_REQUESTED` | medium | escalate | Human review requested. |
| `CHECKPOINT_CREATED` | info | N/A | Governance checkpoint saved. |
| `ANOMALY_DETECTED` | high | warn/deny | Behavioral anomaly found. |
| `MCP_TOOL_POISONING` | critical | deny | MCP tool poisoning detected. |
| `CONTENT_VIOLATION` | high | deny | Content policy violation. |

#### B.2 Hypervisor Event Type Reference

| Category | Event Types | Typical Payload Fields |
|----------|-------------|----------------------|
| Session | CREATED, JOINED, ACTIVATED, TERMINATED, ARCHIVED | agent_count, session_config |
| Ring | ASSIGNED, ELEVATED, DEMOTED, ELEVATION_EXPIRED, BREACH_DETECTED | ring_level, previous_level, reason |
| Trust | VOUCH_CREATED, VOUCH_RELEASED, SLASH_EXECUTED, FAULT_ATTRIBUTED | target_did, amount, evidence |
| Quarantine | ENTERED, RELEASED | reason, duration_s |
| Saga | CREATED, STEP_*, COMPENSATING, COMPLETED, ESCALATED, FANOUT_*, CHECKPOINT_SAVED, HANDOFF | saga_id, step_index, compensation_plan |
| VFS | WRITE, DELETE, SNAPSHOT, RESTORE, CONFLICT | path, content_hash, conflict_resolution |
| Enforcement | RATE_LIMITED, AGENT_KILLED | limit_type, kill_reason |
| Audit | DELTA_CAPTURED, DELTA_COMMITTED, GC_COLLECTED | delta_id, entries_collected |
| Behavioral | BEHAVIOR_DRIFT, HISTORY_VERIFIED, IDENTITY_VERIFIED | drift_score, verification_result |

### Appendix C: Compliance Control Catalog

#### C.1 SOC 2 Controls

**SOC2-CC6.1: Logical and Physical Access Controls**
- Category: Access Control
- Requirements:
  - Agent identities MUST be verified before granting access
  - Access grants MUST be logged with full context
  - Principle of least privilege MUST be enforced
- Evidence Types: identity_verification, access_control_log, privilege_assignment

**SOC2-CC7.2: System Monitoring**
- Category: Monitoring
- Requirements:
  - All governance decisions MUST be logged
  - Anomalies MUST be detected and reported
  - Audit trails MUST be tamper-evident
- Evidence Types: audit_log, anomaly_detection, integrity_verification

#### C.2 HIPAA Controls

**HIPAA-164.312(a)(1): Access Control**
- Category: Technical Safeguards
- Requirements:
  - Unique agent identification MUST be maintained
  - Emergency access procedures MUST be documented
  - Automatic session termination after inactivity
- Evidence Types: identity_verification, access_control_log, session_management

**HIPAA-164.312(b): Audit Controls**
- Category: Technical Safeguards
- Requirements:
  - Hardware, software, and procedural mechanisms MUST record access to ePHI
  - Audit logs MUST be retained per policy
  - Audit logs MUST be reviewable
- Evidence Types: audit_log, access_log, retention_policy

#### C.3 EU AI Act Controls

**EUAI-ART9: Risk Management System**
- Category: Risk Management
- Requirements:
  - Risk management system MUST be established and maintained
  - Risks MUST be identified and analyzed
  - Appropriate risk mitigation measures MUST be adopted
- Evidence Types: risk_assessment, mitigation_plan, monitoring_log

**EUAI-ART13: Transparency and Provision of Information**
- Category: Transparency
- Requirements:
  - AI systems MUST be designed for sufficient transparency
  - Users MUST be informed of AI system capabilities and limitations
  - Decision-making processes MUST be explainable
- Evidence Types: decision_explanation, system_documentation, user_notification

#### C.4 GDPR Controls

**GDPR-ART5: Principles Relating to Processing of Personal Data**
- Category: Data Protection Principles
- Requirements:
  - Data MUST be processed lawfully, fairly, and transparently
  - Data MUST be collected for specified, explicit, and legitimate purposes
  - Data MUST be adequate, relevant, and limited to what is necessary
- Evidence Types: lawful_basis_record, purpose_limitation_log, data_minimization_audit

**GDPR-ART22: Automated Individual Decision-Making**
- Category: Automated Decisions
- Requirements:
  - Data subjects MUST have the right not to be subject to automated decisions
  - Meaningful information about decision logic MUST be provided
  - Safeguards MUST include the right to human intervention
- Evidence Types: decision_explanation, human_override_log, consent_record

### Appendix D: Violation Category Reference

#### D.1 Agent OS Violation Categories

| Category | Description | Typical Severity |
|----------|-------------|------------------|
| `BLOCKED_TOOL` | Tool is explicitly blocked by policy. | high |
| `NOT_ALLOWED_TOOL` | Tool is not in the allowed list. | medium |
| `BLOCKED_PATTERN_INPUT` | Input contains a blocked pattern. | high |
| `BLOCKED_PATTERN_TOOL` | Tool arguments contain a blocked pattern. | high |
| `BLOCKED_PATTERN_OUTPUT` | Output contains a blocked pattern. | high |
| `BLOCKED_PATTERN_MEMORY` | Memory content contains a blocked pattern. | medium |
| `MAX_TOOL_CALLS` | Maximum tool call limit exceeded. | medium |
| `TIMEOUT` | Operation timed out. | low |
| `HUMAN_APPROVAL` | Action requires human approval. | medium |
| `CONFIDENCE_THRESHOLD` | Confidence below required threshold. | medium |
| `DRIFT` | Behavioral drift detected. | high |
| `POLICY_ERROR` | Error during policy evaluation. | high |

### Appendix E: Configuration Reference

#### E.1 Environment Variables

| Variable | Component | Default | Description |
|----------|-----------|---------|-------------|
| `AGT_GSP_MAX_QUEUE_SIZE` | Agent OS | 1024 | Event processor max queue size. |
| `AGT_GSP_SCHEDULE_DELAY_MS` | Agent OS | 2000 | Batch export interval (ms). |
| `AGT_GSP_MAX_BATCH_SIZE` | Agent OS | 100 | Max events per export batch. |
| `AGT_GSP_EXPORT_TIMEOUT_MS` | Agent OS | 10000 | Export timeout (ms). |
| `AGENTMESH_AUDIT_DATA_DIR` | Agent Mesh | /data/audit | Audit data storage directory. |
| `AGENTMESH_AUDIT_RETENTION_DAYS` | Agent Mesh | 90 | Retention period in days. |
| `SANDBOX_ID` | Agent Mesh | None | Current sandbox identifier. |
| `OPENSHELL_SANDBOX_ID` | Agent Mesh | None | Fallback sandbox identifier. |
| `AGT_ENVIRONMENT` | Agent Mesh | None | Deployment environment name. |
| `OPENSHELL_COMPUTE_DRIVER` | Agent Mesh | None | Compute driver identifier. |

#### E.2 Default Constants

| Constant | Value | Component | Description |
|----------|-------|-----------|-------------|
| Circuit Breaker Threshold | 5 | Agent OS | Consecutive failures to open breaker. |
| Circuit Breaker Cooldown | 60s | Agent OS | Cooldown before half-open attempt. |
| Event Bus Max Events | 100,000 | Hypervisor | Maximum events retained in bus. |
| BOM Window Seconds | 5.0 | Agent Mesh | Time window for BOM reconstruction. |
| Audit File Permissions | 0o600 | Agent OS | POSIX file permission mode. |
| Worker Thread Name | agt-governance-event-processor | Agent OS | Daemon thread name. |
| Schema Version | 1 | Agent OS | Current event schema version. |

#### E.3 OTel Attribute Reference

| Attribute | Component | Description |
|-----------|-----------|-------------|
| `agt.audit.event_type` | Agent OS | Audit event type. |
| `agt.audit.action` | Agent OS | Audited action. |
| `agt.audit.decision` | Agent OS | Governance decision. |
| `agt.audit.reason` | Agent OS | Decision reason. |
| `agt.audit.latency_ms` | Agent OS | Decision latency. |
| `agt.agent.id` | Agent OS | Agent identifier. |
| `agt.audit.meta.*` | Agent OS | Promoted metadata. |
| `event.domain` | Agent OS | "agent_os.governance" |
| `event.name` | Agent OS | "audit_entry" |
| `agent.id` | Agent SRE | Agent identifier. |
| `agent.name` | Agent SRE | Agent display name. |
| `agent.sre.slo.*` | Agent SRE | SLO-related attributes. |
| `agent.sre.sli.*` | Agent SRE | SLI-related attributes. |
| `agent.sre.error_budget.*` | Agent SRE | Error budget attributes. |
| `agent.sre.cost.*` | Agent SRE | Cost tracking attributes. |
| `agent.sre.incident.*` | Agent SRE | Incident attributes. |
| `agent.sre.signal.*` | Agent SRE | Signal attributes. |
| `agent.sre.chaos.*` | Agent SRE | Chaos engineering attributes. |
| `agent_os.*` | Lightning | Agent OS span attributes. |

#### E.4 Agent SRE Event Names

| Event Name | Description |
|------------|-------------|
| `agent.sre.slo.status_change` | SLO status transitioned. |
| `agent.sre.burn_rate.alert` | Error budget burn rate alert. |
| `agent.sre.cost.alert` | Cost threshold alert. |
| `agent.sre.incident.detected` | Incident detected. |
| `agent.sre.incident.resolved` | Incident resolved. |
| `agent.sre.signal.received` | External signal received. |
| `agent.sre.chaos.fault_injected` | Chaos fault injected. |
| `agent.sre.chaos.completed` | Chaos experiment completed. |

#### E.5 SLO Status Codes

| Code | Value | Description |
|------|-------|-------------|
| `healthy` | 0 | SLO is being met with comfortable margin. |
| `warning` | 1 | SLO is at risk; error budget depleting. |
| `critical` | 2 | SLO is violated; immediate action needed. |
| `exhausted` | 3 | Error budget fully consumed. |
| `unknown` | -1 | SLO status cannot be determined. |

### Appendix F: Agent SRE Dual Emission Pattern

#### F.1 Emission Strategy [Default Implementation]

Agent SRE events MUST be emitted via dual channels:

1. **Python Logging** -- Emitted via `logging.getLogger(logger_name)` at appropriate
   severity. This channel is consumed by OTel log exporters for centralized collection.

2. **Current Span Events** -- Emitted as events on the currently active OTel span.
   This channel provides trace-correlated event data for distributed tracing backends.

Both channels MUST receive the same event data. Neither channel is a substitute for
the other -- they serve different consumption patterns.

#### F.2 EventLogger Methods [Default Implementation]

| Method | Severity | Description |
|--------|----------|-------------|
| `log_slo_status_change` | WARNING/INFO | SLO status transition. |
| `log_burn_rate_alert` | WARNING | Error budget burn rate exceeded. |
| `log_cost_alert` | WARNING | Cost threshold exceeded. |
| `log_signal` | INFO | External signal received. |
| `log_incident_detected` | ERROR | New incident detected. |
| `log_incident_resolved` | INFO | Incident resolved. |
| `log_fault_injected` | INFO | Chaos fault injected. |
| `log_chaos_completed` | INFO | Chaos experiment completed. |

---

## 25. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0-DRAFT | 2025-05-17 | AGT Team | Initial specification draft. |

---

## 26. References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC 8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- [CloudEvents] CNCF CloudEvents Specification, v1.0.
- [OpenTelemetry] OpenTelemetry Specification, Logs Data Model.
- [EU AI Act] Regulation (EU) 2024/1689 of the European Parliament.
- [SOC 2] AICPA Trust Services Criteria (2017).
- [HIPAA] 45 CFR Part 164, Security Rule.
- [GDPR] Regulation (EU) 2016/679.
