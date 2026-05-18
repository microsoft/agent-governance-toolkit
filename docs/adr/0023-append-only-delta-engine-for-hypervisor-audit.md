# ADR-0023: Append-Only Delta Engine for Hypervisor Audit

## Status

Accepted

## Context

The Agent Hypervisor manages sandboxed execution environments where agents can
modify virtual filesystem state. For forensic analysis and rollback, we needed
to capture every state change with:

- Tamper-evident history (detect if audit records are modified)
- Per-turn granularity (attribute changes to specific agent actions)
- Causal ordering (reconstruct the exact sequence of modifications)
- Low overhead (cannot significantly impact execution latency)

## Decision

We implemented `DeltaEngine` with a SHA-256 hash-chained append-only log:

- `VFSChange` captures individual file operations (create, modify, delete)
  with path, operation type, and content hash
- `SemanticDelta` groups changes into a single atomic unit per agent turn,
  with fields: `delta_id`, `turn_id`, `session_id`, `agent_did`, `timestamp`,
  `changes`, `parent_hash`, `delta_hash`
- Hash computation: `SHA-256(parent_hash || canonical_json(delta))`
- `CommitmentEngine` stores summary hash commitments for periodic anchoring

Key properties:
- Deltas are immutable once captured
- Each delta references its parent hash, forming a chain
- Chain verification detects any modification or deletion
- No external dependencies (pure Python, stdlib hashlib)

## Consequences

- Full forensic reconstruction of any agent's filesystem modifications
- Tamper evidence without blockchain operational overhead
- Per-turn attribution enables precise rollback to any point
- In-memory storage by default (CommitmentEngine) -- production deployments
  can persist to durable storage via the commitment interface
- Hash chain verification is O(n) but only needed for audit, not hot path

## References

- `agent-governance-python/agent-hypervisor/src/hypervisor/audit/delta.py`
- `agent-governance-python/agent-hypervisor/src/hypervisor/audit/commitment.py`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 18
- `docs/specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md`
- PR #2177 (length-prefix encoding fix for Go audit)
