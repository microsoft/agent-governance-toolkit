# ADR-0017: Merkle Chain for Audit Tamper Evidence

## Status

Accepted

## Context

AGT's audit system needed tamper-evidence guarantees for production deployments
where audit logs serve as compliance evidence. Traditional append-only file logs
can be silently modified without detection. Blockchain-based approaches were
considered but rejected due to operational complexity and latency requirements.

The system needed to:
- Detect any modification to historical audit entries
- Provide cryptographic proof that a specific entry existed at a given position
- Support offline verification without access to the original system
- Remain fast enough for inline governance decisions (sub-millisecond overhead)

## Decision

We use a SHA-256 hash chain (Merkle chain) where each audit entry's hash
includes the previous entry's hash, forming an append-only linked structure.

Key design choices:
- Each `AuditEntry` carries `previous_hash` and `entry_hash` fields
- Hash computation uses `hashlib.sha256` over the canonical JSON serialization
- `MerkleAuditChain` manages the chain state and provides `verify_chain()`
- Proof generation exports a subset of entries sufficient to verify inclusion
- No external blockchain anchoring -- verification is self-contained

The chain detects:
- Entry modification (hash mismatch)
- Entry deletion (chain break)
- Entry reordering (previous_hash mismatch)

## Consequences

- Any single-entry modification invalidates all subsequent hashes
- Verification is O(n) for the full chain but O(log n) for inclusion proofs
- No protection against a complete chain replacement (requires external anchoring for that threat model)
- Sub-millisecond per-entry overhead suitable for inline use
- Compatible with CloudEvents export for external archival

## References

- `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 13
- PR #1777 (Decision BOM), PR #2177 (hash encoding fix)
