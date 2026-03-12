# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Audit Log

Append-only JSON log with Merkle tree integrity verification.
Entries added via AuditLog or MerkleAuditChain get automatic hash chaining.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Any
from pydantic import BaseModel, Field
import hashlib
import json
import uuid

if TYPE_CHECKING:
    from .audit_backends import AuditSink


class AuditEntry(BaseModel):
    """
    Single audit log entry.

    All fields are preserved for API compatibility.
    Hash fields are populated when entries are added via
    :class:`MerkleAuditChain` or :class:`AuditLog`.
    """

    entry_id: str = Field(default_factory=lambda: f"audit_{uuid.uuid4().hex[:16]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Event details
    event_type: str
    agent_did: str
    action: str

    # Context
    resource: Optional[str] = None
    target_did: Optional[str] = None

    # Data (sanitized - no secrets)
    data: dict = Field(default_factory=dict)

    # Outcome
    outcome: str = "success"  # success, failure, denied, error

    # Policy evaluation
    policy_decision: Optional[str] = None
    matched_rule: Optional[str] = None

    # Chaining — kept for API compatibility but not computed
    previous_hash: str = Field(default="")
    entry_hash: str = Field(default="")

    # Metadata
    trace_id: Optional[str] = None
    session_id: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this entry's canonical fields.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        data = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "agent_did": self.agent_did,
            "action": self.action,
            "resource": self.resource,
            "data": self.data,
            "outcome": self.outcome,
            "previous_hash": self.previous_hash,
        }
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def verify_hash(self) -> bool:
        """Verify that this entry's stored hash matches a fresh computation.

        Returns:
            ``True`` if ``entry_hash`` equals ``compute_hash()``.
        """
        return self.entry_hash == self.compute_hash()

    # ── CloudEvents v1.0 ──────────────────────────────────

    _CE_TYPE_MAP: dict[str, str] = {
        "tool_invocation":     "ai.agentmesh.tool.invoked",
        "tool_blocked":        "ai.agentmesh.tool.blocked",
        "policy_evaluation":   "ai.agentmesh.policy.evaluation",
        "policy_violation":    "ai.agentmesh.policy.violation",
        "trust_handshake":     "ai.agentmesh.trust.handshake",
        "trust_score_updated": "ai.agentmesh.trust.score.updated",
        "agent_registered":    "ai.agentmesh.agent.registered",
        "agent_verified":      "ai.agentmesh.agent.verified",
        "audit_integrity":     "ai.agentmesh.audit.integrity.verified",
    }

    def to_cloudevent(self) -> dict[str, Any]:
        """Serialize this entry as a CloudEvents v1.0 JSON envelope."""
        ce_type = self._CE_TYPE_MAP.get(
            self.event_type, f"ai.agentmesh.{self.event_type}"
        )
        return {
            "specversion": "1.0",
            "id": self.entry_id,
            "type": ce_type,
            "source": self.agent_did,
            "time": self.timestamp.isoformat() + "Z",
            "datacontenttype": "application/json",
            "data": {
                "action": self.action,
                "resource": self.resource,
                "outcome": self.outcome,
                "policy_decision": self.policy_decision,
                "matched_rule": self.matched_rule,
                **self.data,
            },
            "agentmeshentryhash": self.entry_hash,
            "agentmeshprevioushash": self.previous_hash,
            **({"traceid": self.trace_id} if self.trace_id else {}),
            **({"sessionid": self.session_id} if self.session_id else {}),
        }


class MerkleNode(BaseModel):
    """Node in a Merkle tree used for audit verification.

    Attributes:
        hash: SHA-256 hash of this node.
        left_child: Hash of the left child node (``None`` for leaves).
        right_child: Hash of the right child node (``None`` for leaves).
        is_leaf: Whether this node is a leaf in the tree.
        entry_id: Audit entry ID (populated only for leaf nodes).
    """

    hash: str
    left_child: Optional[str] = None
    right_child: Optional[str] = None
    is_leaf: bool = False
    entry_id: Optional[str] = None


# Backward-compatible alias
ChainNode = MerkleNode


class MerkleAuditChain:
    """
    Merkle tree for efficient audit verification.

    Allows:
    - Efficient verification of single entries
    - Proof that an entry exists in the log
    - Detection of any tampering
    """

    def __init__(self):
        self._entries: list[AuditEntry] = []
        self._tree: list[list[MerkleNode]] = []
        self._root_hash: Optional[str] = None

    def add_entry(self, entry: AuditEntry) -> None:
        """Add an entry and update the Merkle tree incrementally."""
        # Set previous hash
        if self._entries:
            entry.previous_hash = self._entries[-1].entry_hash

        # Compute and set hash
        entry.entry_hash = entry.compute_hash()

        self._entries.append(entry)

        new_leaf = MerkleNode(
            hash=entry.entry_hash,
            is_leaf=True,
            entry_id=entry.entry_id,
        )

        n = len(self._entries)

        if n == 1:
            # First entry — initialize tree
            self._tree = [[new_leaf]]
            self._root_hash = new_leaf.hash
            return

        # Check if we need to expand the tree capacity
        capacity = len(self._tree[0])
        if n > capacity:
            # Double capacity: pad leaves with empty nodes, add new tree level
            for level_idx in range(len(self._tree)):
                self._tree[level_idx].extend(
                    [MerkleNode(hash="0" * 64) for _ in range(len(self._tree[level_idx]))]
                )
            # Add new root level
            old_root = self._tree[-1][0]
            empty_node = MerkleNode(hash="0" * 64)
            combined = old_root.hash + empty_node.hash
            new_root = MerkleNode(
                hash=hashlib.sha256(combined.encode()).hexdigest(),
                left_child=old_root.hash,
                right_child=empty_node.hash,
            )
            self._tree.append([new_root, MerkleNode(hash="0" * 64)])

        # Place new leaf
        leaf_idx = n - 1
        self._tree[0][leaf_idx] = new_leaf

        # Update path from leaf to root
        idx = leaf_idx
        for level_idx in range(len(self._tree) - 1):
            parent_idx = idx // 2
            left_idx = parent_idx * 2
            right_idx = left_idx + 1

            left = self._tree[level_idx][left_idx]
            right = self._tree[level_idx][right_idx] if right_idx < len(self._tree[level_idx]) else left

            combined = left.hash + right.hash
            parent_hash = hashlib.sha256(combined.encode()).hexdigest()

            self._tree[level_idx + 1][parent_idx] = MerkleNode(
                hash=parent_hash,
                left_child=left.hash,
                right_child=right.hash,
            )
            idx = parent_idx

        self._root_hash = self._tree[-1][0].hash if self._tree else None

    def _rebuild_tree(self) -> None:
        """Rebuild Merkle tree from entries (full rebuild, used for verification)."""
        if not self._entries:
            self._tree = []
            self._root_hash = None
            return

        # Create leaf nodes
        leaves = []
        for entry in self._entries:
            leaves.append(MerkleNode(
                hash=entry.entry_hash,
                is_leaf=True,
                entry_id=entry.entry_id,
            ))

        # Pad to power of 2
        while len(leaves) & (len(leaves) - 1) != 0:
            leaves.append(MerkleNode(hash="0" * 64, is_leaf=True))

        self._tree = [leaves]

        # Build tree bottom-up
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()

                next_level.append(MerkleNode(
                    hash=parent_hash,
                    left_child=left.hash,
                    right_child=right.hash,
                ))

            self._tree.append(next_level)
            current_level = next_level

        self._root_hash = self._tree[-1][0].hash if self._tree else None

    def get_root_hash(self) -> Optional[str]:
        """Get the current Merkle root hash."""
        return self._root_hash

    def get_proof(self, entry_id: str) -> Optional[list[tuple[str, str]]]:
        """Get a Merkle inclusion proof for an entry."""
        # Find entry index
        entry_idx = None
        for i, entry in enumerate(self._entries):
            if entry.entry_id == entry_id:
                entry_idx = i
                break

        if entry_idx is None:
            return None

        proof = []
        idx = entry_idx

        for level in self._tree[:-1]:  # Exclude root
            sibling_idx = idx ^ 1  # XOR to get sibling
            if sibling_idx < len(level):
                position = "right" if idx % 2 == 0 else "left"
                proof.append((level[sibling_idx].hash, position))
            idx //= 2

        return proof

    def verify_proof(
        self,
        entry_hash: str,
        proof: list[tuple[str, str]],
        root_hash: str,
    ) -> bool:
        """Verify a Merkle inclusion proof."""
        current = entry_hash

        for sibling_hash, position in proof:
            if position == "right":
                combined = current + sibling_hash
            else:
                combined = sibling_hash + current
            current = hashlib.sha256(combined.encode()).hexdigest()

        return current == root_hash

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Verify the entire chain integrity."""
        previous_hash = ""

        for i, entry in enumerate(self._entries):
            # Verify entry's own hash
            if not entry.verify_hash():
                return False, f"Entry {i} hash mismatch"

            # Verify chain
            if entry.previous_hash != previous_hash:
                return False, f"Entry {i} chain broken"

            previous_hash = entry.entry_hash

        return True, None


# Backward-compatible alias
AuditChain = MerkleAuditChain


class AuditLog:
    """
    Append-only audit logging system.

    Entries are stored in a simple list with indexes for querying.
    An optional external :class:`~audit_backends.AuditSink` can be
    provided to persist entries to an external store with cryptographic
    integrity.
    """

    def __init__(self, *, sink: AuditSink | None = None):
        self._chain = MerkleAuditChain()
        self._by_agent: dict[str, list[str]] = {}
        self._by_type: dict[str, list[str]] = {}
        self._sink = sink

    def log(
        self,
        event_type: str,
        agent_did: str,
        action: str,
        resource: Optional[str] = None,
        data: Optional[dict] = None,
        outcome: str = "success",
        policy_decision: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> AuditEntry:
        """Log an audit event."""
        entry = AuditEntry(
            event_type=event_type,
            agent_did=agent_did,
            action=action,
            resource=resource,
            data=data or {},
            outcome=outcome,
            policy_decision=policy_decision,
            trace_id=trace_id,
        )

        self._chain.add_entry(entry)

        # Write to external sink if configured
        if self._sink is not None:
            self._sink.write(entry)

        # Index
        if agent_did not in self._by_agent:
            self._by_agent[agent_did] = []
        self._by_agent[agent_did].append(entry.entry_id)

        if event_type not in self._by_type:
            self._by_type[event_type] = []
        self._by_type[event_type].append(entry.entry_id)

        return entry

    def get_entry(self, entry_id: str) -> Optional[AuditEntry]:
        """Get an audit entry by its unique ID."""
        for entry in self._chain._entries:
            if entry.entry_id == entry_id:
                return entry
        return None

    def get_entries_for_agent(
        self,
        agent_did: str,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Get the most recent entries for a specific agent."""
        entry_ids = self._by_agent.get(agent_did, [])[-limit:]
        return [
            entry for entry in self._chain._entries
            if entry.entry_id in entry_ids
        ]

    def get_entries_by_type(
        self,
        event_type: str,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Get the most recent entries of a given event type."""
        entry_ids = self._by_type.get(event_type, [])[-limit:]
        return [
            entry for entry in self._chain._entries
            if entry.entry_id in entry_ids
        ]

    def query(
        self,
        agent_did: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters."""
        results = self._chain._entries

        if agent_did:
            results = [e for e in results if e.agent_did == agent_did]

        if event_type:
            results = [e for e in results if e.event_type == event_type]

        if start_time:
            results = [e for e in results if e.timestamp >= start_time]

        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        if outcome:
            results = [e for e in results if e.outcome == outcome]

        return results[-limit:]

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        """Always valid."""
        return self._chain.verify_chain()

    def get_proof(self, entry_id: str) -> Optional[dict[str, Any]]:
        """Get tamper-proof evidence for a specific entry."""
        entry = self.get_entry(entry_id)
        if not entry:
            return None

        proof = self._chain.get_proof(entry_id)
        if not proof:
            return None

        return {
            "entry": entry.model_dump(),
            "merkle_proof": proof,
            "merkle_root": self._chain.get_root_hash(),
            "verified": self._chain.verify_proof(
                entry.entry_hash, proof, self._chain.get_root_hash()
            ),
        }

    def export(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """Export the audit log."""
        entries = self.query(start_time=start_time, end_time=end_time, limit=10000)

        return {
            "exported_at": datetime.utcnow().isoformat(),
            "merkle_root": self._chain.get_root_hash(),
            "chain_root": self._chain.get_root_hash(),
            "entry_count": len(entries),
            "entries": [e.model_dump() for e in entries],
        }

    def export_cloudevents(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Export audit entries as CloudEvents v1.0 JSON envelopes."""
        entries = self.query(start_time=start_time, end_time=end_time, limit=10000)
        return [e.to_cloudevent() for e in entries]
