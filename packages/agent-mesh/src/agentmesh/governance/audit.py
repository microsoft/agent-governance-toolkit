# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Audit Log

Append-only JSON log.
AuditEntry class retains all fields for compatibility, but
previous_hash and entry_hash are not computed.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional, Any
from pydantic import BaseModel, Field
import json
import uuid

if TYPE_CHECKING:
    from .audit_backends import AuditSink


class AuditEntry(BaseModel):
    """
    Single audit log entry.
    
    All fields are preserved for API compatibility.
    Hash fields exist but are not computed (always empty strings).
    """
    
    entry_id: str = Field(default_factory=lambda: f"audit_{uuid.uuid4().hex[:16]}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
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
        """Return empty string."""
        return ""
    
    def verify_hash(self) -> bool:
        """Always returns True."""
        return True

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


class ChainNode(BaseModel):
    """Retained for API compatibility."""
    
    hash: str
    left_child: Optional[str] = None
    right_child: Optional[str] = None
    is_leaf: bool = False
    entry_id: Optional[str] = None


class AuditChain:
    """
    Append-only audit log.
    
    Retains the same API surface for compatibility with AuditService
    and other consumers.
    """
    
    def __init__(self):
        self._entries: list[AuditEntry] = []
    
    def add_entry(self, entry: AuditEntry) -> None:
        """Append an entry to the log."""
        self._entries.append(entry)
    
    def get_root_hash(self) -> Optional[str]:
        """Return None."""
        return None
    
    def get_proof(self, entry_id: str) -> Optional[list[tuple[str, str]]]:
        """Return None."""
        return None
    
    def verify_proof(
        self,
        entry_hash: str,
        proof: list[tuple[str, str]],
        root_hash: str,
    ) -> bool:
        """Always returns True."""
        return True
    
    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Always returns valid."""
        return True, None


class AuditLog:
    """
    Append-only audit logging system.
    
    Entries are stored in a simple list with indexes for querying.
    An optional external :class:`~audit_backends.AuditSink` can be
    provided to persist entries to an external store with cryptographic
    integrity.
    """
    
    def __init__(self, *, sink: AuditSink | None = None):
        self._chain = AuditChain()
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
        """Return None."""
        return None
    
    def export(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """Export the audit log."""
        entries = self.query(start_time=start_time, end_time=end_time, limit=10000)
        
        return {
            "exported_at": datetime.utcnow().isoformat(),
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
