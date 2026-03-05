# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Audit Service

Append-only logger for tamper-evident audit trails.

Wraps the core AuditLog and AuditChain to provide:
- Immutable event history
- Cryptographic verification
- Compliance audit trails
- Query and export capabilities
"""

from __future__ import annotations

from typing import Any, Optional

from agentmesh.governance.audit import AuditEntry, AuditLog, AuditChain


class AuditService:
    """
    Service layer for audit logging.

    Provides a higher-level API over AuditLog with:
    - Convenience methods for common event types
    - Batch logging
    - Summary statistics
    - Verification helpers
    """

    def __init__(self) -> None:
        self._log = AuditLog()

    @property
    def chain(self) -> AuditChain:
        """Access the underlying audit chain for verification."""
        return self._log._chain

    def log_action(
        self,
        agent_did: str,
        action: str,
        outcome: str = "success",
        resource: Optional[str] = None,
        data: Optional[dict] = None,
        trace_id: Optional[str] = None,
    ) -> AuditEntry:
        """Log an agent action."""
        return self._log.log(
            event_type="agent_action",
            agent_did=agent_did,
            action=action,
            resource=resource,
            data=data,
            outcome=outcome,
            trace_id=trace_id,
        )

    def log_policy_decision(
        self,
        agent_did: str,
        action: str,
        decision: str,
        policy_name: str = "",
        data: Optional[dict] = None,
    ) -> AuditEntry:
        """Log a policy enforcement decision."""
        outcome = "success" if decision == "allow" else "denied"
        return self._log.log(
            event_type="policy_decision",
            agent_did=agent_did,
            action=action,
            outcome=outcome,
            policy_decision=decision,
            data={**(data or {}), "policy_name": policy_name},
        )

    def log_handshake(
        self,
        initiator_did: str,
        responder_did: str,
        success: bool,
        data: Optional[dict] = None,
    ) -> AuditEntry:
        """Log a trust handshake event."""
        return self._log.log(
            event_type="trust_handshake",
            agent_did=initiator_did,
            action="handshake",
            resource=responder_did,
            outcome="success" if success else "failure",
            data=data,
        )

    def log_trust_change(
        self,
        agent_did: str,
        old_score: float,
        new_score: float,
        reason: str = "",
    ) -> AuditEntry:
        """Log a trust score change."""
        return self._log.log(
            event_type="trust_change",
            agent_did=agent_did,
            action="trust_update",
            data={
                "old_score": old_score,
                "new_score": new_score,
                "reason": reason,
            },
        )

    def query_by_agent(self, agent_did: str) -> list[AuditEntry]:
        """Get all audit entries for an agent."""
        return self._log.query(agent_did=agent_did)

    def query_by_type(self, event_type: str) -> list[AuditEntry]:
        """Get all audit entries of a specific type."""
        return self._log.query(event_type=event_type)

    def verify_chain(self) -> bool:
        """Verify the integrity of the audit chain."""
        valid, _error = self._log.verify_integrity()
        return valid

    @property
    def entry_count(self) -> int:
        """Total number of audit entries."""
        return len(self._log._chain._entries)

    def summary(self) -> dict[str, Any]:
        """Get audit service summary statistics."""
        count = self.entry_count
        return {
            "total_entries": count,
            "chain_valid": self.verify_chain(),
            "root_hash": self._log._chain.get_root_hash() if count > 0 else None,
        }


__all__ = ["AuditService", "AuditEntry", "AuditLog", "AuditChain"]
