# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Protocol objects for the action-bound approval protocol (ADR-0030 section 3).

The protocol separates four objects so that authorization evidence is explicit
and tamper-evident:

* :class:`PolicyDecisionRecord` - the policy verdict that suspended execution;
* :class:`ApprovalRequest` - the pending request bound to one action digest;
* :class:`ApprovalChainEntry` - one append-only, hash-linked approver decision;
* :class:`ApprovalResolution` - the terminal outcome; only ``outcome=ALLOW``
  can release execution.

These names intentionally mirror the ADR. They live in this subpackage rather
than at ``agentmesh.governance`` top level to avoid colliding with the legacy
``agentmesh.governance.approval.ApprovalRequest`` while the migration in
ADR-0030 section 9 is in progress.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from .digest import sha256_jcs

__all__ = [
    "Verdict",
    "ApprovalStatus",
    "ApproverKind",
    "EntryDecision",
    "Outcome",
    "PolicyDecisionRecord",
    "ApprovalRequest",
    "ApprovalChainEntry",
    "ApprovalResolution",
    "utcnow",
]


def utcnow() -> datetime:
    """Timezone-aware current UTC time (the protocol never uses naive times)."""
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class Verdict(str, Enum):
    """Canonical policy enforcement outcomes (ADR-0030 section 1)."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalStatus(str, Enum):
    """Lifecycle state of an :class:`ApprovalRequest`."""

    PENDING = "pending"
    ALLOWED = "allowed"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    CONSUMED = "consumed"


class ApproverKind(str, Enum):
    """Kind of principal recorded on a chain entry."""

    HUMAN = "human"
    SERVICE = "service"
    # Advisory only - never satisfies a required stage (ADR-0030 section 8).
    LLM_ADVISORY = "llm_advisory"


class EntryDecision(str, Enum):
    """An individual approver's vote on a chain entry."""

    ALLOW = "allow"
    DENY = "deny"


class Outcome(str, Enum):
    """Terminal resolution outcome of an approval request."""

    ALLOW = "allow"
    DENY = "deny"
    EXPIRED = "expired"


@dataclass
class PolicyDecisionRecord:
    """A ``require_approval`` policy decision (ADR-0030 section 3)."""

    action_digest: str
    policy_rule_id: str
    policy_version: str
    approval_chain_id: str
    approval_chain_version: str
    verdict: Verdict = Verdict.REQUIRE_APPROVAL
    policy_decision_id: str = field(default_factory=lambda: _new_id("pd"))
    decided_at: datetime = field(default_factory=utcnow)


@dataclass
class ApprovalRequest:
    """A pending approval request bound to one action digest."""

    policy_decision_id: str
    action_digest: str
    agent_id: str
    operation: str
    policy_version: str
    approval_chain_id: str
    approval_chain_version: str
    expires_at: datetime
    subject_id: Optional[str] = None
    target_resource: Optional[str] = None
    fail_closed_on_timeout: bool = True
    status: ApprovalStatus = ApprovalStatus.PENDING
    approval_request_id: str = field(default_factory=lambda: _new_id("ar"))
    requested_at: datetime = field(default_factory=utcnow)

    def presented_canonical(self) -> dict[str, Any]:
        """Request fields presented to an approver (hashed as ``input_digest``)."""
        return {
            "approval_request_id": self.approval_request_id,
            "policy_decision_id": self.policy_decision_id,
            "action_digest": self.action_digest,
            "agent_id": self.agent_id,
            "subject_id": self.subject_id,
            "operation": self.operation,
            "target_resource": self.target_resource,
            "policy_version": self.policy_version,
            "approval_chain_id": self.approval_chain_id,
            "approval_chain_version": self.approval_chain_version,
            "expires_at": self.expires_at.isoformat(),
        }

    def input_digest(self) -> str:
        return sha256_jcs(self.presented_canonical())


@dataclass
class ApprovalChainEntry:
    """One append-only, hash-linked approver decision (ADR-0030 section 3)."""

    approval_request_id: str
    stage_index: int
    approver_kind: ApproverKind
    approver_identity: str
    identity_assurance: str
    decision: EntryDecision
    input_digest: str
    reason_code: str = ""
    previous_entry_digest: Optional[str] = None
    chain_entry_id: str = field(default_factory=lambda: _new_id("ace"))
    decided_at: datetime = field(default_factory=utcnow)
    # Populated by ``seal()``; covers every field except itself.
    entry_digest: Optional[str] = None

    def _canonical_without_digest(self) -> dict[str, Any]:
        return {
            "approval_request_id": self.approval_request_id,
            "chain_entry_id": self.chain_entry_id,
            "stage_index": self.stage_index,
            "approver_kind": self.approver_kind.value,
            "approver_identity": self.approver_identity,
            "identity_assurance": self.identity_assurance,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "input_digest": self.input_digest,
            "previous_entry_digest": self.previous_entry_digest,
            "decided_at": self.decided_at.isoformat(),
        }

    def compute_digest(self) -> str:
        """Return the SHA-256/JCS digest over every field except ``entry_digest``."""
        return sha256_jcs(self._canonical_without_digest())

    def seal(self) -> "ApprovalChainEntry":
        """Set ``entry_digest`` to the computed digest and return self."""
        self.entry_digest = self.compute_digest()
        return self

    def verify_digest(self) -> bool:
        """True if the stored ``entry_digest`` matches the recomputed digest."""
        return self.entry_digest is not None and self.entry_digest == self.compute_digest()


@dataclass
class ApprovalResolution:
    """The terminal resolution of an approval request (ADR-0030 section 3)."""

    approval_request_id: str
    outcome: Outcome
    action_digest: str
    policy_version: str
    approval_chain_version: str
    final_entry_digest: Optional[str] = None
    approval_resolution_id: str = field(default_factory=lambda: _new_id("apr"))
    resolved_at: datetime = field(default_factory=utcnow)
