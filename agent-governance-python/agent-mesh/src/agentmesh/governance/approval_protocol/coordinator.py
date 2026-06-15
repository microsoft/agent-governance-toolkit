# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Approval coordinator for the action-bound approval protocol (ADR-0030).

The coordinator owns the approval lifecycle:

* :meth:`ApprovalCoordinator.open_request` turns a ``require_approval`` policy
  decision into a durable, action-bound :class:`~.models.ApprovalRequest`;
* :meth:`ApprovalCoordinator.submit_entry` records an authenticated, hash-linked
  approver decision and resolves the request when the chain is satisfied;
* :meth:`ApprovalCoordinator.validate_for_execution` performs the atomic
  pre-execution revalidation (ADR-0030 section 6) and consumes the approval
  exactly once.

Every failure path is fail-closed: anything that is not an unambiguous terminal
allow over the exact action, policy version, and chain version denies execution
and returns a machine-readable reason code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, Optional

from .binding import ActionBinding
from .models import (
    ApprovalChainEntry,
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStatus,
    ApproverKind,
    EntryDecision,
    Outcome,
    PolicyDecisionRecord,
    Verdict,
    utcnow,
)
from .store import ApprovalStore


class ApprovalProtocolError(Exception):
    """Raised when a request cannot be created or an entry cannot be recorded."""


class ReasonCode:
    """Machine-readable reason codes emitted by execution-time validation."""

    OK = "ok"
    UNKNOWN_REQUEST = "unknown_request"
    NO_RESOLUTION = "no_resolution"
    NOT_TERMINAL_ALLOW = "not_terminal_allow"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    ALREADY_CONSUMED = "already_consumed"
    ACTION_DIGEST_MISMATCH = "action_digest_mismatch"
    POLICY_VERSION_MISMATCH = "policy_version_mismatch"
    CHAIN_VERSION_MISMATCH = "chain_version_mismatch"
    CHAIN_TAMPERED = "chain_tampered"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class ExecutionDecision:
    """Result of :meth:`ApprovalCoordinator.validate_for_execution`."""

    allowed: bool
    reason_code: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


@dataclass(frozen=True)
class ApprovalStage:
    """One ordered stage of an approval chain.

    A stage is satisfied by at least one authenticated, non-advisory ``ALLOW``
    entry from a permitted identity or role. A stage with neither identities nor
    roles configured can never be satisfied (fail-closed).
    """

    stage_index: int
    allowed_identities: frozenset[str] = frozenset()
    allowed_roles: frozenset[str] = frozenset()
    required: bool = True

    def authorizes(self, identity: str, roles: Iterable[str]) -> bool:
        if identity in self.allowed_identities:
            return True
        return bool(self.allowed_roles.intersection(roles))


@dataclass(frozen=True)
class ApprovalChain:
    """A versioned, immutable approval-chain configuration."""

    chain_id: str
    version: str
    stages: tuple[ApprovalStage, ...]

    def stage(self, stage_index: int) -> Optional[ApprovalStage]:
        for stage in self.stages:
            if stage.stage_index == stage_index:
                return stage
        return None


@dataclass
class ApprovalCoordinator:
    """Creates, advances, and validates action-bound approval requests."""

    store: ApprovalStore
    chains: dict[str, ApprovalChain]
    clock: Callable[[], datetime] = field(default=utcnow)

    # -- creation -----------------------------------------------------------

    def open_request(
        self,
        binding: ActionBinding,
        *,
        policy_rule_id: str,
        policy_version: str,
        chain_id: str,
        ttl_seconds: float,
        target_resource: Optional[str] = None,
        fail_closed_on_timeout: bool = True,
    ) -> tuple[PolicyDecisionRecord, ApprovalRequest]:
        """Open a durable approval request for a ``require_approval`` decision."""
        chain = self.chains.get(chain_id)
        if chain is None:
            raise ApprovalProtocolError(f"unknown approval chain: {chain_id!r}")

        action_digest = binding.digest()
        decision = PolicyDecisionRecord(
            action_digest=action_digest,
            policy_rule_id=policy_rule_id,
            policy_version=policy_version,
            approval_chain_id=chain.chain_id,
            approval_chain_version=chain.version,
            verdict=Verdict.REQUIRE_APPROVAL,
        )
        now = self.clock()
        request = ApprovalRequest(
            policy_decision_id=decision.policy_decision_id,
            action_digest=action_digest,
            agent_id=binding.agent_id,
            operation=binding.operation,
            policy_version=policy_version,
            approval_chain_id=chain.chain_id,
            approval_chain_version=chain.version,
            expires_at=now + timedelta(seconds=ttl_seconds),
            subject_id=binding.subject_id,
            target_resource=target_resource
            if target_resource is not None
            else binding.target.resource,
            fail_closed_on_timeout=fail_closed_on_timeout,
        )
        self.store.save_request(request)
        return decision, request

    # -- advancing the chain ------------------------------------------------

    def submit_entry(
        self,
        approval_request_id: str,
        *,
        stage_index: int,
        approver_kind: ApproverKind,
        approver_identity: str,
        identity_assurance: str,
        decision: EntryDecision,
        reason_code: str = "",
        roles: Iterable[str] = (),
        chain_entry_id: Optional[str] = None,
    ) -> ApprovalChainEntry:
        """Record an approver decision and resolve the request if complete.

        Advisory (LLM) entries are recorded for audit but never satisfy or
        terminate a stage (ADR-0030 section 8). Authenticated entries are
        authority-checked against the stage before they are appended.
        """
        request = self.store.get_request(approval_request_id)
        if request is None:
            raise ApprovalProtocolError(f"unknown approval request: {approval_request_id!r}")

        # Idempotent resubmission by caller-supplied chain_entry_id.
        if chain_entry_id is not None:
            for existing in self.store.get_entries(approval_request_id):
                if existing.chain_entry_id == chain_entry_id:
                    return existing

        if self._expire_if_due(request):
            raise ApprovalProtocolError("approval request has expired")
        if request.status != ApprovalStatus.PENDING:
            raise ApprovalProtocolError(
                f"approval request is not pending (status={request.status.value})"
            )

        chain = self.chains[request.approval_chain_id]
        stage = chain.stage(stage_index)
        if stage is None:
            raise ApprovalProtocolError(f"unknown stage index: {stage_index}")

        is_advisory = approver_kind == ApproverKind.LLM_ADVISORY
        if not is_advisory and not stage.authorizes(approver_identity, roles):
            raise ApprovalProtocolError(
                f"identity {approver_identity!r} not permitted for stage {stage_index}"
            )

        prior = self.store.get_entries(approval_request_id)
        previous_digest = prior[-1].entry_digest if prior else None
        entry_kwargs = dict(
            approval_request_id=approval_request_id,
            stage_index=stage_index,
            approver_kind=approver_kind,
            approver_identity=approver_identity,
            identity_assurance=identity_assurance,
            decision=decision,
            input_digest=request.input_digest(),
            reason_code=reason_code,
            previous_entry_digest=previous_digest,
        )
        if chain_entry_id is not None:
            entry_kwargs["chain_entry_id"] = chain_entry_id
        entry = ApprovalChainEntry(**entry_kwargs).seal()

        self.store.append_entry(entry)
        if not is_advisory:
            self._maybe_resolve(request, chain)
        return entry

    def _maybe_resolve(self, request: ApprovalRequest, chain: ApprovalChain) -> None:
        if self.store.get_resolution(request.approval_request_id) is not None:
            return

        entries = [
            e
            for e in self.store.get_entries(request.approval_request_id)
            if e.approver_kind != ApproverKind.LLM_ADVISORY
        ]

        # A single authenticated deny terminates the chain immediately.
        for entry in entries:
            if entry.decision == EntryDecision.DENY:
                self._resolve(request, Outcome.DENY, entry.entry_digest)
                return

        # Allow is terminal only once every required stage has an allow.
        allowed_stages = {
            e.stage_index for e in entries if e.decision == EntryDecision.ALLOW
        }
        required = {s.stage_index for s in chain.stages if s.required}
        if required.issubset(allowed_stages):
            final_digest = entries[-1].entry_digest if entries else None
            self._resolve(request, Outcome.ALLOW, final_digest)

    def _resolve(
        self, request: ApprovalRequest, outcome: Outcome, final_entry_digest: Optional[str]
    ) -> ApprovalResolution:
        resolution = ApprovalResolution(
            approval_request_id=request.approval_request_id,
            outcome=outcome,
            action_digest=request.action_digest,
            policy_version=request.policy_version,
            approval_chain_version=request.approval_chain_version,
            final_entry_digest=final_entry_digest,
        )
        self.store.save_resolution(resolution)
        terminal = {
            Outcome.ALLOW: ApprovalStatus.ALLOWED,
            Outcome.DENY: ApprovalStatus.DENIED,
            Outcome.EXPIRED: ApprovalStatus.EXPIRED,
        }[outcome]
        self.store.set_status(request.approval_request_id, terminal)
        return resolution

    # -- execution-time validation -----------------------------------------

    def validate_for_execution(
        self,
        approval_request_id: str,
        *,
        current_action_digest: str,
        current_policy_version: str,
        current_chain_version: str,
        consume: bool = True,
    ) -> ExecutionDecision:
        """Atomically revalidate a resolved approval immediately before execution."""
        try:
            request = self.store.get_request(approval_request_id)
            if request is None:
                return ExecutionDecision(False, ReasonCode.UNKNOWN_REQUEST)

            self._expire_if_due(request)

            resolution = self.store.get_resolution(approval_request_id)
            if resolution is None:
                return ExecutionDecision(False, ReasonCode.NO_RESOLUTION)
            if resolution.outcome == Outcome.EXPIRED:
                return ExecutionDecision(False, ReasonCode.EXPIRED)
            if resolution.outcome != Outcome.ALLOW:
                return ExecutionDecision(False, ReasonCode.NOT_TERMINAL_ALLOW)

            if request.status == ApprovalStatus.CONSUMED:
                return ExecutionDecision(False, ReasonCode.ALREADY_CONSUMED)
            if request.status == ApprovalStatus.CANCELLED:
                return ExecutionDecision(False, ReasonCode.CANCELLED)
            if request.status != ApprovalStatus.ALLOWED:
                return ExecutionDecision(False, ReasonCode.NOT_TERMINAL_ALLOW)

            # An approval is valid only within the request's time window; an
            # allow granted before expiry must not execute after it.
            if self.clock() >= request.expires_at:
                return ExecutionDecision(False, ReasonCode.EXPIRED)

            # Bind the resolution to the exact action / policy / chain version.
            if current_action_digest != resolution.action_digest:
                return ExecutionDecision(False, ReasonCode.ACTION_DIGEST_MISMATCH)
            if current_policy_version != resolution.policy_version:
                return ExecutionDecision(False, ReasonCode.POLICY_VERSION_MISMATCH)
            if current_chain_version != resolution.approval_chain_version:
                return ExecutionDecision(False, ReasonCode.CHAIN_VERSION_MISMATCH)

            if not self._chain_intact(approval_request_id, resolution.final_entry_digest):
                return ExecutionDecision(False, ReasonCode.CHAIN_TAMPERED)

            if consume and not self.store.consume(approval_request_id):
                return ExecutionDecision(False, ReasonCode.ALREADY_CONSUMED)

            return ExecutionDecision(True, ReasonCode.OK)
        except Exception:  # fail closed on any unexpected error
            return ExecutionDecision(False, ReasonCode.INTERNAL_ERROR)

    # -- helpers ------------------------------------------------------------

    def _expire_if_due(self, request: ApprovalRequest) -> bool:
        """If a pending request is past expiry, resolve it ``EXPIRED``. Returns True if expired."""
        if request.status != ApprovalStatus.PENDING:
            return request.status == ApprovalStatus.EXPIRED
        if self.clock() >= request.expires_at:
            self._resolve(request, Outcome.EXPIRED, None)
            return True
        return False

    def _chain_intact(self, approval_request_id: str, final_entry_digest: Optional[str]) -> bool:
        """Verify every entry's digest and the append-only previous-digest links."""
        entries = self.store.get_entries(approval_request_id)
        previous: Optional[str] = None
        for entry in entries:
            if not entry.verify_digest():
                return False
            if entry.previous_entry_digest != previous:
                return False
            previous = entry.entry_digest
        if final_entry_digest is not None and previous != final_entry_digest:
            return False
        return True
