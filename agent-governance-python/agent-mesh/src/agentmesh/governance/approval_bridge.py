# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compatibility bridge from legacy approval handlers to the ADR-0030 protocol.

Step 3 of the ADR-0030 migration. The action-bound approval protocol
(:mod:`.approval_protocol`) is asynchronous and durable, but the existing
:class:`~agentmesh.governance.approval.ApprovalHandler` implementations
(callback, console, webhook, auto-reject) are synchronous: a handler is asked
for a decision and returns one inline.

:class:`LegacyHandlerAdapter` wraps such a handler so its vote becomes one
authenticated entry on a protocol approval chain: it asks the handler, maps the
``approved`` / ``approver`` / ``reason`` result onto a single
:meth:`~.approval_protocol.ApprovalCoordinator.submit_entry` call, and reports
the outcome. This keeps existing handlers working inside the protocol without
each integration (govern, Agent OS escalation, MCP gateway, framework adapters)
reimplementing the same mapping.

This module is allowed to depend on both the legacy ``approval`` module and the
``approval_protocol`` foundation; the foundation never depends back on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from .approval import ApprovalDecision, ApprovalHandler, ApprovalRequest
from .approval_protocol import (
    ApprovalChainEntry,
    ApprovalCoordinator,
    ApprovalProtocolError,
    ApproverKind,
    EntryDecision,
)
from .approval_protocol import ApprovalRequest as ProtocolApprovalRequest

__all__ = [
    "AdapterResult",
    "ApprovalTransport",
    "LegacyHandlerAdapter",
    "submit_vote",
]


@runtime_checkable
class ApprovalTransport(Protocol):
    """A protocol-native approval source.

    Unlike a legacy :class:`~agentmesh.governance.approval.ApprovalHandler`
    (which only receives the thin legacy request), a transport is handed the
    full protocol :class:`ApprovalRequest` so it can present the action digest,
    versions, and expiry to the approver. :class:`VersionedWebhookApproval`
    satisfies this.
    """

    def request_decision(
        self, request: ProtocolApprovalRequest
    ) -> ApprovalDecision: ...


@dataclass
class AdapterResult:
    """Outcome of bridging one handler vote into a protocol chain entry.

    Attributes:
        approval: The legacy handler's decision (always present).
        entry: The submitted chain entry, or ``None`` if it was rejected.
        error: Fail-closed reason when ``entry`` is ``None`` (e.g. the approver
            identity is not permitted by the stage, or the request has expired).
    """

    approval: ApprovalDecision
    entry: Optional[ApprovalChainEntry]
    error: Optional[str]

    @property
    def submitted(self) -> bool:
        return self.entry is not None


def submit_vote(
    coordinator: ApprovalCoordinator,
    request: ProtocolApprovalRequest,
    approval: ApprovalDecision,
    *,
    approver_kind: ApproverKind = ApproverKind.HUMAN,
    identity_assurance: str = "approval-handler",
    stage_index: int = 0,
) -> AdapterResult:
    """Record an already-obtained approver vote as one protocol chain entry.

    Shared by every vote source (legacy handler, webhook transport, ...).
    Fail-closed: any :class:`ApprovalProtocolError` from ``submit_entry``
    (unpermitted identity, expired request, unknown stage) yields an
    :class:`AdapterResult` with ``entry=None`` and a populated ``error`` rather
    than propagating, so callers can deny without special-casing.
    """
    try:
        entry = coordinator.submit_entry(
            request.approval_request_id,
            stage_index=stage_index,
            approver_kind=approver_kind,
            approver_identity=approval.approver or "unknown",
            identity_assurance=identity_assurance,
            decision=(
                EntryDecision.ALLOW if approval.approved else EntryDecision.DENY
            ),
            reason_code=approval.reason or "",
        )
    except ApprovalProtocolError as exc:
        return AdapterResult(
            approval=approval, entry=None, error=f"approval entry rejected: {exc}"
        )
    return AdapterResult(approval=approval, entry=entry, error=None)


class LegacyHandlerAdapter:
    """Drives one protocol chain entry from a legacy ``ApprovalHandler`` vote."""

    def __init__(
        self,
        handler: ApprovalHandler,
        *,
        approver_kind: ApproverKind = ApproverKind.HUMAN,
        identity_assurance: str = "approval-handler",
    ) -> None:
        self._handler = handler
        self._approver_kind = approver_kind
        self._identity_assurance = identity_assurance

    def collect(
        self,
        coordinator: ApprovalCoordinator,
        request: ProtocolApprovalRequest,
        legacy_request: ApprovalRequest,
        *,
        stage_index: int = 0,
    ) -> AdapterResult:
        """Ask the handler and submit its vote as a chain entry.

        Fail-closed: any :class:`ApprovalProtocolError` from ``submit_entry``
        (unpermitted identity, expired request, unknown stage) yields an
        :class:`AdapterResult` with ``entry=None`` and a populated ``error``
        rather than propagating, so callers can deny without special-casing.
        """
        approval = self._handler.request_approval(legacy_request)
        return submit_vote(
            coordinator,
            request,
            approval,
            approver_kind=self._approver_kind,
            identity_assurance=self._identity_assurance,
            stage_index=stage_index,
        )
