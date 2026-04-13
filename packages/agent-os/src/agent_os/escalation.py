# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Human-in-the-loop escalation workflows for AI agent governance.

Provides approval gates, timeout escalation, and configurable escalation
policies so agents can't take high-risk actions without human sign-off.

This directly addresses the criticism that AGT has "no human escalation
primitives baked in." Now it does.

Usage:
    from agent_os.escalation import EscalationManager, EscalationPolicy

    policy = EscalationPolicy(
        actions_requiring_approval=["delete_file", "deploy", "send_email"],
        timeout_seconds=300,
        default_on_timeout="deny",
    )
    manager = EscalationManager(policy)

    decision = await manager.request_approval(
        agent_id="agent-1",
        action="deploy",
        context={"target": "production", "version": "2.1.0"},
    )
    if decision.approved:
        # proceed
        ...
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Awaitable

from pydantic import BaseModel, Field


class EscalationOutcome(str, Enum):
    """Outcome of an escalation request."""
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    PENDING = "pending"
    AUTO_APPROVED = "auto_approved"


class EscalationRequest(BaseModel):
    """A pending human approval request."""
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_id: str
    action: str
    context: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    urgency: str = Field(default="normal", description="low, normal, high, critical")
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    outcome: EscalationOutcome = EscalationOutcome.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None


class EscalationDecision(BaseModel):
    """Result of an escalation request."""
    request_id: str
    approved: bool
    outcome: EscalationOutcome
    decided_by: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""


class EscalationPolicy(BaseModel):
    """Policy governing when and how actions are escalated to humans."""

    actions_requiring_approval: list[str] = Field(
        default_factory=list,
        description="Actions that always require human approval",
    )
    action_patterns_requiring_approval: list[str] = Field(
        default_factory=list,
        description="Regex patterns for actions requiring approval",
    )
    classifications_requiring_approval: list[str] = Field(
        default_factory=list,
        description="Data classifications that trigger escalation (e.g., RESTRICTED, TOP_SECRET)",
    )
    timeout_seconds: int = Field(
        default=300,
        description="Seconds to wait for human response before timeout action",
    )
    default_on_timeout: str = Field(
        default="deny",
        description="Action when timeout: 'deny' (safe default) or 'approve'",
    )
    max_auto_approvals_per_hour: int = Field(
        default=0,
        description="Max actions auto-approved per hour (0 = never auto-approve)",
    )
    escalation_chain: list[str] = Field(
        default_factory=list,
        description="Ordered list of approvers. If first doesn't respond, escalate to next.",
    )
    notify_on_timeout: bool = Field(
        default=True,
        description="Send notification when escalation times out",
    )


class EscalationManager:
    """Manages human-in-the-loop approval workflows.

    When an agent requests a high-risk action, the manager:
    1. Checks if the action requires approval (per policy)
    2. Creates an EscalationRequest
    3. Notifies the approval handler (webhook, UI, Slack, etc.)
    4. Waits for human response or timeout
    5. Returns the decision

    The approval handler is pluggable — implement your own notification
    system (Slack bot, email, Teams, dashboard, etc.)
    """

    def __init__(
        self,
        policy: EscalationPolicy,
        approval_handler: Callable[[EscalationRequest], Awaitable[None]] | None = None,
        timeout_handler: Callable[[EscalationRequest], Awaitable[None]] | None = None,
    ) -> None:
        self.policy = policy
        self._pending: dict[str, EscalationRequest] = {}
        self._approval_handler = approval_handler
        self._timeout_handler = timeout_handler
        self._events: list[dict[str, Any]] = []

    def requires_approval(self, action: str, **context: Any) -> bool:
        """Check if an action requires human approval per policy."""
        import re

        if action in self.policy.actions_requiring_approval:
            return True

        for pattern in self.policy.action_patterns_requiring_approval:
            if re.search(pattern, action):
                return True

        classification = context.get("classification", "")
        if classification in self.policy.classifications_requiring_approval:
            return True

        return False

    async def request_approval(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any] | None = None,
        reason: str = "",
        urgency: str = "normal",
    ) -> EscalationDecision:
        """Request human approval for an action.

        If the action doesn't require approval, returns auto-approved.
        Otherwise, creates an escalation request and waits for response.
        """
        if not self.requires_approval(action, **(context or {})):
            decision = EscalationDecision(
                request_id="auto",
                approved=True,
                outcome=EscalationOutcome.AUTO_APPROVED,
                decided_by="policy",
                reason="Action does not require approval",
            )
            self._record_event("auto_approved", agent_id, action, decision)
            return decision

        now = datetime.now(timezone.utc)
        request = EscalationRequest(
            agent_id=agent_id,
            action=action,
            context=context or {},
            reason=reason,
            urgency=urgency,
            expires_at=now + timedelta(seconds=self.policy.timeout_seconds),
        )
        self._pending[request.request_id] = request

        # Notify approval handler
        if self._approval_handler:
            await self._approval_handler(request)

        self._record_event("escalated", agent_id, action, request)

        # Wait for response or timeout
        deadline = request.expires_at
        while datetime.now(timezone.utc) < deadline:
            if request.outcome != EscalationOutcome.PENDING:
                break
            await asyncio.sleep(0.1)

        # Handle timeout
        if request.outcome == EscalationOutcome.PENDING:
            if self.policy.default_on_timeout == "approve":
                request.outcome = EscalationOutcome.TIMED_OUT
                approved = True
            else:
                request.outcome = EscalationOutcome.TIMED_OUT
                approved = False

            request.decided_by = "timeout"
            request.decided_at = datetime.now(timezone.utc)

            if self._timeout_handler and self.policy.notify_on_timeout:
                await self._timeout_handler(request)

            decision = EscalationDecision(
                request_id=request.request_id,
                approved=approved,
                outcome=EscalationOutcome.TIMED_OUT,
                decided_by="timeout",
                reason=f"Timed out after {self.policy.timeout_seconds}s — default: {self.policy.default_on_timeout}",
            )
        else:
            decision = EscalationDecision(
                request_id=request.request_id,
                approved=request.outcome == EscalationOutcome.APPROVED,
                outcome=request.outcome,
                decided_by=request.decided_by or "unknown",
                decided_at=request.decided_at or datetime.now(timezone.utc),
            )

        del self._pending[request.request_id]
        self._record_event("decided", agent_id, action, decision)
        return decision

    def approve(self, request_id: str, decided_by: str = "human", reason: str = "") -> bool:
        """Approve a pending escalation request (called by human/UI)."""
        request = self._pending.get(request_id)
        if not request or request.outcome != EscalationOutcome.PENDING:
            return False
        request.outcome = EscalationOutcome.APPROVED
        request.decided_by = decided_by
        request.decided_at = datetime.now(timezone.utc)
        return True

    def deny(self, request_id: str, decided_by: str = "human", reason: str = "") -> bool:
        """Deny a pending escalation request (called by human/UI)."""
        request = self._pending.get(request_id)
        if not request or request.outcome != EscalationOutcome.PENDING:
            return False
        request.outcome = EscalationOutcome.DENIED
        request.decided_by = decided_by
        request.decided_at = datetime.now(timezone.utc)
        return True

    @property
    def pending_requests(self) -> list[EscalationRequest]:
        """Get all pending escalation requests."""
        return [r for r in self._pending.values() if r.outcome == EscalationOutcome.PENDING]

    @property
    def audit_trail(self) -> list[dict[str, Any]]:
        """Get the escalation audit trail."""
        return list(self._events)

    def _record_event(self, event_type: str, agent_id: str, action: str, data: Any) -> None:
        self._events.append({
            "event_type": event_type,
            "agent_id": agent_id,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data.model_dump(mode="json") if hasattr(data, "model_dump") else str(data),
        })
