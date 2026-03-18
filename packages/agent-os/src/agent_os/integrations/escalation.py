# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Human-in-the-Loop Escalation for Governance Policies.

Adds an ``ESCALATE`` decision tier between ALLOW and DENY. When a policy
requires human approval, the agent is **suspended** and an approval request
is routed to a configurable backend (in-memory queue, webhook, or custom
handler).  A timeout with configurable default action ensures the system
never blocks indefinitely.

Usage:
    from agent_os.integrations.escalation import (
        EscalationHandler,
        EscalationPolicy,
        EscalationRequest,
        EscalationDecision,
        InMemoryApprovalQueue,
    )

    queue = InMemoryApprovalQueue()
    handler = EscalationHandler(backend=queue, timeout_seconds=300)
    policy = EscalationPolicy(integration, handler=handler)

    result = policy.evaluate("tool_call", context, input_data)
    if result.decision == EscalationDecision.PENDING:
        # Agent is suspended — await human decision
        queue.approve(result.request_id, approver="admin@corp.com")
        final = policy.resolve(result.request_id)
"""

from __future__ import annotations

import abc
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Optional

from .base import BaseIntegration, ExecutionContext, GovernanceEventType

logger = logging.getLogger(__name__)


class EscalationDecision(Enum):
    """Possible outcomes of an escalation evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    PENDING = "PENDING"
    TIMEOUT = "TIMEOUT"


class DefaultTimeoutAction(Enum):
    """Action to take when a human doesn't respond within the SLA."""

    DENY = "deny"
    ALLOW = "allow"


@dataclass
class QuorumConfig:
    """Configuration for M-of-N approval quorum.

    When set, an escalation requires at least ``required_approvals``
    ALLOW votes from distinct approvers before the action is permitted.
    A single DENY from any approver is enough to deny immediately
    unless ``required_denials`` is set.

    Attributes:
        required_approvals: Minimum ALLOW votes needed (M).
        total_approvers: Total approver pool size (N).  Informational.
        required_denials: Number of DENY votes to reject (default 1).
    """

    required_approvals: int = 2
    total_approvers: int = 3
    required_denials: int = 1

    def __post_init__(self) -> None:
        if self.required_approvals < 1:
            raise ValueError("required_approvals must be >= 1")
        if self.required_denials < 1:
            raise ValueError("required_denials must be >= 1")


@dataclass
class EscalationRequest:
    """A request for human approval of an agent action.

    Attributes:
        request_id: Unique identifier for this escalation.
        agent_id: ID of the agent whose action needs approval.
        action: Description of the action being escalated.
        reason: Why escalation was triggered.
        context_snapshot: Serialisable snapshot of the execution context.
        created_at: When the escalation was created.
        resolved_at: When a human responded (or timeout).
        decision: Final decision from the human (or timeout default).
        resolved_by: Identifier of the human who resolved.
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    action: str = ""
    reason: str = ""
    context_snapshot: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    decision: EscalationDecision = EscalationDecision.PENDING
    resolved_by: Optional[str] = None
    # Quorum tracking: list of (approver, decision, timestamp) votes
    votes: list[tuple[str, str, datetime]] = field(default_factory=list)


class ApprovalBackend(abc.ABC):
    """Abstract interface for escalation approval backends."""

    @abc.abstractmethod
    def submit(self, request: EscalationRequest) -> None:
        """Submit an escalation request for human review."""

    @abc.abstractmethod
    def get_decision(self, request_id: str) -> EscalationRequest | None:
        """Retrieve the current state of an escalation request."""

    @abc.abstractmethod
    def approve(self, request_id: str, approver: str = "") -> bool:
        """Approve an escalation request. Returns True if found and updated."""

    @abc.abstractmethod
    def deny(self, request_id: str, approver: str = "") -> bool:
        """Deny an escalation request. Returns True if found and updated."""

    @abc.abstractmethod
    def list_pending(self) -> list[EscalationRequest]:
        """List all pending escalation requests."""


class InMemoryApprovalQueue(ApprovalBackend):
    """Thread-safe in-memory approval queue.

    Suitable for testing, single-process deployments, and development.
    For production, implement a backend that uses Redis, a database,
    or a webhook-based notification service.
    """

    def __init__(self) -> None:
        self._requests: dict[str, EscalationRequest] = {}
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}

    def submit(self, request: EscalationRequest) -> None:
        with self._lock:
            self._requests[request.request_id] = request
            self._events[request.request_id] = threading.Event()

    def get_decision(self, request_id: str) -> EscalationRequest | None:
        with self._lock:
            return self._requests.get(request_id)

    def approve(self, request_id: str, approver: str = "") -> bool:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None or req.decision != EscalationDecision.PENDING:
                return False
            req.decision = EscalationDecision.ALLOW
            req.resolved_by = approver
            req.resolved_at = datetime.now(timezone.utc)
            event = self._events.get(request_id)
        if event:
            event.set()
        return True

    def deny(self, request_id: str, approver: str = "") -> bool:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None or req.decision != EscalationDecision.PENDING:
                return False
            req.decision = EscalationDecision.DENY
            req.resolved_by = approver
            req.resolved_at = datetime.now(timezone.utc)
            event = self._events.get(request_id)
        if event:
            event.set()
        return True

    def list_pending(self) -> list[EscalationRequest]:
        with self._lock:
            return [
                r
                for r in self._requests.values()
                if r.decision == EscalationDecision.PENDING
            ]

    def wait_for_decision(
        self, request_id: str, timeout: float | None = None
    ) -> EscalationDecision:
        """Block until a decision is made or timeout expires.

        Returns:
            The final decision, or ``PENDING`` if timeout was reached.
        """
        event = self._events.get(request_id)
        if event is None:
            return EscalationDecision.PENDING
        event.wait(timeout=timeout)
        req = self._requests.get(request_id)
        return req.decision if req else EscalationDecision.PENDING


class WebhookApprovalBackend(ApprovalBackend):
    """Approval backend that sends webhook notifications for escalations.

    Stores state in-memory but fires an HTTP POST to the configured URL
    when a new escalation is submitted. The receiving system is responsible
    for calling back via the ``approve``/``deny`` methods (e.g., via an
    API endpoint).

    Args:
        webhook_url: URL to POST escalation notifications to.
        headers: Optional HTTP headers (e.g., auth tokens).
    """

    def __init__(
        self,
        webhook_url: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._inner = InMemoryApprovalQueue()
        self._webhook_url = webhook_url
        self._headers = headers or {}

    def submit(self, request: EscalationRequest) -> None:
        self._inner.submit(request)
        self._notify(request)

    def _notify(self, request: EscalationRequest) -> None:
        """Fire-and-forget webhook notification."""
        try:
            import urllib.request
            import json

            payload = json.dumps(
                {
                    "request_id": request.request_id,
                    "agent_id": request.agent_id,
                    "action": request.action,
                    "reason": request.reason,
                    "created_at": request.created_at.isoformat(),
                },
                default=str,
            ).encode()
            req = urllib.request.Request(
                self._webhook_url,
                data=payload,
                headers={**self._headers, "Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
            logger.info("Escalation webhook sent for %s", request.request_id)
        except Exception:
            logger.warning(
                "Failed to send escalation webhook for %s",
                request.request_id,
                exc_info=True,
            )

    def get_decision(self, request_id: str) -> EscalationRequest | None:
        return self._inner.get_decision(request_id)

    def approve(self, request_id: str, approver: str = "") -> bool:
        return self._inner.approve(request_id, approver)

    def deny(self, request_id: str, approver: str = "") -> bool:
        return self._inner.deny(request_id, approver)

    def list_pending(self) -> list[EscalationRequest]:
        return self._inner.list_pending()


class EscalationHandler:
    """Manages escalation lifecycle: submit, wait, resolve.

    Args:
        backend: The approval backend to use.
        timeout_seconds: How long to wait for a human decision.
        default_action: What to do if the timeout expires.
        on_escalate: Optional callback fired when an escalation is created.
        quorum: Optional quorum configuration for M-of-N approval.
            When set, approvals/denials are counted against quorum
            thresholds before a final decision is reached.
        fatigue_window_seconds: Rolling window (in seconds) for fatigue
            detection.  Defaults to 60 (one minute).
        fatigue_threshold: Maximum number of escalations per agent within
            the fatigue window.  If exceeded, new escalations are
            auto-denied.  ``None`` disables fatigue detection.
    """

    def __init__(
        self,
        backend: ApprovalBackend | None = None,
        timeout_seconds: float = 300,
        default_action: DefaultTimeoutAction = DefaultTimeoutAction.DENY,
        on_escalate: Callable[[EscalationRequest], None] | None = None,
        quorum: QuorumConfig | None = None,
        fatigue_window_seconds: float = 60.0,
        fatigue_threshold: int | None = None,
    ) -> None:
        self.backend = backend or InMemoryApprovalQueue()
        self.timeout_seconds = timeout_seconds
        self.default_action = default_action
        self._on_escalate = on_escalate
        self.quorum = quorum
        self._fatigue_window = fatigue_window_seconds
        self._fatigue_threshold = fatigue_threshold
        # Per-agent escalation timestamps for fatigue detection
        self._escalation_times: dict[str, list[datetime]] = {}

    def _check_fatigue(self, agent_id: str) -> bool:
        """Return True if the agent is triggering escalations too rapidly.

        When fatigue detection is enabled, auto-DENY prevents an agent
        from overwhelming human reviewers with a flood of requests (the
        approval-fatigue attack described in Ona/Veto research).
        """
        if self._fatigue_threshold is None:
            return False

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._fatigue_window)
        times = self._escalation_times.get(agent_id, [])
        # Prune old timestamps
        recent = [t for t in times if t > cutoff]
        self._escalation_times[agent_id] = recent
        return len(recent) >= self._fatigue_threshold

    def escalate(
        self,
        agent_id: str,
        action: str,
        reason: str,
        context_snapshot: dict[str, Any] | None = None,
    ) -> EscalationRequest:
        """Create and submit an escalation request.

        If fatigue detection is enabled and the agent has exceeded the
        threshold, the request is immediately auto-denied.

        Returns:
            The ``EscalationRequest`` — PENDING normally, DENY if fatigued.
        """
        # Fatigue check
        if self._check_fatigue(agent_id):
            logger.warning(
                "Escalation fatigue: agent %s exceeded %d escalations in %.0fs — auto-DENY",
                agent_id,
                self._fatigue_threshold,
                self._fatigue_window,
            )
            request = EscalationRequest(
                agent_id=agent_id,
                action=action,
                reason=f"Auto-denied: escalation fatigue ({reason})",
                context_snapshot=context_snapshot or {},
                decision=EscalationDecision.DENY,
                resolved_at=datetime.now(timezone.utc),
                resolved_by="system:fatigue_detector",
            )
            return request

        # Record timestamp for fatigue tracking
        self._escalation_times.setdefault(agent_id, []).append(
            datetime.now(timezone.utc)
        )

        request = EscalationRequest(
            agent_id=agent_id,
            action=action,
            reason=reason,
            context_snapshot=context_snapshot or {},
        )
        self.backend.submit(request)
        logger.info(
            "Escalation %s created for agent %s: %s",
            request.request_id,
            agent_id,
            reason,
        )
        if self._on_escalate:
            self._on_escalate(request)
        return request

    def resolve(self, request_id: str) -> EscalationDecision:
        """Check or wait for a resolution.

        For ``InMemoryApprovalQueue``, this blocks up to ``timeout_seconds``.
        For other backends, this polls once and returns the current state.

        When quorum is configured, the decision is evaluated against
        quorum thresholds instead of accepting a single vote.

        Returns:
            The final decision. If the timeout expires, applies the
            ``default_action`` and returns that.
        """
        if isinstance(self.backend, InMemoryApprovalQueue):
            decision = self.backend.wait_for_decision(
                request_id, timeout=self.timeout_seconds
            )
        else:
            req = self.backend.get_decision(request_id)
            decision = req.decision if req else EscalationDecision.PENDING

        # Quorum evaluation
        if self.quorum and decision != EscalationDecision.PENDING:
            req = self.backend.get_decision(request_id)
            if req:
                approvals = sum(1 for _, v, _ in req.votes if v == "ALLOW")
                denials = sum(1 for _, v, _ in req.votes if v == "DENY")

                if denials >= self.quorum.required_denials:
                    return EscalationDecision.DENY
                if approvals >= self.quorum.required_approvals:
                    return EscalationDecision.ALLOW
                # Not enough votes yet — treat as pending/timeout
                decision = EscalationDecision.PENDING

        if decision == EscalationDecision.PENDING:
            # Timeout — apply default
            decision = (
                EscalationDecision.ALLOW
                if self.default_action == DefaultTimeoutAction.ALLOW
                else EscalationDecision.DENY
            )
            logger.warning(
                "Escalation %s timed out after %.0fs, defaulting to %s",
                request_id,
                self.timeout_seconds,
                decision.value,
            )
        return decision


@dataclass
class EscalationResult:
    """Result of an escalation policy evaluation."""

    action: str
    decision: EscalationDecision
    reason: Optional[str]
    request: Optional[EscalationRequest] = None
    policy_name: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EscalationPolicy:
    """Wraps a BaseIntegration with human-in-the-loop escalation.

    When ``require_human_approval`` is True in the policy, instead of
    immediately denying the action, this wrapper **suspends** execution
    and routes an approval request to the configured handler.

    This is the ``ESCALATE`` tier between ALLOW and DENY.

    Args:
        integration: The governance integration to wrap.
        handler: The escalation handler managing approvals.
        policy_name: Name for audit logging.
    """

    def __init__(
        self,
        integration: BaseIntegration,
        handler: EscalationHandler | None = None,
        *,
        policy_name: str = "default",
    ) -> None:
        self._integration = integration
        self._handler = handler or EscalationHandler()
        self._policy_name = policy_name

    @property
    def handler(self) -> EscalationHandler:
        return self._handler

    def evaluate(
        self,
        action: str,
        context: ExecutionContext,
        input_data: Any = None,
    ) -> EscalationResult:
        """Evaluate a policy check with escalation support.

        If the policy would deny due to ``require_human_approval``,
        this creates an escalation request instead of blocking.

        For all other deny reasons (blocked patterns, timeouts, etc.),
        the action is denied immediately — escalation only applies
        to the human-approval gate.

        Returns:
            An ``EscalationResult`` with the decision and optional
            escalation request.
        """
        allowed, reason = self._integration.pre_execute(context, input_data)

        if allowed:
            return EscalationResult(
                action=action,
                decision=EscalationDecision.ALLOW,
                reason=None,
                policy_name=self._policy_name,
            )

        # Check if this denial was due to human approval requirement
        if self._integration.policy.require_human_approval and reason and (
            "human approval" in reason.lower()
        ):
            request = self._handler.escalate(
                agent_id=context.agent_id,
                action=action,
                reason=reason,
                context_snapshot={
                    "session_id": context.session_id,
                    "call_count": context.call_count,
                    "total_tokens": context.total_tokens,
                    "input_summary": str(input_data)[:500] if input_data else "",
                },
            )
            self._integration.emit(
                GovernanceEventType.POLICY_CHECK,
                {
                    "agent_id": context.agent_id,
                    "action": action,
                    "escalation_id": request.request_id,
                    "phase": "escalated",
                },
            )
            return EscalationResult(
                action=action,
                decision=EscalationDecision.PENDING,
                reason=reason,
                request=request,
                policy_name=self._policy_name,
            )

        # Hard deny (not an escalation scenario)
        return EscalationResult(
            action=action,
            decision=EscalationDecision.DENY,
            reason=reason,
            policy_name=self._policy_name,
        )

    def resolve(self, request_id: str) -> EscalationDecision:
        """Wait for and return the human decision on an escalation.

        Delegates to the handler's resolve method, which blocks or
        polls depending on the backend.
        """
        return self._handler.resolve(request_id)

    def evaluate_and_wait(
        self,
        action: str,
        context: ExecutionContext,
        input_data: Any = None,
    ) -> EscalationResult:
        """Evaluate and, if escalated, block until resolved.

        Convenience method that combines ``evaluate()`` and ``resolve()``.
        """
        result = self.evaluate(action, context, input_data)
        if result.decision == EscalationDecision.PENDING and result.request:
            final = self.resolve(result.request.request_id)
            result.decision = final
        return result
