# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Human-in-the-loop approval queue and handler primitives.

Native policy runtimes own escalation decisions and invoke their configured
approval resolver. This module provides host-side approval backends, quorum
handling, timeout behavior, and auditable request state.
"""

from __future__ import annotations

import abc
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Optional


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
            if req is None:
                return False
            if not approver.strip():
                return False
            if any(a == approver for a, _, _ in req.votes):
                return False
            req.votes.append((approver, "ALLOW", datetime.now(timezone.utc)))
            if req.decision == EscalationDecision.PENDING:
                req.decision = EscalationDecision.ALLOW
                req.resolved_by = approver
                req.resolved_at = datetime.now(timezone.utc)
            # Fire on every accepted vote, not just the one that first sets
            # req.decision, wait_for_quorum() (see below) needs a wake-up
            # for each subsequent vote too, to re-check quorum promptly
            # instead of blocking for the remainder of the timeout even
            # after enough votes have already arrived.
            event = self._events.get(request_id)
        if event:
            event.set()
        return True

    def deny(self, request_id: str, approver: str = "") -> bool:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return False
            if not approver.strip():
                return False
            if any(a == approver for a, _, _ in req.votes):
                return False
            req.votes.append((approver, "DENY", datetime.now(timezone.utc)))
            if req.decision == EscalationDecision.PENDING:
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

    def wait_for_quorum(
        self,
        request_id: str,
        timeout: float | None,
        is_satisfied: Callable[[EscalationRequest], bool],
    ) -> EscalationRequest | None:
        """Block until ``is_satisfied(request)`` is true, or until
        ``timeout`` seconds have elapsed *in total* since this call started.

        Unlike :meth:`wait_for_decision`, which returns as soon as the
        underlying event fires once, this re-checks ``is_satisfied`` after
        every vote and keeps waiting for the remaining time budget if it
        still isn't met. The per-request ``threading.Event`` is fired by
        ``approve``/``deny`` on every accepted vote; re-arming it here with
        ``clear()`` -- always while holding ``self._lock``, the same lock
        ``approve``/``deny`` hold while mutating the request and before
        they call ``set()``, means no vote recorded between our check
        and the next ``wait()`` can be missed.

        Returns:
            The ``EscalationRequest`` (whatever its latest state is when
            ``is_satisfied`` becomes true or time runs out), or ``None``
            if the request is unknown.
        """
        event = self._events.get(request_id)
        if event is None:
            return self._requests.get(request_id)

        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                req = self._requests.get(request_id)
                if req is None or is_satisfied(req):
                    return req
                # Not satisfied yet, re-arm so the next approve()/deny()
                # wakes us again. Safe: still holding self._lock here, and
                # approve()/deny() only call set() after releasing it, so
                # any vote racing with this clear() is strictly ordered
                # before or after this critical section, never lost.
                event.clear()

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    with self._lock:
                        return self._requests.get(request_id)
            else:
                remaining = None

            event.wait(timeout=remaining)


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
            req = urllib.request.Request(  # noqa: S310 — webhook URL from configuration
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

    def _quorum_outcome(self, req: EscalationRequest) -> EscalationDecision | None:
        """Evaluate ``req.votes`` against ``self.quorum``.

        Returns ``ALLOW``/``DENY`` once enough votes are in to decide,
        or ``None`` if quorum has not been satisfied yet. Single source
        of truth for the vote tally. Used both as the wait predicate
        and for the final decision, so the two can never disagree.
        """
        assert self.quorum is not None
        approvals = sum(1 for _, v, _ in req.votes if v == "ALLOW")
        denials = sum(1 for _, v, _ in req.votes if v == "DENY")
        if denials >= self.quorum.required_denials:
            return EscalationDecision.DENY
        if approvals >= self.quorum.required_approvals:
            return EscalationDecision.ALLOW
        return None

    def resolve(self, request_id: str) -> EscalationDecision:
        """Check or wait for a resolution.

        For ``InMemoryApprovalQueue``, this blocks up to ``timeout_seconds``.
        For other backends, this polls once and returns the current state.

        When quorum is configured, the decision is evaluated against
        quorum thresholds instead of accepting a single vote. With
        ``InMemoryApprovalQueue``, this waits across all votes that
        arrive within ``timeout_seconds``, not just the first one,
        so an M-of-N quorum gets its full window to collect M votes.

        Note:
            Quorum with a non-``InMemoryApprovalQueue`` backend (e.g.
            :class:`WebhookApprovalBackend`) still only polls once; it
            cannot block on new votes the way the in-memory queue can.
            Calling ``resolve()`` again does not help: if quorum is
            unmet, this method applies ``default_action`` immediately on
            the very first call, regardless of ``timeout_seconds``; it
            does not wait, and repeated polling will keep returning the
            same default rather than the outcome of later votes. Configure
            quorum with an in-memory backend if you need real waiting.

        Returns:
            The final decision. For a non-blocking backend with quorum
            configured, an unmet quorum resolves to ``default_action``
            immediately, see the Note above.
        """
        if isinstance(self.backend, InMemoryApprovalQueue):
            if self.quorum:
                req = self.backend.wait_for_quorum(
                    request_id,
                    timeout=self.timeout_seconds,
                    is_satisfied=lambda r: self._quorum_outcome(r) is not None,
                )
                decision = req.decision if req else EscalationDecision.PENDING
            else:
                req = None
                decision = self.backend.wait_for_decision(
                    request_id, timeout=self.timeout_seconds
                )
        else:
            req = self.backend.get_decision(request_id)
            decision = req.decision if req else EscalationDecision.PENDING

        # Quorum evaluation (also catches the non-blocking backend case
        # above, and re-derives the decision from votes either way so a
        # raw req.decision set by a single approve()/deny() call never
        # leaks through without being checked against quorum).
        if self.quorum and decision != EscalationDecision.PENDING:
            decision = (
                (self._quorum_outcome(req) if req else None)
                or EscalationDecision.PENDING
            )

        if decision == EscalationDecision.PENDING:
            # No settled decision (or quorum unmet) — apply default.
            decision = (
                EscalationDecision.ALLOW
                if self.default_action == DefaultTimeoutAction.ALLOW
                else EscalationDecision.DENY
            )
            blocked_wait = isinstance(self.backend, InMemoryApprovalQueue)
            logger.warning(
                "Escalation %s %s, defaulting to %s",
                request_id,
                (
                    f"timed out after {self.timeout_seconds:.0f}s"
                    if blocked_wait
                    else "has an unresolved decision on a non-blocking "
                    f"backend (quorum unmet or no vote yet; "
                    f"timeout_seconds={self.timeout_seconds:.0f}s was not "
                    "actually waited)"
                ),
                decision.value,
            )
        return decision
