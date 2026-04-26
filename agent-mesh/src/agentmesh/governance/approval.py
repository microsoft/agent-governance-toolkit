# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Human-in-the-loop approval workflows for policy-gated agent actions.

When a policy rule returns ``require_approval``, the approval handler
pauses execution, requests human approval, and resumes or denies
based on the response.

Usage::

    from agentmesh.governance.approval import (
        CallbackApproval, AutoRejectApproval,
    )
    from agentmesh.governance import govern

    handler = CallbackApproval(lambda req: ApprovalDecision(approved=True, approver="admin"))
    safe = govern(my_tool, policy="policy.yaml", approval_handler=handler)
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ApprovalRequest:
    """Details of an action awaiting approval.

    Attributes:
        action: Description of the action (from policy context).
        rule_name: Name of the policy rule that triggered approval.
        policy_name: Name of the policy containing the rule.
        agent_id: Identifier of the acting agent.
        context: Full evaluation context.
        approvers: List of required approvers from the policy rule.
        requested_at: When the approval was requested.
    """

    action: str
    rule_name: str
    policy_name: str
    agent_id: str
    context: dict = field(default_factory=dict)
    approvers: list[str] = field(default_factory=list)
    requested_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class ApprovalDecision:
    """Result of an approval request.

    Attributes:
        approved: Whether the action was approved.
        approver: Identity of the person who approved/denied.
        reason: Optional explanation.
        decided_at: When the decision was made.
    """

    approved: bool
    approver: str = ""
    reason: str = ""
    decided_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ApprovalHandler(ABC):
    """Abstract base class for approval handlers."""

    @abstractmethod
    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        """Request approval for a policy-gated action.

        Implementations may block (waiting for human input), call an
        external service, or auto-decide.

        Args:
            request: Details of the action awaiting approval.

        Returns:
            An ``ApprovalDecision`` indicating whether the action is approved.
        """


class AutoRejectApproval(ApprovalHandler):
    """Automatically rejects all approval requests (fail-safe default).

    Use in production to ensure ``require_approval`` actions are denied
    when no human reviewer is configured.

    Args:
        reason: Rejection reason included in the decision.
    """

    def __init__(self, reason: str = "No approval handler configured — auto-rejected"):
        self._reason = reason

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        logger.warning(
            "Auto-rejecting approval for rule '%s' — no handler configured",
            request.rule_name,
        )
        return ApprovalDecision(
            approved=False,
            approver="system:auto-reject",
            reason=self._reason,
        )


class CallbackApproval(ApprovalHandler):
    """Delegates approval to a custom callback function.

    Args:
        callback: Function that receives an ``ApprovalRequest`` and
            returns an ``ApprovalDecision``.
        timeout_seconds: Max time to wait for callback. Default 300 (5 min).
        on_timeout: Action when timeout expires. Default: deny.
    """

    def __init__(
        self,
        callback: Callable[[ApprovalRequest], ApprovalDecision],
        timeout_seconds: float = 300,
        on_timeout: str = "deny",
    ):
        self._callback = callback
        self._timeout = timeout_seconds
        self._on_timeout = on_timeout

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        start = time.monotonic()
        try:
            decision = self._callback(request)
            elapsed = time.monotonic() - start
            if elapsed > self._timeout:
                logger.warning(
                    "Approval callback took %.1fs (timeout=%.0fs) — enforcing timeout",
                    elapsed, self._timeout,
                )
                return ApprovalDecision(
                    approved=False,
                    approver="system:timeout",
                    reason=f"Approval timed out after {self._timeout}s",
                )
            return decision
        except Exception as e:
            logger.error("Approval callback error: %s", e, exc_info=True)
            return ApprovalDecision(
                approved=False,
                approver="system:error",
                reason=f"Approval callback error: {e}",
            )


class ConsoleApproval(ApprovalHandler):
    """Interactive console-based approval for development/testing.

    Prompts the user via stdin. NOT for production use.
    """

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        print(f"\n{'='*60}")
        print(f"APPROVAL REQUIRED")
        print(f"{'='*60}")
        print(f"  Rule:    {request.rule_name}")
        print(f"  Policy:  {request.policy_name}")
        print(f"  Agent:   {request.agent_id}")
        print(f"  Action:  {request.action}")
        if request.approvers:
            print(f"  Approvers: {', '.join(request.approvers)}")
        print(f"{'='*60}")

        try:
            response = input("Approve? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            response = "n"

        approved = response in ("y", "yes")
        return ApprovalDecision(
            approved=approved,
            approver="console:interactive",
            reason="Approved by console" if approved else "Rejected by console",
        )


class WebhookApproval(ApprovalHandler):
    """HTTP webhook-based approval (Slack, Teams, PagerDuty, etc.).

    Posts an approval request to a URL and polls or waits for a
    callback response.

    Args:
        url: Webhook endpoint URL.
        timeout_seconds: Max time to wait. Default 300 (5 min).
        headers: Optional HTTP headers (e.g., auth tokens).
    """

    def __init__(
        self,
        url: str,
        timeout_seconds: float = 300,
        headers: Optional[dict[str, str]] = None,
    ):
        self._url = url
        self._timeout = timeout_seconds
        self._headers = headers or {}

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        import urllib.request
        import json

        payload = json.dumps({
            "type": "approval_request",
            "rule_name": request.rule_name,
            "policy_name": request.policy_name,
            "agent_id": request.agent_id,
            "action": request.action,
            "approvers": request.approvers,
            "requested_at": request.requested_at.isoformat(),
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            **self._headers,
        }

        try:
            req = urllib.request.Request(
                self._url, data=payload, headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return ApprovalDecision(
                    approved=body.get("approved", False),
                    approver=body.get("approver", "webhook"),
                    reason=body.get("reason", ""),
                )
        except Exception as e:
            logger.error("Webhook approval error: %s", e)
            return ApprovalDecision(
                approved=False,
                approver="system:webhook-error",
                reason=f"Webhook error: {e}",
            )
