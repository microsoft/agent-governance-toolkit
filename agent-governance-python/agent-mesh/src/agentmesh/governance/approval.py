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
import os
import time
import warnings
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# Strict mode (ADR-0030 section 9, step 5) rejects the two unsafe legacy
# behaviors this module retains for backward compatibility: timeout
# auto-approval and trusting an unverified, body-supplied approver identity.
# Off by default (deprecation warnings only); enable per-handler with
# ``strict=True`` or globally with AGT_APPROVAL_STRICT=1. The environment
# variable is a floor: per-handler ``strict=False`` cannot loosen it.
_STRICT_ENV = "AGT_APPROVAL_STRICT"


def _strict_mode(explicit: bool | None) -> bool:
    """Resolve the effective strict mode for a handler."""
    env = os.environ.get(_STRICT_ENV, "").strip().lower() in ("1", "true", "yes", "on")
    return bool(explicit) or env


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
        default_factory=lambda: datetime.now(UTC)
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
        default_factory=lambda: datetime.now(UTC)
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
        on_timeout: Deprecated. Timeouts always deny regardless of this value.
            Passing any value other than ``"deny"`` emits ``FutureWarning`` and
            raises ``ValueError`` when strict mode is enabled.
        strict: Optional opt-in to strict approval handling. When enabled,
            deprecated unsafe values are rejected at construction time.
    """

    def __init__(
        self,
        callback: Callable[[ApprovalRequest], ApprovalDecision],
        timeout_seconds: float = 300,
        on_timeout: str = "deny",
        *,
        strict: bool | None = None,
    ):
        # Timeout auto-approval is unsafe at a governance boundary (ADR-0030
        # section 9). A timeout always denies; ``on_timeout`` is deprecated and
        # any non-"deny" value is rejected in strict mode.
        if on_timeout != "deny":
            message = (
                "CallbackApproval on_timeout is deprecated: timeout auto-approval "
                "is unsafe and unsupported, so a timeout always denies. Remove the "
                "on_timeout argument."
            )
            if _strict_mode(strict):
                raise ValueError(message)
            warnings.warn(message, FutureWarning, stacklevel=2)
        self._callback = callback
        self._timeout = timeout_seconds

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
        print("APPROVAL REQUIRED")
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
        headers: dict[str, str] | None = None,
        *,
        strict: bool | None = None,
    ):
        from agentmesh.governance.advisory import _validate_webhook_url

        _validate_webhook_url(url)
        self._url = url
        self._timeout = timeout_seconds
        self._headers = headers or {}
        # This handler trusts an unverified, body-supplied approver identity,
        # which ADR-0030 section 5 forbids. Use VersionedWebhookApproval
        # (agentmesh.governance.approval_webhook) for the action-bound contract.
        message = (
            "WebhookApproval is deprecated: it trusts an unverified body-supplied "
            "approver identity. Use VersionedWebhookApproval (ADR-0030)."
        )
        if _strict_mode(strict):
            raise ValueError(message)
        warnings.warn(
            message,
            FutureWarning,
            stacklevel=2,
        )

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        import json
        import urllib.request

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
                approved = body.get("approved", False)
                return ApprovalDecision(
                    approved=approved,
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
