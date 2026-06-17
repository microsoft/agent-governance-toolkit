# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Versioned, action-bound webhook approval contract (ADR-0030 step 4, section 5).

The legacy :class:`~agentmesh.governance.approval.WebhookApproval` sends a thin
payload with no request id, action digest, policy/chain version, or expiry, and
it trusts an ``approver`` string supplied in the response body. ADR-0030 section
5 supersedes that: a webhook is a transport, not an approver identity type, and
the contract must carry the binding and refuse body-supplied identities that are
not backed by a verified assertion.

This module provides that contract against the merged protocol foundation:

* :func:`build_webhook_request` builds the schema-versioned, action-bound
  request payload from a protocol :class:`ApprovalRequest`;
* :func:`parse_webhook_response` validates the response echoes the binding and
  only honours an approve when the approver identity is verified;
* :class:`VersionedWebhookApproval` is the protocol-native transport. It takes
  the protocol request (the legacy ``ApprovalHandler.request_approval``
  signature is too thin to carry the action digest), POSTs the payload with
  caller-supplied auth headers, and fails closed on timeout, transport error,
  malformed response, or binding mismatch.

It depends only on the protocol foundation and the legacy ``ApprovalDecision``
result type; it does not modify ``govern`` or the foundation package. Wiring the
transport into the govern/bridge flow is a separate follow-up.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

from .advisory import _validate_webhook_url
from .approval import ApprovalDecision
from .approval_protocol import ApprovalRequest

logger = logging.getLogger(__name__)

WEBHOOK_SCHEMA_VERSION = "1.0"

# A verifier maps (response_body, request) to the verified approver principal,
# or None when the identity cannot be trusted. It is the single extension point
# for "bound to authenticated transport or a verified identity assertion".
ResponseVerifier = Callable[[dict, ApprovalRequest], Optional[str]]
Transport = Callable[[str, bytes, dict, float], dict]


def build_webhook_request(
    request: ApprovalRequest, *, schema_version: str = WEBHOOK_SCHEMA_VERSION
) -> dict[str, Any]:
    """Build the versioned, action-bound webhook request payload.

    Carries the ADR-0030 section 5 required fields (request id, policy decision
    id, action digest, policy version, chain version, expiry) by reusing the
    protocol request's canonical presentation, plus the schema version and the
    input digest the approver is asked to attest to.
    """
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "type": "approval_request",
        "input_digest": request.input_digest(),
    }
    payload.update(request.presented_canonical())
    return payload


def _deny(reason: str, *, approver: str = "webhook:rejected") -> ApprovalDecision:
    return ApprovalDecision(approved=False, approver=approver, reason=reason)


def parse_webhook_response(
    body: Any,
    *,
    request: ApprovalRequest,
    response_verifier: Optional[ResponseVerifier] = None,
) -> ApprovalDecision:
    """Validate a webhook response and map it to an :class:`ApprovalDecision`.

    Fail-closed: the response must echo ``approval_request_id`` and
    ``action_digest`` from the request, and an approve is honoured only when the
    approver identity is verified by ``response_verifier``. A deny is always
    honoured (denying is the safe direction). Anything malformed denies.
    """
    if not isinstance(body, dict):
        return _deny("malformed webhook response")

    if body.get("approval_request_id") != request.approval_request_id:
        return _deny("approval_request_id mismatch", approver="webhook:binding-mismatch")
    if body.get("action_digest") != request.action_digest:
        return _deny("action_digest mismatch", approver="webhook:binding-mismatch")

    approved = body.get("approved")
    if approved is None and "decision" in body:
        approved = body.get("decision") == "allow"
    if not isinstance(approved, bool):
        return _deny("missing or malformed 'approved' field")

    reason = str(body.get("reason", ""))

    if not approved:
        return ApprovalDecision(
            approved=False,
            approver=str(body.get("approver") or "webhook"),
            reason=reason or "denied by webhook",
        )

    # Approve path: a body-supplied identity is only trusted when verified.
    principal: Optional[str] = None
    if response_verifier is not None:
        try:
            principal = response_verifier(body, request)
        except Exception as exc:  # a misbehaving verifier must not allow
            return _deny(f"identity verification error: {exc}")
    if not principal:
        return _deny("approve rejected: unverified approver identity")

    return ApprovalDecision(approved=True, approver=str(principal), reason=reason)


class VersionedWebhookApproval:
    """Protocol-native versioned webhook approval transport (ADR-0030 section 5).

    Args:
        url: Webhook endpoint (validated against the SSRF guard).
        timeout_seconds: Max time to wait for the response. Default 300.
        headers: Outbound headers, e.g. a bearer token or HMAC for
            authenticating the remote service.
        response_verifier: Verifies the approver identity in the response and
            returns the trusted principal, or None to deny the approve.
        transport: Optional injected ``(url, data, headers, timeout) -> dict``
            for testing; defaults to a urllib POST.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 300.0,
        headers: Optional[dict[str, str]] = None,
        response_verifier: Optional[ResponseVerifier] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        _validate_webhook_url(url)
        self._url = url
        self._timeout = timeout_seconds
        self._headers = dict(headers or {})
        self._response_verifier = response_verifier
        self._transport = transport

    def request_decision(self, request: ApprovalRequest) -> ApprovalDecision:
        """POST the versioned payload and return the validated decision."""
        data = json.dumps(build_webhook_request(request)).encode("utf-8")
        headers = {"Content-Type": "application/json", **self._headers}
        post = self._transport or self._http_post
        try:
            body = post(self._url, data, headers, self._timeout)
        except Exception as exc:  # timeout, transport, auth, decode
            logger.error("versioned webhook approval error: %s", exc)
            return _deny(f"webhook error: {exc}", approver="system:webhook-error")
        return parse_webhook_response(
            body, request=request, response_verifier=self._response_verifier
        )

    @staticmethod
    def _http_post(url: str, data: bytes, headers: dict, timeout: float) -> dict:
        import urllib.request

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
