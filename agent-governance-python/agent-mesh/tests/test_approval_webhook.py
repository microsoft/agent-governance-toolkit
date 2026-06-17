# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the versioned, action-bound webhook approval contract (ADR-0030 step 4)."""

import json
from datetime import timedelta

import pytest

from agentmesh.governance.approval_protocol import ApprovalRequest, utcnow
from agentmesh.governance.approval_webhook import (
    WEBHOOK_SCHEMA_VERSION,
    VersionedWebhookApproval,
    build_webhook_request,
    parse_webhook_response,
)


def _request():
    return ApprovalRequest(
        policy_decision_id="pd_1",
        action_digest="sha256:abc123",
        agent_id="agent-1",
        operation="tool.invoke",
        policy_version="2026.06.17",
        approval_chain_id="high-risk",
        approval_chain_version="3",
        expires_at=utcnow() + timedelta(seconds=300),
        subject_id="user-1",
        target_resource="prod-db",
    )


def _verifier(body, request):
    # Trust the body-supplied approver only when a valid assertion accompanies it.
    return body.get("approver") if body.get("identity_assertion") == "valid" else None


def _ok_response(request, **overrides):
    body = {
        "approval_request_id": request.approval_request_id,
        "action_digest": request.action_digest,
        "approved": True,
        "approver": "alice",
        "identity_assertion": "valid",
        "reason": "reviewed",
    }
    body.update(overrides)
    return body


class TestBuildWebhookRequest:
    def test_payload_carries_binding_and_versions(self):
        request = _request()
        payload = build_webhook_request(request)
        assert payload["schema_version"] == WEBHOOK_SCHEMA_VERSION
        assert payload["type"] == "approval_request"
        assert payload["approval_request_id"] == request.approval_request_id
        assert payload["action_digest"] == "sha256:abc123"
        assert payload["policy_version"] == "2026.06.17"
        assert payload["approval_chain_version"] == "3"
        assert payload["input_digest"].startswith("sha256:")
        assert "expires_at" in payload


class TestParseWebhookResponse:
    def test_verified_approve(self):
        request = _request()
        decision = parse_webhook_response(
            _ok_response(request), request=request, response_verifier=_verifier
        )
        assert decision.approved
        assert decision.approver == "alice"

    def test_request_id_mismatch_denies(self):
        request = _request()
        decision = parse_webhook_response(
            _ok_response(request, approval_request_id="ar_other"),
            request=request,
            response_verifier=_verifier,
        )
        assert not decision.approved
        assert decision.approver == "webhook:binding-mismatch"

    def test_action_digest_mismatch_denies(self):
        request = _request()
        decision = parse_webhook_response(
            _ok_response(request, action_digest="sha256:tampered"),
            request=request,
            response_verifier=_verifier,
        )
        assert not decision.approved
        assert decision.approver == "webhook:binding-mismatch"

    def test_approve_without_verifier_denies(self):
        request = _request()
        decision = parse_webhook_response(_ok_response(request), request=request)
        assert not decision.approved
        assert "unverified" in decision.reason

    def test_approve_with_unverifiable_identity_denies(self):
        request = _request()
        decision = parse_webhook_response(
            _ok_response(request, identity_assertion="forged"),
            request=request,
            response_verifier=_verifier,
        )
        assert not decision.approved

    def test_explicit_deny_needs_no_verifier(self):
        request = _request()
        decision = parse_webhook_response(
            _ok_response(request, approved=False, approver="bob", reason="too risky"),
            request=request,
        )
        assert not decision.approved
        assert decision.reason == "too risky"

    def test_malformed_denies(self):
        request = _request()
        assert not parse_webhook_response("nope", request=request).approved
        assert not parse_webhook_response(
            {"approval_request_id": request.approval_request_id,
             "action_digest": request.action_digest},
            request=request,
        ).approved  # missing 'approved'


class TestVersionedWebhookApproval:
    def test_request_decision_posts_versioned_payload(self):
        request = _request()
        captured = {}

        def fake_transport(url, data, headers, timeout):
            captured["url"] = url
            captured["payload"] = json.loads(data.decode("utf-8"))
            captured["headers"] = headers
            return _ok_response(request)

        wh = VersionedWebhookApproval(
            "https://example.com/approve",
            headers={"Authorization": "Bearer t"},
            response_verifier=_verifier,
            transport=fake_transport,
        )
        decision = wh.request_decision(request)
        assert decision.approved and decision.approver == "alice"
        assert captured["payload"]["action_digest"] == "sha256:abc123"
        assert captured["payload"]["schema_version"] == WEBHOOK_SCHEMA_VERSION
        assert captured["headers"]["Authorization"] == "Bearer t"

    def test_transport_error_fails_closed(self):
        def boom(url, data, headers, timeout):
            raise TimeoutError("timed out")

        wh = VersionedWebhookApproval("https://example.com/a", transport=boom)
        decision = wh.request_decision(_request())
        assert not decision.approved
        assert "webhook error" in decision.reason

    def test_bad_url_rejected(self):
        with pytest.raises(ValueError):
            VersionedWebhookApproval("ftp://evil/approve")
