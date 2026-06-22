# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Wiring the versioned webhook transport into govern via the coordinator (ADR-0030)."""

import json

import pytest

from agentmesh.governance.approval import ApprovalDecision
from agentmesh.governance.approval_bridge import ApprovalTransport, submit_vote
from agentmesh.governance.approval_protocol import (
    ActionBinding,
    ActionTarget,
    ApprovalChain,
    ApprovalCoordinator,
    ApprovalStage,
    EntryDecision,
    InMemoryApprovalStore,
)
from agentmesh.governance.approval_webhook import VersionedWebhookApproval
from agentmesh.governance.govern import GovernanceDenied, govern

ALICE = "alice"

REQUIRE_APPROVAL_POLICY = """
apiVersion: governance.toolkit/v1
name: webhook-approval-test
agents: ["*"]
default_action: allow
rules:
  - name: approve-transfer
    condition: "action.type == 'transfer'"
    action: require_approval
    priority: 100
"""


def _coord(identities=frozenset({ALICE})):
    chain = ApprovalChain(
        "default", "1", (ApprovalStage(0, allowed_identities=identities),)
    )
    return ApprovalCoordinator(InMemoryApprovalStore(), {chain.chain_id: chain})


def _binding():
    return ActionBinding(
        operation="tool.invoke", agent_id="a", target=ActionTarget("t", "1")
    )


def _open(coord):
    _, request = coord.open_request(
        _binding(),
        policy_rule_id="r",
        policy_version="v1",
        chain_id="default",
        ttl_seconds=300,
    )
    return request


def _transfer(**kwargs):
    return "transfer-done"


def _verifier(body, request):
    return body.get("approver") if body.get("identity_assertion") == "valid" else None


def _echo_transport(approved=True, approver=ALICE, assertion="valid", capture=None):
    def transport(url, data, headers, timeout):
        payload = json.loads(data.decode("utf-8"))
        if capture is not None:
            capture["payload"] = payload
        return {
            "approval_request_id": payload["approval_request_id"],
            "action_digest": payload["action_digest"],
            "approved": approved,
            "approver": approver,
            "identity_assertion": assertion,
        }

    return transport


def _webhook(transport, verifier=_verifier):
    return VersionedWebhookApproval(
        "https://example.com/approve", response_verifier=verifier, transport=transport
    )


def _governed(coord, webhook):
    return govern(
        _transfer,
        policy=REQUIRE_APPROVAL_POLICY,
        approval_coordinator=coord,
        approval_chain_id="default",
        approval_transport=webhook,
    )


class TestSubmitVote:
    def test_approve_records_allow_entry(self):
        coord = _coord()
        request = _open(coord)
        result = submit_vote(
            coord, request, ApprovalDecision(approved=True, approver=ALICE, reason="ok")
        )
        assert result.submitted and result.entry.decision == EntryDecision.ALLOW
        assert result.error is None

    def test_unpermitted_identity_fails_closed(self):
        coord = _coord()
        request = _open(coord)
        result = submit_vote(
            coord, request, ApprovalDecision(approved=True, approver="mallory")
        )
        assert not result.submitted and result.error

    def test_versioned_webhook_satisfies_transport_protocol(self):
        assert isinstance(_webhook(_echo_transport()), ApprovalTransport)


class TestGovernWebhookTransport:
    def test_approve_runs_tool_and_webhook_receives_binding(self):
        capture = {}
        g = _governed(_coord(), _webhook(_echo_transport(capture=capture)))
        assert g(action="transfer", amount=100) == "transfer-done"
        # The webhook payload carried the action binding and versioned envelope.
        assert capture["payload"]["action_digest"].startswith("sha256:")
        assert capture["payload"]["schema_version"] == "1.0"
        assert capture["payload"]["policy_version"]

    def test_deny_is_denied(self):
        g = _governed(_coord(), _webhook(_echo_transport(approved=False)))
        with pytest.raises(GovernanceDenied):
            g(action="transfer", amount=100)

    def test_unverified_identity_is_denied(self):
        g = _governed(_coord(), _webhook(_echo_transport(assertion="forged")))
        with pytest.raises(GovernanceDenied):
            g(action="transfer", amount=100)

    def test_binding_mismatch_is_denied(self):
        # A webhook that echoes the wrong action digest must not release.
        def tamper(url, data, headers, timeout):
            payload = json.loads(data.decode("utf-8"))
            return {
                "approval_request_id": payload["approval_request_id"],
                "action_digest": "sha256:tampered",
                "approved": True,
                "approver": ALICE,
                "identity_assertion": "valid",
            }

        g = _governed(_coord(), _webhook(tamper))
        with pytest.raises(GovernanceDenied):
            g(action="transfer", amount=100)
