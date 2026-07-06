# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Routing require_approval through the action-bound coordinator (ADR-0030, #3067)."""

import pytest

from agentmesh.governance.approval import ApprovalDecision, CallbackApproval
from agentmesh.governance.approval_protocol import (
    ApprovalChain,
    ApprovalCoordinator,
    ApprovalStage,
    InMemoryApprovalStore,
)
from agentmesh.governance.govern import GovernanceDenied, govern

ALICE = "alice"

REQUIRE_APPROVAL_POLICY = """
apiVersion: governance.toolkit/v1
name: approval-coord-test
agents: ["*"]
default_action: allow
rules:
  - name: approve-transfer
    condition: "action.type == 'transfer'"
    action: require_approval
    approvers: ["alice"]
    priority: 100
"""


def _transfer(**kwargs):
    return "transfer-done"


def _coordinator(identities=frozenset({ALICE})):
    chain = ApprovalChain(
        "default", "1", (ApprovalStage(0, allowed_identities=identities),)
    )
    return ApprovalCoordinator(InMemoryApprovalStore(), {chain.chain_id: chain})


def _approver(approved=True, approver=ALICE):
    return CallbackApproval(
        lambda req: ApprovalDecision(approved=approved, approver=approver)
    )


def _governed(coord, handler, **extra):
    return govern(
        _transfer,
        policy=REQUIRE_APPROVAL_POLICY,
        approval_handler=handler,
        approval_coordinator=coord,
        approval_chain_id="default",
        **extra,
    )


class TestRequireApprovalViaCoordinator:
    def test_approved_runs_the_tool(self):
        g = _governed(_coordinator(), _approver(approved=True))
        assert g(action="transfer", amount=100) == "transfer-done"

    def test_rejected_denies(self):
        g = _governed(_coordinator(), _approver(approved=False))
        with pytest.raises(GovernanceDenied):
            g(action="transfer", amount=100)

    def test_unpermitted_identity_denies(self):
        # The approver identity is not permitted by the chain stage: fail closed.
        g = _governed(_coordinator(), _approver(approved=True, approver="mallory"))
        with pytest.raises(GovernanceDenied):
            g(action="transfer", amount=100)

    def test_zero_ttl_denies_fail_closed(self):
        # An already-expired request must deny even on an approve vote.
        g = _governed(_coordinator(), _approver(approved=True), approval_ttl_seconds=0)
        with pytest.raises(GovernanceDenied):
            g(action="transfer", amount=100)

    def test_audit_links_protocol_ids(self):
        g = _governed(_coordinator(), _approver(approved=True))
        g(action="transfer", amount=100)
        entries = g.audit_log.get_entries_by_type("approval_decision")
        assert entries, "expected an approval_decision audit entry"
        entry = entries[-1]
        assert entry.arguments_hash and entry.arguments_hash.startswith("sha256:")
        assert entry.approver_did == ALICE
        assert entry.policy_version
        assert entry.data.get("approval_request_id")
        assert entry.data.get("approval_resolution_id")

    def test_action_digest_is_bound_to_parameters(self):
        # Different parameters must produce different action digests in the log.
        g1 = _governed(_coordinator(), _approver(approved=True))
        g1(action="transfer", amount=100)
        g2 = _governed(_coordinator(), _approver(approved=True))
        g2(action="transfer", amount=999)
        d1 = g1.audit_log.get_entries_by_type("approval_decision")[-1].arguments_hash
        d2 = g2.audit_log.get_entries_by_type("approval_decision")[-1].arguments_hash
        assert d1 != d2

    def test_non_approval_action_is_unaffected(self):
        # An action that does not match the require_approval rule is allowed and
        # never touches the coordinator.
        g = _governed(_coordinator(), _approver(approved=True))
        assert g(action="read") == "transfer-done"

    def test_legacy_path_without_coordinator(self):
        # No coordinator configured: the legacy handler path is unchanged.
        g = govern(
            _transfer,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=_approver(approved=True),
        )
        assert g(action="transfer", amount=100) == "transfer-done"
