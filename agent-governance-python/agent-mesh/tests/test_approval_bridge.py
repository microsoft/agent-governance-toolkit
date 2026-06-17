# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the legacy-handler -> protocol compatibility bridge (ADR-0030 step 3)."""

from agentmesh.governance.approval import (
    ApprovalDecision,
    ApprovalRequest,
    CallbackApproval,
)
from agentmesh.governance.approval_bridge import AdapterResult, LegacyHandlerAdapter
from agentmesh.governance.approval_protocol import (
    ActionBinding,
    ActionTarget,
    ApprovalChain,
    ApprovalCoordinator,
    ApprovalStage,
    ApproverKind,
    EntryDecision,
    InMemoryApprovalStore,
    Outcome,
)

ALICE = "alice"


def _coord(identities=frozenset({ALICE})):
    chain = ApprovalChain("c", "1", (ApprovalStage(0, allowed_identities=identities),))
    return ApprovalCoordinator(InMemoryApprovalStore(), {chain.chain_id: chain})


def _binding():
    return ActionBinding(
        operation="tool.invoke", agent_id="a", target=ActionTarget("t", "1")
    )


def _open(coord, ttl_seconds=300):
    _, request = coord.open_request(
        _binding(),
        policy_rule_id="r",
        policy_version="v1",
        chain_id="c",
        ttl_seconds=ttl_seconds,
    )
    return request


def _legacy_request():
    return ApprovalRequest(action="transfer", rule_name="r", policy_name="p", agent_id="a")


def _handler(approved=True, approver=ALICE, reason="ok"):
    return CallbackApproval(
        lambda req: ApprovalDecision(approved=approved, approver=approver, reason=reason)
    )


class TestLegacyHandlerAdapter:
    def test_approve_submits_allow_entry_and_resolves(self):
        coord = _coord()
        request = _open(coord)
        result = LegacyHandlerAdapter(_handler(approved=True)).collect(
            coord, request, _legacy_request()
        )
        assert isinstance(result, AdapterResult)
        assert result.submitted and result.entry is not None
        assert result.error is None
        assert result.entry.decision == EntryDecision.ALLOW
        assert result.entry.approver_identity == ALICE
        resolution = coord.store.get_resolution(request.approval_request_id)
        assert resolution is not None and resolution.outcome == Outcome.ALLOW

    def test_reject_submits_deny_entry(self):
        coord = _coord()
        request = _open(coord)
        result = LegacyHandlerAdapter(_handler(approved=False)).collect(
            coord, request, _legacy_request()
        )
        assert result.submitted
        assert result.entry.decision == EntryDecision.DENY
        resolution = coord.store.get_resolution(request.approval_request_id)
        assert resolution is not None and resolution.outcome == Outcome.DENY

    def test_unpermitted_identity_fails_closed(self):
        coord = _coord()
        request = _open(coord)
        result = LegacyHandlerAdapter(_handler(approver="mallory")).collect(
            coord, request, _legacy_request()
        )
        assert not result.submitted
        assert result.entry is None
        assert result.error and "rejected" in result.error
        # The handler's vote is still reported even though it was not recorded.
        assert result.approval.approver == "mallory"

    def test_expired_request_fails_closed(self):
        coord = _coord()
        request = _open(coord, ttl_seconds=0)
        result = LegacyHandlerAdapter(_handler()).collect(
            coord, request, _legacy_request()
        )
        assert not result.submitted
        assert result.error

    def test_reason_and_approver_propagate(self):
        coord = _coord()
        request = _open(coord)
        result = LegacyHandlerAdapter(_handler(reason="looks-ok")).collect(
            coord, request, _legacy_request()
        )
        assert result.entry.reason_code == "looks-ok"
        assert result.approval.reason == "looks-ok"

    def test_custom_kind_and_assurance(self):
        coord = _coord()
        request = _open(coord)
        adapter = LegacyHandlerAdapter(
            _handler(), approver_kind=ApproverKind.SERVICE, identity_assurance="mtls"
        )
        result = adapter.collect(coord, request, _legacy_request())
        assert result.entry.approver_kind == ApproverKind.SERVICE
        assert result.entry.identity_assurance == "mtls"
