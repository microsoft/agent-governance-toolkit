# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for human-in-the-loop approval workflows."""

import pytest
from agentmesh.governance.approval import (
    ApprovalRequest,
    ApprovalDecision,
    AutoRejectApproval,
    CallbackApproval,
)
from agentmesh.governance.govern import govern, GovernanceDenied


REQUIRE_APPROVAL_POLICY = """
apiVersion: governance.toolkit/v1
name: approval-test
agents: ["*"]
default_action: allow
rules:
  - name: approve-transfer
    condition: "action.type == 'transfer'"
    action: require_approval
    approvers: ["manager", "compliance"]
    description: "Transfers require human approval"
    priority: 100
  - name: block-delete
    condition: "action.type == 'delete'"
    action: deny
    priority: 100
"""


def dummy_tool(action="read", **kwargs):
    return {"action": action, "status": "executed", **kwargs}


class TestAutoRejectApproval:
    def test_auto_rejects_all(self):
        handler = AutoRejectApproval()
        request = ApprovalRequest(
            action="transfer",
            rule_name="approve-transfer",
            policy_name="test",
            agent_id="agent-1",
        )
        decision = handler.request_approval(request)
        assert not decision.approved
        assert "auto-reject" in decision.approver

    def test_custom_reason(self):
        handler = AutoRejectApproval(reason="Production safety")
        request = ApprovalRequest(
            action="transfer", rule_name="r", policy_name="p", agent_id="a",
        )
        decision = handler.request_approval(request)
        assert decision.reason == "Production safety"


class TestCallbackApproval:
    def test_callback_approves(self):
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=True, approver="admin")
        )
        request = ApprovalRequest(
            action="transfer", rule_name="r", policy_name="p", agent_id="a",
        )
        decision = handler.request_approval(request)
        assert decision.approved
        assert decision.approver == "admin"

    def test_callback_rejects(self):
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=False, approver="admin", reason="Too risky")
        )
        request = ApprovalRequest(
            action="transfer", rule_name="r", policy_name="p", agent_id="a",
        )
        decision = handler.request_approval(request)
        assert not decision.approved
        assert decision.reason == "Too risky"

    def test_callback_error_rejects(self):
        def failing_callback(req):
            raise RuntimeError("Service unavailable")

        handler = CallbackApproval(failing_callback)
        request = ApprovalRequest(
            action="transfer", rule_name="r", policy_name="p", agent_id="a",
        )
        decision = handler.request_approval(request)
        assert not decision.approved
        assert "error" in decision.approver

    def test_callback_receives_request_details(self):
        received = {}
        def capture_callback(req):
            received["action"] = req.action
            received["rule"] = req.rule_name
            received["approvers"] = req.approvers
            return ApprovalDecision(approved=True, approver="test")

        handler = CallbackApproval(capture_callback)
        request = ApprovalRequest(
            action="transfer", rule_name="approve-transfer",
            policy_name="p", agent_id="a", approvers=["mgr"],
        )
        handler.request_approval(request)
        assert received["action"] == "transfer"
        assert received["rule"] == "approve-transfer"
        assert received["approvers"] == ["mgr"]


class TestApprovalWithGovern:
    def test_require_approval_auto_rejects_by_default(self):
        """Without an approval handler, require_approval is auto-rejected."""
        safe = govern(dummy_tool, policy=REQUIRE_APPROVAL_POLICY)
        with pytest.raises(GovernanceDenied) as exc:
            safe(action="transfer")
        assert "auto-reject" in str(exc.value).lower() or "rejected" in str(exc.value).lower()

    def test_require_approval_with_callback_approve(self):
        """CallbackApproval that approves allows execution."""
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=True, approver="admin@corp")
        )
        safe = govern(
            dummy_tool,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=handler,
        )
        result = safe(action="transfer", amount=5000)
        assert result["status"] == "executed"
        assert result["amount"] == 5000

    def test_require_approval_with_callback_reject(self):
        """CallbackApproval that rejects denies execution."""
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=False, approver="admin", reason="Amount too high")
        )
        safe = govern(
            dummy_tool,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=handler,
        )
        with pytest.raises(GovernanceDenied) as exc:
            safe(action="transfer", amount=1000000)
        assert "Amount too high" in str(exc.value)

    def test_deny_bypasses_approval(self):
        """Deny rules are enforced without going through approval."""
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=True, approver="admin")
        )
        safe = govern(
            dummy_tool,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=handler,
        )
        # delete is deny, not require_approval — should not hit handler
        with pytest.raises(GovernanceDenied):
            safe(action="delete")

    def test_allow_bypasses_approval(self):
        """Allowed actions don't trigger approval."""
        call_count = {"n": 0}
        def counting_callback(req):
            call_count["n"] += 1
            return ApprovalDecision(approved=True, approver="admin")

        handler = CallbackApproval(counting_callback)
        safe = govern(
            dummy_tool,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=handler,
        )
        safe(action="read")
        assert call_count["n"] == 0  # no approval needed for read

    def test_approval_audit_trail(self):
        """Approval decisions are logged in the audit trail."""
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=True, approver="admin@corp")
        )
        safe = govern(
            dummy_tool,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=handler,
        )
        safe(action="transfer")

        entries = safe.audit_log.query(event_type="approval_decision")
        assert len(entries) >= 1
        assert entries[0].data.get("approver") == "admin@corp"

    def test_approval_with_on_deny_callback(self):
        """on_deny callback fires when approval is rejected."""
        handler = CallbackApproval(
            lambda req: ApprovalDecision(approved=False, approver="admin")
        )
        denied = []
        safe = govern(
            dummy_tool,
            policy=REQUIRE_APPROVAL_POLICY,
            approval_handler=handler,
            on_deny=lambda d: denied.append(d),
        )
        safe(action="transfer")
        assert len(denied) == 1


class TestApprovalRequest:
    def test_request_has_timestamp(self):
        req = ApprovalRequest(
            action="test", rule_name="r", policy_name="p", agent_id="a",
        )
        assert req.requested_at is not None

    def test_request_preserves_approvers(self):
        req = ApprovalRequest(
            action="test", rule_name="r", policy_name="p",
            agent_id="a", approvers=["alice", "bob"],
        )
        assert req.approvers == ["alice", "bob"]
