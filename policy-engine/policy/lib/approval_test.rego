# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.approval_test

import data.agt.approval
import rego.v1

test_escalate_if_true_condition_emits_verdict if {
	verdict := approval.escalate_if(true, "needs_review")
	verdict.decision == "escalate"
	verdict.reason == "needs_review"
}

test_escalate_if_false_condition_emits_nothing if {
	not approval.escalate_if(false, "needs_review")
}

test_escalate_if_approver_required_lists_approvers if {
	verdict := approval.escalate_if_approver_required(["alice", "bob"])
	verdict.decision == "escalate"
	verdict.reason == "approval_required"
	contains(verdict.message, "alice")
}

test_escalate_if_approver_required_empty_emits_nothing if {
	not approval.escalate_if_approver_required([])
}

test_escalate_with_message_carries_message if {
	verdict := approval.escalate_with_message("high_value_action", "spend exceeds 1000")
	verdict.decision == "escalate"
	verdict.reason == "high_value_action"
	verdict.message == "spend exceeds 1000"
}

test_escalate_if_non_string_reason_emits_nothing if {
	not approval.escalate_if(true, 123)
}
