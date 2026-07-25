# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.approval

import rego.v1

escalate_if(condition, reason) := verdict if {
	condition
	is_string(reason)
	verdict := {
		"decision": "escalate",
		"reason": reason,
	}
}

escalate_if_approver_required(approvers) := verdict if {
	is_array(approvers)
	count(approvers) > 0
	verdict := {
		"decision": "escalate",
		"reason": "approval_required",
		"message": sprintf("requires approval from %v", [approvers]),
	}
}

escalate_with_message(reason, message) := verdict if {
	is_string(reason)
	is_string(message)
	verdict := {
		"decision": "escalate",
		"reason": reason,
		"message": message,
	}
}
