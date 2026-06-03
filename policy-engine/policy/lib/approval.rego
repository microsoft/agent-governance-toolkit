# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock approval helpers. These rules produce `escalate` verdicts per
# SPECIFICATION.md §13.1; the host approval path (§17.1) resolves
# them through the resolver declared in the `approval` manifest section
# (§D5). Approver-list helpers let manifests express "this action requires
# named approvers" without authoring a custom Rego rule.

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
