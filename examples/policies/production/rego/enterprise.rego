# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.production.enterprise

import rego.v1

legacy_input := {
	"action": object.get(tool_call, "name", ""),
	"output": object.get(tool_call, "args", input.policy_target.value),
} if {
	input.intervention_point == "pre_tool_call"
	tool_call := object.get(object.get(input, "snapshot", {}), "tool_call", {})
}

legacy_input := {
	"action": object.get(body, "action", object.get(input, "intervention_point", "")),
	"output": object.get(body, "output", body),
} if {
	input.intervention_point != "pre_tool_call"
	body := input.policy_target.value
	is_object(body)
}

legacy_input := {
	"action": object.get(input, "intervention_point", ""),
	"output": input.policy_target.value,
} if {
	input.intervention_point != "pre_tool_call"
	not is_object(input.policy_target.value)
}

denials contains "File deletion is not permitted" if {
	legacy_input.action == "delete_file"
}

denials contains "Code execution is blocked" if {
	legacy_input.action == "execute_code"
}

denials contains "SSH is not permitted" if {
	legacy_input.action == "ssh_connect"
}

denials contains "SSN pattern detected in output" if {
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, sprintf("%v", [legacy_input.output]))
}

escalations contains "File writes require approval" if {
	legacy_input.action == "write_file"
}

escalations contains "Email requires review" if {
	legacy_input.action == "send_email"
}

escalations contains "Deployments require sign-off" if {
	legacy_input.action == "deploy"
}

denials contains "Tool call budget exceeded (50)" if {
	budgets := object.get(object.get(object.get(input, "snapshot", {}), "envelope", {}), "budgets", {})
	object.get(budgets, "tool_call_count", 0) >= 50
}

allows contains "allow-read" if {
	regex.match(`^(read_|search_|lookup_|calculate)`, legacy_input.action)
}

result := {
	"decision": "deny",
	"reason": concat("; ", sort([reason | reason := denials[_]])),
} if count(denials) > 0

result := {
	"decision": "escalate",
	"reason": concat("; ", sort([reason | reason := escalations[_]])),
} if {
	count(denials) == 0
	count(escalations) > 0
}

result := {
	"decision": "allow",
	"reason": concat("; ", sort([reason | reason := allows[_]])),
} if {
	count(denials) == 0
	count(escalations) == 0
	count(allows) > 0
}

result := {
	"decision": "deny",
	"reason": "Default deny",
} if {
	count(denials) == 0
	count(escalations) == 0
	count(allows) == 0
}
