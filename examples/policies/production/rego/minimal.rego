# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.production.minimal

import rego.v1

legacy_input := {
	"action": object.get(body, "action", object.get(input, "intervention_point", "")),
	"output": object.get(body, "output", body),
} if {
	body := input.policy_target.value
	is_object(body)
}

legacy_input := {
	"action": object.get(input, "intervention_point", ""),
	"output": input.policy_target.value,
} if not is_object(input.policy_target.value)

escalations := set()

denials contains "File deletion requires manual intervention" if {
	legacy_input.action == "delete_file"
}

denials contains "Database schema changes are not permitted" if {
	legacy_input.action == "drop_table"
}

denials contains "Arbitrary code execution is blocked" if {
	legacy_input.action == "execute_code"
}

denials contains "Direct SSH access is not permitted" if {
	legacy_input.action == "ssh_connect"
}

denials contains "Tool call budget exceeded (100)" if {
	budgets := object.get(object.get(object.get(input, "snapshot", {}), "envelope", {}), "budgets", {})
	object.get(budgets, "tool_call_count", 0) >= 100
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
	"reason": "Default allow",
} if {
	count(denials) == 0
	count(escalations) == 0
}
