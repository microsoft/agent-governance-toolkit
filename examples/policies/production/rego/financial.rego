# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.production.financial

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

denials contains "PCI: Credit card number detected" if {
	regex.match(`\b(?:\d[ -]*?){13,16}\b`, sprintf("%v", [legacy_input.output]))
}

denials contains "PII: SSN pattern detected" if {
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, sprintf("%v", [legacy_input.output]))
}

denials contains "Code execution prohibited" if {
	legacy_input.action == "execute_code"
}

escalations contains "Financial transactions require compliance approval" if {
	regex.match(`transfer_|payment_|trade_`, legacy_input.action)
}

allows contains "allow-read" if {
	regex.match(`^(read_|search_|lookup_|calculate)`, legacy_input.action)
}

denials contains "Tool call budget exceeded (30)" if {
	budgets := object.get(object.get(object.get(input, "snapshot", {}), "envelope", {}), "budgets", {})
	object.get(budgets, "tool_call_count", 0) >= 30
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
