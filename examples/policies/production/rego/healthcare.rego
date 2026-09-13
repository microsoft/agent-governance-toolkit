# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.production.healthcare

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

denials contains "PHI: SSN pattern detected" if {
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, sprintf("%v", [legacy_input.output]))
}

denials contains "PHI: Medical Record Number detected" if {
	regex.match(`(?i)MRN[:\s]*\d{6,}`, sprintf("%v", [legacy_input.output]))
}

denials contains "Deletion prohibited in healthcare" if {
	regex.match(`^delete_`, legacy_input.action)
}

escalations contains "Clinical data requires clinician approval" if {
	regex.match(`patient_|clinical_|medical_`, legacy_input.action)
}

allows contains "allow-read" if {
	regex.match(`^(read_|search_|lookup_)`, legacy_input.action)
}

denials contains "Tool call budget exceeded (25)" if {
	budgets := object.get(object.get(object.get(input, "snapshot", {}), "envelope", {}), "budgets", {})
	object.get(budgets, "tool_call_count", 0) >= 25
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
