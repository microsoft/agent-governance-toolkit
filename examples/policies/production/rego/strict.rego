# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.production.strict

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

denials contains "Credential pattern detected in output" if {
	regex.match(`(?i)(api[_-]?key|password|secret|token)[:\s=]+\S{8,}`, sprintf("%v", [legacy_input.output]))
}

denials contains "PII detected in output" if {
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, sprintf("%v", [legacy_input.output]))
}

allows contains "allow-read-file" if {
	legacy_input.action == "read_file"
}

allows contains "allow-search" if {
	legacy_input.action == "web_search"
}

allows contains "allow-summarize" if {
	legacy_input.action == "summarize"
}

denials contains "Tool call budget exceeded (10)" if {
	budgets := object.get(object.get(object.get(input, "snapshot", {}), "envelope", {}), "budgets", {})
	object.get(budgets, "tool_call_count", 0) >= 10
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
