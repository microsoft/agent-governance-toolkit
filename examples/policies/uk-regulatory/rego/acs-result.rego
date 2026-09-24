# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt_policies.acs

import rego.v1

legacy_input(policy_input, "input") := {
	"action": object.get(body, "action", "input"),
	"params": object.get(body, "params", {}),
	"output": object.get(body, "output", body),
	"context": object.union(
		object.get(object.get(policy_input, "snapshot", {}), "envelope", {}),
		object.get(policy_input, "annotations", {}),
	),
} if {
	body := object.get(
		object.get(object.get(policy_input, "snapshot", {}), "input", {}),
		"body",
		{},
	)
	is_object(body)
}

legacy_input(policy_input, "input") := {
	"action": "input",
	"params": {},
	"output": body,
	"context": object.union(
		object.get(object.get(policy_input, "snapshot", {}), "envelope", {}),
		object.get(policy_input, "annotations", {}),
	),
} if {
	body := object.get(
		object.get(object.get(policy_input, "snapshot", {}), "input", {}),
		"body",
		"",
	)
	not is_object(body)
}

legacy_input(policy_input, "pre_tool_call") := {
	"action": object.get(
		object.get(object.get(policy_input, "snapshot", {}), "tool_call", {}),
		"name",
		"",
	),
	"params": object.get(
		object.get(object.get(policy_input, "snapshot", {}), "tool_call", {}),
		"args",
		{},
	),
	"output": "",
	"context": object.union(
		object.get(object.get(policy_input, "snapshot", {}), "envelope", {}),
		object.get(policy_input, "annotations", {}),
	),
}

legacy_input(policy_input, "output") := {
	"action": "output",
	"params": {},
	"output": object.get(
		object.get(object.get(policy_input, "snapshot", {}), "output", {}),
		"content",
		"",
	),
	"context": object.union(
		object.get(object.get(policy_input, "snapshot", {}), "envelope", {}),
		object.get(policy_input, "annotations", {}),
	),
}

normalize(denials, escalations, audits) := {
	"decision": "deny",
	"reason": concat("; ", sort([reason | reason := denials[_]])),
} if count(denials) > 0

normalize(denials, escalations, audits) := {
	"decision": "escalate",
	"reason": concat("; ", sort([reason | reason := escalations[_]])),
} if {
	count(denials) == 0
	count(escalations) > 0
}

normalize(denials, escalations, audits) := {
	"decision": "warn",
	"reason": concat("; ", sort([reason | reason := audits[_]])),
} if {
	count(denials) == 0
	count(escalations) == 0
	count(audits) > 0
}

normalize(denials, escalations, audits) := {
	"decision": "allow",
	"reason": "No regulatory rule matched",
} if {
	count(denials) == 0
	count(escalations) == 0
	count(audits) == 0
}
