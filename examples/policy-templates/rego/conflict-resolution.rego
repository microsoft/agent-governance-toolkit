# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.templates.conflict_resolution

import rego.v1

context := input.policy_target.value if is_object(input.policy_target.value)

context := {"output": input.policy_target.value} if {
	not is_object(input.policy_target.value)
	input.intervention_point == "output"
}

context := {"input": input.policy_target.value} if {
	not is_object(input.policy_target.value)
	input.intervention_point != "output"
}

candidates contains {"name": "deny-dangerous-ddl", "action": "deny", "priority": 100, "message": "Conflict resolution: dangerous DDL denied (deny-overrides)"} if {
	regex.match(`^sql_execute$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "production-reads", "action": "allow", "priority": 50, "message": "Conflict resolution: production read access allowed"} if {
	regex.match(`^sql_read$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "production-writes", "action": "deny", "priority": 80, "message": "Conflict resolution: production write denied (first-match)"} if {
	regex.match(`^k8s_apply$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "staging-operations", "action": "allow", "priority": 40, "message": "Conflict resolution: staging operation allowed"} if {
	regex.match(`^k8s_apply$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "config-reads", "action": "allow", "priority": 60, "message": "Conflict resolution: config read allowed (most-specific-wins)"} if {
	regex.match(`^k8s_get$`, sprintf("%v", [object.get(context, "action", 0)]))
}

max_priority := max([candidate.priority | candidate := candidates[_]]) if count(candidates) > 0

winner_names := sort([candidate.name | candidate := candidates[_]; candidate.priority == max_priority]) if count(candidates) > 0

winner := candidate if {
	count(candidates) > 0
	candidate := candidates[_]
	candidate.name == winner_names[0]
}

result := {
	"decision": winner.action,
	"reason": winner.name,
	"message": winner.message,
} if count(candidates) > 0

result := {
	"decision": "deny",
	"reason": "default_deny",
} if count(candidates) == 0
