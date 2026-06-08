# Ported from AgentShield/examples/policies/llama-guard.yaml
package agent_control_specification.llama_guard

import rego.v1

default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

annotation := object.get(input.annotations, "llama_guard", {})

scores := object.get(annotation, "scores", {})

score(name) := object.get(scores, name, 0)

input_verdict := deny_verdict("llama_guard_input_unsafe", "Llama Guard flagged the user input as unsafe.") if {
	input.intervention_point == "input"
	not llama_guard_safe
} else := {"decision": "allow"}

llama_guard_safe if not llama_guard_unsafe

llama_guard_unsafe if object.get(annotation, "unsafe", false) == true

llama_guard_unsafe if lower(object.get(annotation, "label", "safe")) == "unsafe"

deny_verdict(reason, message) := {
	"decision": "deny",
	"reason": reason,
	"message": message,
}
