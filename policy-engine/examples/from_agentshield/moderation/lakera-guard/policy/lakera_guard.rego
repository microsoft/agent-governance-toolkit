# Ported from AgentShield/examples/policies/lakera-guard.yaml
package agent_control_specification.lakera_guard

import rego.v1

default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

annotation := object.get(input.annotations, "lakera", {})

scores := object.get(annotation, "scores", {})

score(name) := object.get(scores, name, 0)

input_verdict := deny_verdict("lakera_input_flagged", "Lakera Guard flagged the user input.") if {
	input.intervention_point == "input"
	not lakera_safe
} else := {"decision": "allow"}

lakera_safe if not lakera_flagged

lakera_flagged if score("prompt_injection") >= 0.8

lakera_flagged if score("jailbreak") >= 0.7

deny_verdict(reason, message) := {
	"decision": "deny",
	"reason": reason,
	"message": message,
}
