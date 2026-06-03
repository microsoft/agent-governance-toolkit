# Ported from AgentShield/examples/policies/perspective-api.yaml
package agent_control_specification.perspective_api

import rego.v1

default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

annotation := object.get(input.annotations, "perspective", {})

scores := object.get(annotation, "scores", {})

score(name) := object.get(scores, name, 0)

input_verdict := deny_verdict("perspective_input_toxic", "Perspective API flagged the user input as toxic.") if {
	input.intervention_point == "input"
	not perspective_safe
} else := {"decision": "allow"}

perspective_safe if not perspective_flagged

perspective_flagged if score("toxicity") >= 0.8

perspective_flagged if score("severe_toxicity") >= 0.7

perspective_flagged if score("threat") >= 0.7

perspective_flagged if score("identity_attack") >= 0.7

deny_verdict(reason, message) := {
	"decision": "deny",
	"reason": reason,
	"message": message,
}
