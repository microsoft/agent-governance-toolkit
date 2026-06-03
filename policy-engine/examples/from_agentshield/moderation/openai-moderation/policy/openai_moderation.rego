# Ported from AgentShield/examples/policies/openai-moderation.yaml
package agent_control_specification.openai_moderation

import rego.v1

default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

verdict := output_verdict if input.intervention_point == "output"

annotation := object.get(input.annotations, "openai_mod", {})

scores := object.get(annotation, "scores", {})

score(name) := object.get(scores, name, 0)

input_verdict := deny_verdict("openai_mod_input_flagged", "OpenAI Moderation flagged the user input.") if {
	input.intervention_point == "input"
	not openai_moderation_safe
} else := {"decision": "allow"}

output_verdict := deny_verdict("openai_mod_output_flagged", "OpenAI Moderation flagged the agent output.") if {
	input.intervention_point == "output"
	not openai_moderation_safe
} else := {"decision": "allow"}

openai_moderation_safe if not openai_moderation_flagged

openai_moderation_flagged if score("hate") >= 0.7

openai_moderation_flagged if score("self_harm") >= 0.7

openai_moderation_flagged if score("sexual") >= 0.7

openai_moderation_flagged if score("violence") >= 0.7

deny_verdict(reason, message) := {
	"decision": "deny",
	"reason": reason,
	"message": message,
}
