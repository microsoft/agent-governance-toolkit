# Ported from AgentShield/examples/policies/azure-content-safety.yaml
package agent_control_specification.azure_content_safety

import rego.v1

default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

default post_tool_call_verdict := {"decision": "allow"}

default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

verdict := post_tool_call_verdict if input.intervention_point == "post_tool_call"

verdict := output_verdict if input.intervention_point == "output"

annotation := object.get(input.annotations, "aacs", {})

scores := object.get(annotation, "scores", {})

score(name) := object.get(scores, name, 0)

input_verdict := deny_verdict("aacs_input_flagged", "Azure Content Safety flagged the user input.") if {
	input.intervention_point == "input"
	not azure_content_safe
} else := {"decision": "allow"}

post_tool_call_verdict := deny_verdict("aacs_post_tool_flagged", "Azure Content Safety flagged content in the tool result.") if {
	input.intervention_point == "post_tool_call"
	not azure_content_safe
} else := {"decision": "allow"}

output_verdict := deny_verdict("aacs_output_flagged", "Azure Content Safety flagged content in the agent response.") if {
	input.intervention_point == "output"
	not azure_content_safe
} else := {"decision": "allow"}

azure_content_safe if not azure_content_flagged

azure_content_flagged if score("Hate") >= 2

azure_content_flagged if score("SelfHarm") >= 2

azure_content_flagged if score("Sexual") >= 4

azure_content_flagged if score("Violence") >= 2

deny_verdict(reason, message) := {
	"decision": "deny",
	"reason": reason,
	"message": message,
}
