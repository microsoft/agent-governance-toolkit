package acs.real

import rego.v1

# Real-endpoint demo policy. The "aacs" annotation is produced by a host
# dispatcher that calls Azure AI Content Safety and returns severity scores
# (0/2/4/6) per category. The policy denies when any category crosses its
# Azure-recommended threshold, at both the user input and the model output.

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}

annotation := object.get(input.annotations, "aacs", {})
scores := object.get(annotation, "scores", {})
score(name) := object.get(scores, name, 0)

flagged if score("Hate") >= 2
flagged if score("SelfHarm") >= 2
flagged if score("Sexual") >= 4
flagged if score("Violence") >= 2

deny_verdict(reason, message) := {
	"decision": "deny",
	"reason": reason,
	"message": message,
}

input_verdict := deny_verdict("aacs_input_flagged", "Azure Content Safety flagged the user input.") if {
	input.intervention_point == "input"
	flagged
}

output_verdict := deny_verdict("aacs_output_flagged", "Azure Content Safety flagged the model output.") if {
	input.intervention_point == "output"
	flagged
}

verdict := input_verdict if input.intervention_point == "input"
verdict := output_verdict if input.intervention_point == "output"
