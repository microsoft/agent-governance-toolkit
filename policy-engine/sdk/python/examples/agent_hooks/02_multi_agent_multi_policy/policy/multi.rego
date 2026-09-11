# Policy bundle for the crewAI "multi agent, multiple policies" quickstart.
#
# Three independent guard rules, one per intervention point, all sharing this
# bundle. Each is referenced by its own policy id in manifest.yaml:
#
#   input_firewall   (input)          -> block prompt-injection in the request
#   prompt_firewall  (pre_model_call) -> block credential exfiltration in prompts
#   output_guard     (output)         -> block PII (SSN) leaking in the answer
#
# They govern every agent in the crew uniformly, because the AcsInterceptor is
# installed as the crew-wide governor. ACS evaluates each intervention point
# independently against the snapshot the host supplies.
package agent_control_specification.multi

import rego.v1

default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

default pre_model_call_verdict := {"decision": "allow"}

default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

verdict := pre_model_call_verdict if input.intervention_point == "pre_model_call"

verdict := output_verdict if input.intervention_point == "output"

# --- input_firewall: block prompt-injection in the incoming request ---------
# crewAI delivers the kickoff `inputs` mapping at the `input` point, not a flat
# string, so scan every string leaf of the (possibly structured) payload.
default input_text := ""

input_text := lower(concat(" ", [leaf |
	walk(input.policy_target.value, [_, leaf])
	is_string(leaf)
]))

input_verdict := deny(
	"blocked_prompt_injection",
	"The request tries to override the agents' safety instructions and was blocked by the Agent Control Specification.",
) if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(instructions?|prompts?|rules?|guardrails?)\b`, input_text)
}

# --- prompt_firewall: block credential exfiltration in outgoing prompts ------
default messages := []

messages := input.policy_target.value if is_array(input.policy_target.value)

prompt_text := concat(" ", [lower(content) |
	some message in messages
	content := object.get(message, "content", "")
	is_string(content)
])

pre_model_call_verdict := deny(
	"blocked_secret_exfiltration",
	"The model prompt attempts to read or exfiltrate credentials and was blocked by the Agent Control Specification.",
) if {
	input.intervention_point == "pre_model_call"
	regex.match(`(?i)(password|api[_ ]?key|secret[_ ]?key|credential|exfiltrat)`, prompt_text)
}

# --- output_guard: block PII (SSN) leaking in the final answer ---------------
default answer_text := ""

answer_text := lower(input.policy_target.value) if is_string(input.policy_target.value)

output_verdict := deny(
	"blocked_pii_in_output",
	"An agent's final answer contained a Social Security Number and was blocked by the Agent Control Specification.",
) if {
	input.intervention_point == "output"
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, answer_text)
}

deny(reason, message) := {"decision": "deny", "reason": reason, "message": message}
