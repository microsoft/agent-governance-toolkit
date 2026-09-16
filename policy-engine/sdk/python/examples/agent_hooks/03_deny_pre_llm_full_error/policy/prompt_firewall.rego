# Prompt firewall for the crewAI "deny before the LLM call" quickstart.
#
# ACS is stateless: this policy inspects only the snapshot the host supplies at
# the `pre_model_call` intervention point. The host (crewAI, via the
# agent_control_specification AcsInterceptor) provides the outgoing chat messages at
# `$.messages`, which the engine exposes to Rego as `input.policy_target.value`.
#
# A `deny` verdict here aborts the model call *before* any tokens are sent to
# the provider. crewAI surfaces the `reason`/`message` below to the caller, so
# keep `message` customer-safe and actionable.
package agent_control_specification.deny_pre_llm

import rego.v1

default verdict := {"decision": "allow"}

default pre_model_call_verdict := {"decision": "allow"}

verdict := pre_model_call_verdict if input.intervention_point == "pre_model_call"

# The policy target is the outgoing message list. Guard the type so a malformed
# snapshot fails safe to an empty haystack (which matches nothing, allowing the
# call; ACS itself fails closed on any engine error — see the runner note).
default messages := []

messages := input.policy_target.value if is_array(input.policy_target.value)

# Flatten every string `content` field into one lowercased haystack.
prompt_text := concat(" ", [lower(content) |
	some message in messages
	content := object.get(message, "content", "")
	is_string(content)
])

pre_model_call_verdict := deny(
	"blocked_prohibited_prompt",
	"Agent Control Specification blocked this model call: the prompt attempts to exfiltrate credentials or override the agent's safety instructions.",
) if {
	input.intervention_point == "pre_model_call"
	regex.match(`(?i)(password|api[_ ]?key|secret[_ ]?key|credential|exfiltrat|ignore (all )?previous instructions)`, prompt_text)
}

deny(reason, message) := {"decision": "deny", "reason": reason, "message": message}
