# Output guard for the crewAI "single agent, single policy" quickstart.
#
# One policy, one intervention point. ACS inspects the agent's final answer at
# the `output` point (exposed to Rego as `input.policy_target.value`) and blocks
# it if it leaks a US Social Security Number. Legitimate answers pass straight
# through, so governance stays out of the way of normal work.
package agent_control_specification.single_agent

import rego.v1

default verdict := {"decision": "allow"}

default output_verdict := {"decision": "allow"}

verdict := output_verdict if input.intervention_point == "output"

# Guard the type so a structured (non-string) payload fails safe to "allow".
default answer_text := ""

answer_text := lower(input.policy_target.value) if is_string(input.policy_target.value)

output_verdict := deny(
	"blocked_pii_in_output",
	"The agent's final answer contained a Social Security Number and was blocked by the Agent Control Specification.",
) if {
	input.intervention_point == "output"
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, answer_text)
}

deny(reason, message) := {"decision": "deny", "reason": reason, "message": message}
