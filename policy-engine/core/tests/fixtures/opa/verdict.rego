package agent_control_specification.input

import rego.v1

default verdict := {"decision": "allow"}

verdict := {
    "decision": "deny",
    "reason": "blocked_text",
    "message": "Input contained blocked text.",
} if {
    contains(input.policy_target.value.text, "block")
}
