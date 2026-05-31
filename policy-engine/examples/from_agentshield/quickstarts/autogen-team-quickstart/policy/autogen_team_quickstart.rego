# Ported from AgentShield/examples/autogen_team_quickstart_azure.guardrails.yaml.
# ACS is stateless. Host snapshots must supply prior AgentShield variables explicitly:
#   snapshot.kyc_token, snapshot.account_tier, snapshot.business_account_authorized.
package agent_control_specification.autogen_team_quickstart

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"
verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"
verdict := output_verdict if input.intervention_point == "output"

input_text := lower(object.get(object.get(input.policy_target, "value", {}), "text", ""))
tool_args := object.get(input.policy_target, "value", {})
snapshot := object.get(input, "snapshot", {})
tool_name := object.get(object.get(input, "tool", {}), "name", "")

input_verdict := deny("input_policy_bypass", "Prompt requests cross-customer access or attempts to bypass policy.") if {
	input.intervention_point == "input"
	regex.match(`(?i)(look up|modify|access)\s+(another|other|customer\s+\d+|\s*customer\s*[^\s]*?\s+(account|profile))`, input_text)
} else := deny("input_policy_bypass", "Prompt requests cross-customer access or attempts to bypass policy.") if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(ignore|disregard|forget)\s+(previous|prior|all)\s+(instructions?|prompts?|rules?)`, input_text)
} else := deny("input_policy_bypass", "Prompt requests cross-customer access or attempts to bypass policy.") if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(bypass|skip|override)\s+(kyc|verification|approval|guardrails?)`, input_text)
}

pre_tool_call_verdict := deny("create_account_requires_kyc", "create_account requires a kyc_token from verify_identity.") if {
	input.intervention_point == "pre_tool_call"
	tool_name == "create_account"
	not has_kyc_token
} else := deny("ssn_only_to_verify_identity", "SSN-shaped argument is only permitted on verify_identity.") if {
	input.intervention_point == "pre_tool_call"
	tool_name != "verify_identity"
	args_contain_ssn
} else := escalate("business_account_requires_approval", "Business-tier accounts require explicit manager approval.") if {
	input.intervention_point == "pre_tool_call"
	tool_name == "create_account"
	is_business_tier
	not bool_snapshot("business_account_authorized")
}

output_verdict := redact_ssn if {
	input.intervention_point == "output"
	redact_ssn
} else := redact_card if {
	input.intervention_point == "output"
	redact_card
}

has_kyc_token if object.get(snapshot, "kyc_token", "") != ""

is_business_tier if lower(object.get(snapshot, "account_tier", object.get(tool_args, "account_tier", object.get(tool_args, "tier", "")))) == "business"

args_text := lower(sprintf("%v", [tool_args]))
args_contain_ssn if regex.match(`\b\d{3}-\d{2}-\d{4}\b`, args_text)

bool_snapshot(name) if object.get(snapshot, name, false) == true

output_text := object.get(object.get(input.policy_target, "value", {}), "text", "")

redact_ssn := transform_redact("redact_ssn_in_final_reply", "SSN detected in final customer-facing reply.", "[SSN-REDACTED]", m[0]) if {
	m := regex.find_n(`\b\d{3}-\d{2}-\d{4}\b`, output_text, 1)
	count(m) > 0
}

redact_card := transform_redact("redact_card_in_final_reply", "Card number detected in final customer-facing reply.", "[CARD-REDACTED]", m[0]) if {
	m := regex.find_n(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`, output_text, 1)
	count(m) > 0
}

# AGT-DELTA D1.1: rewrite the single regex match through a Transform
# verdict scoped to ``$policy_target.text``. The Rust core rejects any
# verdict carrying ``effects`` with ``runtime_error:policy_output_invalid``.
transform_redact(reason, message, replacement, match) := {
	"decision": "transform",
	"reason": reason,
	"message": message,
	"transform": {"path": "$policy_target.text", "value": replace(output_text, match, replacement)},
}

deny(reason, message) := {"decision": "deny", "reason": reason, "message": message}
escalate(reason, message) := {"decision": "escalate", "reason": reason, "message": message}
