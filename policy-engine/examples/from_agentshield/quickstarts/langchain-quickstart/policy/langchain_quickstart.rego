# Ported from AgentShield/examples/langchain_quickstart_azure.guardrails.yaml.
# ACS is stateless. Host snapshots must supply snapshot.email_authorized for the
# per-call send_email approval decision.
package agent_control_specification.langchain_quickstart

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

input_verdict := deny("block_pii_exfiltration_attempts", "Prompt requests emailing or forwarding PII or credentials.") if {
	input.intervention_point == "input"
	regex.match(`(?i)(email|send|forward|exfiltrate)[\s\S]{0,80}\b(ssn|social\s*security|credit\s*card|password)\b`, input_text)
}

pre_tool_call_verdict := deny("read_file_path_allowlist", "Reading from secret or system paths is not permitted.") if {
	input.intervention_point == "pre_tool_call"
	tool_name == "read_file"
	path_is_sensitive
} else := escalate("send_email_requires_approval", "send_email requires explicit operator approval.") if {
	input.intervention_point == "pre_tool_call"
	tool_name == "send_email"
	not bool_snapshot("email_authorized")
}

output_verdict := redact_ssn if {
	input.intervention_point == "output"
	redact_ssn
} else := redact_card if {
	input.intervention_point == "output"
	redact_card
}

path := lower(object.get(tool_args, "path", ""))
path_is_sensitive if contains(path, "secret")
path_is_sensitive if contains(path, "/etc/")
bool_snapshot(name) if object.get(snapshot, name, false) == true

output_text := object.get(object.get(input.policy_target, "value", {}), "text", "")
redact_ssn := transform_redact("redact_ssn_in_response", "SSN detected in agent output.", "[SSN-REDACTED]", m[0]) if {
	m := regex.find_n(`\b\d{3}-\d{2}-\d{4}\b`, output_text, 1)
	count(m) > 0
}
redact_card := transform_redact("redact_card_in_response", "Card number detected in agent output.", "[CARD-REDACTED]", m[0]) if {
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
