# Ported from AgentShield/examples/agents/document-dlp/guardrails.yaml.
# ACS is stateless. Hosts must supply AgentShield variables and lifetimes as
# snapshot fields: data_sensitivity, data_jurisdictions, user_clearance,
# resolved_recipients, recipient_verified, send_email_authorized,
# eu_transfer_authorized, and send_email_denied. AgentShield wildcard tool DLP is
# applied to all declared ACS tools. Truly undeclared tools fail closed before
# policy evaluation.
package agent_control_specification.document_dlp

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"
verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"
verdict := post_tool_call_verdict if input.intervention_point == "post_tool_call"
verdict := output_verdict if input.intervention_point == "output"

input_text := lower(object.get(object.get(input.policy_target, "value", {}), "text", ""))
tool_args := object.get(input.policy_target, "value", {})
snapshot := object.get(input, "snapshot", {})
tool_name := object.get(object.get(input, "tool", {}), "name", "")
annotations := object.get(input, "annotations", {})

input_verdict := deny("block_bypass_and_credential_exfiltration", "Request attempts to bypass DLP or exfiltrate credentials.") if {
	input.intervention_point == "input"
	regex.match(`(?i)(ignore|bypass|disable|override)\s+(dlp|policy|guardrails?|instructions?)`, input_text)
} else := deny("block_bypass_and_credential_exfiltration", "Request attempts to bypass DLP or exfiltrate credentials.") if {
	input.intervention_point == "input"
	regex.match(`(?i)(send|email|forward|upload|copy)[\s\S]{0,80}\b(password|secret|api\s*key|ssn|social\s*security)\b`, input_text)
}

pre_tool_call_verdict := deny("blocked_after_prior_email_denial", "Prior send_email denial remains active in the host-provided snapshot.") if {
	input.intervention_point == "pre_tool_call"
	tool_name == "datastore_send_email"
	bool_snapshot("send_email_denied")
} else := deny("save_record_blocks_confidential_or_eu", "Confidential or EU data may not be saved into the datastore.") if {
	input.intervention_point == "pre_tool_call"
	tool_name == "datastore_save_record"
	cannot_save_record
} else := deny("send_email_requires_verified_recipient", "Email recipients must be verified before sending.") if {
	is_send_email
	not bool_snapshot("recipient_verified")
} else := deny("send_email_confidential_requires_internal_recipients", "Confidential or restricted data can only be sent to internal recipients.") if {
	is_send_email
	sensitivity_confidential_or_restricted
	not all_recipients_internal
} else := escalate("send_email_non_public_requires_approval", "Sending non-public data requires an explicit DLP approval.") if {
	is_send_email
	sensitivity_non_public
	not clearance_manager_or_above
	not bool_snapshot("send_email_authorized")
} else := escalate("eu_transfer_requires_approval", "Sending EU-origin data requires an explicit transfer approval.") if {
	is_send_email
	jurisdiction_contains("EU")
	not bool_snapshot("eu_transfer_authorized")
} else := deny("wildcard_tool_dlp_blocks_restricted_data", "Restricted data may not be passed to non-read DLP tools.") if {
	input.intervention_point == "pre_tool_call"
	tool_name != "datastore_lookup_documents"
	tool_name != "datastore_fetch_document"
	lower(object.get(snapshot, "data_sensitivity", "")) == "restricted"
} else := deny("tool_execution_llm_judge", "Task-adherence annotator flagged the tool call.") if {
	input.intervention_point == "pre_tool_call"
	ann_flag("task_adherence")
}

post_tool_call_verdict := redact_secret if {
	input.intervention_point == "post_tool_call"
	redact_secret
} else := redact_ssn_post if {
	input.intervention_point == "post_tool_call"
	redact_ssn_post
}

output_verdict := redact_secret_out if {
	input.intervention_point == "output"
	redact_secret_out
} else := redact_ssn_out if {
	input.intervention_point == "output"
	redact_ssn_out
}

is_send_email if {
	input.intervention_point == "pre_tool_call"
	tool_name == "datastore_send_email"
}
bool_snapshot(name) if object.get(snapshot, name, false) == true
ann_flag(name) if object.get(object.get(annotations, name, {}), "flagged", false) == true
ann_flag(name) if lower(object.get(object.get(annotations, name, {}), "label", "")) in {"deny", "block", "unsafe"}

sensitivity := lower(object.get(snapshot, "data_sensitivity", ""))
sensitivity_non_public if sensitivity in {"internal", "confidential", "restricted"}
sensitivity_confidential_or_restricted if sensitivity in {"confidential", "restricted"}
clearance_manager_or_above if lower(object.get(snapshot, "user_clearance", "")) in {"manager", "director", "executive"}

cannot_save_record if sensitivity_confidential_or_restricted
cannot_save_record if jurisdiction_contains("EU")

jurisdictions := object.get(snapshot, "data_jurisdictions", [])
jurisdiction_contains(j) if j in jurisdictions

recipients := object.get(snapshot, "resolved_recipients", [])
all_recipients_internal if {
	count(recipients) > 0
	not some_external_recipient
}
some_external_recipient if {
	some r in recipients
	not endswith(lower(r), "@example.com")
}

post_value := object.get(input.policy_target, "value", {})
post_text := object.get(post_value, "text", sprintf("%v", [post_value]))
output_text := object.get(object.get(input.policy_target, "value", {}), "text", "")

redact_secret := transform_redact_from(post_text, "redact_secret_in_tool_result", "Tool result contains a secret-like value.", "[SECRET-REDACTED]", `(?i)\b(api[_ -]?key|password|secret)\s*[:=]\s*[^\s,;]+`)
redact_ssn_post := transform_redact_from(post_text, "redact_ssn_in_tool_result", "Tool result contains an SSN-shaped value.", "[SSN-REDACTED]", `\b\d{3}-\d{2}-\d{4}\b`)
redact_secret_out := transform_redact_from(output_text, "redact_secret_in_output", "Output contains a secret-like value.", "[SECRET-REDACTED]", `(?i)\b(api[_ -]?key|password|secret)\s*[:=]\s*[^\s,;]+`)
redact_ssn_out := transform_redact_from(output_text, "redact_ssn_in_output", "Output contains an SSN-shaped value.", "[SSN-REDACTED]", `\b\d{3}-\d{2}-\d{4}\b`)

# AGT-DELTA D1.1: rewrite the single regex match through a Transform
# verdict scoped to ``$policy_target.text``. The Rust core rejects any
# verdict carrying ``effects`` with ``runtime_error:policy_output_invalid``.
transform_redact_from(text, reason, message, replacement, pattern) := {
	"decision": "transform",
	"reason": reason,
	"message": message,
	"transform": {"path": "$policy_target.text", "value": replace(text, m[0], replacement)},
} if {
	m := regex.find_n(pattern, text, 1)
	count(m) > 0
}

deny(reason, message) := {"decision": "deny", "reason": reason, "message": message}
escalate(reason, message) := {"decision": "escalate", "reason": reason, "message": message}
