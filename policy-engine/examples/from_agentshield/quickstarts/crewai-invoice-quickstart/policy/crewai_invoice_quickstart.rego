# Ported from AgentShield/examples/crewai_invoice_quickstart_azure.guardrails.yaml.
# ACS is stateless. Host snapshots must supply prior AgentShield variables explicitly:
#   snapshot.vendor, snapshot.invoice_id, snapshot.amount, snapshot.fraud_score,
#   snapshot.large_payment_authorized.
package agent_control_specification.crewai_invoice_quickstart

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

input_verdict := deny("block_bypass_or_jailbreak", "Prompt requests bypassing fraud-check or coercing blanket approval.") if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(instructions?|prompts?|rules?|guardrails?)\b`, input_text)
} else := deny("block_bypass_or_jailbreak", "Prompt requests bypassing fraud-check or coercing blanket approval.") if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(skip|bypass|override|disable)\s+(the\s+)?(fraud|risk|verification|approval|guardrails?|policy|policies)\b`, input_text)
} else := deny("block_bypass_or_jailbreak", "Prompt requests bypassing fraud-check or coercing blanket approval.") if {
	input.intervention_point == "input"
	regex.match(`(?i)\bapprove\s+(all|every|this|the)\s+invoices?\b`, input_text)
}

pre_tool_call_verdict := deny("approve_payment_requires_allowlisted_vendor", "Payment may only be approved for allowlisted vendors.") if {
	is_approve_payment
	not vendor_is_allowlisted
} else := deny("approve_payment_requires_fraud_check", "Fraud risk must be checked and below 30 before approving payment.") if {
	is_approve_payment
	not fraud_score_acceptable
} else := deny("approve_payment_vendor_arg_matches_extracted", "approve_payment vendor arg must match the extracted invoice vendor.") if {
	is_approve_payment
	not approval_vendor_matches_extracted
} else := deny("approve_payment_invoice_arg_matches_extracted", "approve_payment invoice_id arg must match the extracted invoice.") if {
	is_approve_payment
	not approval_invoice_matches_extracted
} else := escalate("large_payment_requires_manager_approval", "Payments strictly over $10,000 require explicit manager approval.") if {
	is_approve_payment
	is_large_payment
	not bool_snapshot("large_payment_authorized")
}

output_verdict := redact_ssn if {
	input.intervention_point == "output"
	redact_ssn
} else := redact_card if {
	input.intervention_point == "output"
	redact_card
}

is_approve_payment if {
	input.intervention_point == "pre_tool_call"
	tool_name == "approve_payment"
}

vendor := upper(object.get(snapshot, "vendor", ""))
invoice_id := object.get(snapshot, "invoice_id", "")
amount := object.get(snapshot, "amount", 0)
fraud_score := object.get(snapshot, "fraud_score", null)

vendor_is_allowlisted if vendor in {"BIG_CORP", "VENDOR_A", "VENDOR_B"}
fraud_score_acceptable if {
	fraud_score != null
	fraud_score < 30
}
is_large_payment if amount > 10000
approval_vendor_matches_extracted if upper(object.get(tool_args, "vendor", "")) == vendor
approval_invoice_matches_extracted if object.get(tool_args, "invoice_id", "") == invoice_id
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
