# Consolidated port of AgentShield bank-manager guardrails.yaml,
# bank-base.guardrails.yaml, and bank-mcp-template.guardrails.yaml.
# ACS is stateless. Hosts must supply all AgentShield state as snapshot fields:
#   mode, violation_count, transfer_approved, customer_ack_token, transfer_amount,
#   transfer_execution_authorized, high_value_transfer_authorized,
#   fraud_review_authorized, transfer_authorized, admin_mode_active,
#   freeze_account_authorized, payments_api_authorized, fraud_agent_authorized,
#   fraud_score, fraud_risk_score, account_sensitivity, transaction_velocity,
#   geographic_anomaly, unusual_counterparty.
# `mode: restricted` represents the active bank-mcp-template restricted mode lockout.
package agent_control_specification.bank_manager

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"
verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"
verdict := post_tool_call_verdict if input.intervention_point == "post_tool_call"

input_text := lower(object.get(object.get(input.policy_target, "value", {}), "text", ""))
tool_args := object.get(input.policy_target, "value", {})
snapshot := object.get(input, "snapshot", {})
tool_name := object.get(object.get(input, "tool", {}), "name", "")
annotations := object.get(input, "annotations", {})

input_verdict := deny("input_regex_fraud_or_pii", "Input contains account takeover language, PII, or payment manipulation instructions.") if {
	input.intervention_point == "input"
	regex.match(`(?i)(unauthorized\s+transfer|bypass\s+(approval|limits?)|steal\s+funds|\b\d{3}-\d{2}-\d{4}\b|\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b)`, input_text)
} else := deny("input_llm_security_judge", "Input security annotator flagged the request.") if {
	input.intervention_point == "input"
	ann_flag("input_security")
}

pre_tool_call_verdict := deny("restricted_mode_lockdown", "Restricted mode is active. Sensitive bank tools and external endpoints are blocked unconditionally.") if {
	input.intervention_point == "pre_tool_call"
	restricted_mode_active
	restricted_resource
} else := deny("external_api_not_allowed", "External HTTP endpoint is outside the approved MCP endpoint set.") if {
	is_http_request
	not endpoint_is_internal_bank_api
} else := deny("payment_amount_hard_limit", "Transfers over $50,000 are never allowed.") if {
	is_payment_tool
	amount > 50000
} else := deny("create_transfer_requires_customer_approval", "create_transfer requires customer approval and an acknowledgement token.") if {
	tool_name == "create_transfer"
	not transfer_approved
} else := deny("create_transfer_requires_customer_ack", "create_transfer requires an explicit customer acknowledgement token.") if {
	tool_name == "create_transfer"
	not has_customer_ack_token
} else := deny("fraud_score_high_block", "High fraud score requires manual handling outside the automated transfer path.") if {
	tool_name == "create_transfer"
	fraud_score >= 75
} else := escalate("create_transfer_execution_approval", "Executing a transfer requires per-call operator approval.") if {
	tool_name == "create_transfer"
	not bool_snapshot("transfer_execution_authorized")
} else := escalate("high_value_transfer_requires_approval", "Transfers over $10,000 require senior approval.") if {
	is_payment_tool
	amount > 10000
	not bool_snapshot("high_value_transfer_authorized")
} else := escalate("sensitive_or_risky_transfer_review", "Sensitive accounts or risky transfers require human fraud review.") if {
	tool_name == "prepare_transfer"
	transfer_needs_review
	not bool_snapshot("fraud_review_authorized")
} else := escalate("transfer_requires_approval", "Transfer preparation requires customer-service approval.") if {
	tool_name == "prepare_transfer"
	not bool_snapshot("transfer_authorized")
} else := deny("freeze_requires_admin_mode", "freeze_account is only available while admin mode is active.") if {
	tool_name == "freeze_account"
	not bool_snapshot("admin_mode_active")
} else := escalate("freeze_requires_approval", "Freezing an account requires operator approval.") if {
	tool_name == "freeze_account"
	not bool_snapshot("freeze_account_authorized")
} else := escalate("enable_admin_mode_requires_approval", "Enabling admin mode requires explicit approval.") if {
	tool_name == "enable_admin_mode"
	not bool_snapshot("admin_mode_authorized")
} else := escalate("payments_api_requires_approval", "Payments API calls require approval.") if {
	is_payments_api
	not bool_snapshot("payments_api_authorized")
} else := escalate("fraud_agent_high_risk_requires_approval", "High-risk fraud agent decisions require a human gate.") if {
	tool_name == "fraud_detection_agent"
	fraud_agent_high_risk
	not bool_snapshot("fraud_agent_authorized")
} else := deny("tool_execution_llm_judge", "Tool execution LLM judge flagged the call.") if {
	input.intervention_point == "pre_tool_call"
	ann_flag("tool_adherence")
} else := deny("fraud_classifier_flagged_tool_call", "Fraud classifier flagged the tool call.") if {
	input.intervention_point == "pre_tool_call"
	ann_flag("fraud_classifier")
}

post_tool_call_verdict := redact_ssn if {
	input.intervention_point == "post_tool_call"
	redact_ssn
} else := redact_card if {
	input.intervention_point == "post_tool_call"
	redact_card
}

ann_flag(name) if object.get(object.get(annotations, name, {}), "flagged", false) == true
ann_flag(name) if lower(object.get(object.get(annotations, name, {}), "label", "")) in {"deny", "block", "unsafe", "fraud", "high_risk"}

bool_snapshot(name) if object.get(snapshot, name, false) == true
restricted_mode_active if object.get(snapshot, "mode", "") == "restricted"
restricted_mode_active if object.get(snapshot, "violation_count", 0) >= 3

restricted_resource if tool_name in {"create_transfer", "prepare_transfer", "freeze_account", "enable_admin_mode", "http.request"}

is_http_request if tool_name == "http.request"
endpoint := lower(object.get(tool_args, "url", object.get(tool_args, "endpoint", object.get(snapshot, "endpoint", ""))))
endpoint_is_internal_bank_api if startswith(endpoint, "https://api.bank.example/")
endpoint_is_internal_bank_api if startswith(endpoint, "/internal/")
is_payments_api if {
	is_http_request
	contains(endpoint, "/payments")
}

is_payment_tool if tool_name in {"prepare_transfer", "create_transfer"}
amount := object.get(tool_args, "amount", object.get(snapshot, "transfer_amount", 0))
fraud_score := object.get(snapshot, "fraud_score", 0)
transfer_approved if bool_snapshot("transfer_approved")
has_customer_ack_token if object.get(snapshot, "customer_ack_token", "") != ""

transfer_needs_review if lower(object.get(snapshot, "account_sensitivity", "")) in {"high", "restricted"}
transfer_needs_review if object.get(snapshot, "transaction_velocity", 0) > 5
transfer_needs_review if object.get(snapshot, "geographic_anomaly", false) == true
transfer_needs_review if object.get(snapshot, "unusual_counterparty", false) == true

fraud_agent_high_risk if object.get(snapshot, "fraud_risk_score", 0) >= 70

result_value := object.get(input.policy_target, "value", {})
result_text := object.get(result_value, "text", sprintf("%v", [result_value]))
redact_ssn := transform_redact("redact_ssn_in_tool_result", "Tool result contains an SSN-shaped value.", "[SSN-REDACTED]", m[0]) if {
	m := regex.find_n(`\b\d{3}-\d{2}-\d{4}\b`, result_text, 1)
	count(m) > 0
}
redact_card := transform_redact("redact_card_in_tool_result", "Tool result contains a card-shaped value.", "[CARD-REDACTED]", m[0]) if {
	m := regex.find_n(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`, result_text, 1)
	count(m) > 0
}
# AGT-DELTA D1.1: rewrite the single regex match through a Transform
# verdict scoped to ``$policy_target.text``. The Rust core rejects any
# verdict carrying ``effects`` with ``runtime_error:policy_output_invalid``.
transform_redact(reason, message, replacement, match) := {
	"decision": "transform",
	"reason": reason,
	"message": message,
	"transform": {"path": "$policy_target.text", "value": replace(result_text, match, replacement)},
}

deny(reason, message) := {"decision": "deny", "reason": reason, "message": message}
escalate(reason, message) := {"decision": "escalate", "reason": reason, "message": message}
