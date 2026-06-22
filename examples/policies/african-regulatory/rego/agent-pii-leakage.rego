package agt_policies_agent.pii_leakage

import rego.v1

# PII Leakage Prevention
# Universal AI agent safety control — scans agent output for PII before delivery.
# Deployer-configurable pattern sets and sensitivity levels.
#
# Regulatory alignment:
#   OWASP Agentic AI Top 10 — LLM06 Sensitive Information Disclosure
#   NDPA 2023 s.25 — data subjects' right to protection of personal data
#   POPIA s.19 — security safeguards for personal information
#   Kenya DPA s.25 — controller must implement appropriate safeguards
#
# Config (override via data.config.pii_leakage.*):
#   extra_patterns — additional regex patterns to flag as deny-level PII
#   allowed_actions — set of actions permitted to include PII in output

_output_text := v if {
	is_string(input.output)
	v := input.output
} else := ""

# ── Pattern definitions (RE2 — OPA uses Go RE2 engine) ────────────────

# 11-digit identifiers: BVN, NIN, South African temp ID, Kenyan ID (7-8 digits also covered)
_bvn_nin_pattern := `\b[0-9]{11}\b`

# Credit / debit card numbers (Visa, Mastercard, Amex)
_credit_card_pattern := `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`

# Email addresses
_email_pattern := `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`

# International phone numbers (loose — catches common formats)
_phone_pattern := `(\+[0-9]{1,3}[\s\-]?)?(\([0-9]{1,4}\)[\s\-]?)?[0-9]{6,14}\b`

# South African ID (13-digit YYMMDD + 7)
_sa_id_pattern := `\b[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{7}\b`

# ── Detection helpers ─────────────────────────────────────────────────

_contains_bvn_nin if {
	regex.match(_bvn_nin_pattern, _output_text)
}

_contains_credit_card if {
	regex.match(_credit_card_pattern, _output_text)
}

_contains_email if {
	regex.match(_email_pattern, _output_text)
}

_contains_phone if {
	regex.match(_phone_pattern, _output_text)
}

_contains_sa_id if {
	regex.match(_sa_id_pattern, _output_text)
}

_has_extra_pattern if {
	some pattern in data.config.pii_leakage.extra_patterns
	regex.match(pattern, _output_text)
}

# ── Allowed PII actions (deployer opt-in) ─────────────────────────────

_allowed_pii_actions := s if {
	s := data.config.pii_leakage.allowed_actions
} else := set()

_action_is_pii_allowed if {
	input.action in _allowed_pii_actions
}

# ── Deny: high-sensitivity PII ────────────────────────────────────────

deny contains msg if {
	_contains_credit_card
	not _action_is_pii_allowed
	msg := "PII leakage: credit/debit card number detected in agent output — blocked."
}

deny contains msg if {
	_contains_bvn_nin
	not _action_is_pii_allowed
	msg := "PII leakage: BVN/NIN-format identifier (11-digit) detected in agent output — blocked."
}

deny contains msg if {
	_contains_sa_id
	not _action_is_pii_allowed
	msg := "PII leakage: South African ID number detected in agent output — blocked."
}

deny contains msg if {
	_has_extra_pattern
	not _action_is_pii_allowed
	msg := "PII leakage: custom high-sensitivity pattern detected in agent output — blocked."
}

# ── Escalate: medium-sensitivity PII ─────────────────────────────────

escalate contains msg if {
	_contains_email
	not _contains_credit_card
	not _contains_bvn_nin
	not _contains_sa_id
	not _action_is_pii_allowed
	msg := "PII leakage: email address detected in agent output — route to review."
}

escalate contains msg if {
	_contains_phone
	not _contains_credit_card
	not _contains_bvn_nin
	not _contains_sa_id
	not _action_is_pii_allowed
	msg := "PII leakage: phone number detected in agent output — route to review."
}

# ── Audit: PII-capable action even when no pattern matched ────────────

_pii_capable_actions := {
	"respond_to_customer", "send_email", "send_sms",
	"generate_report", "export_data", "read_customer",
}

_is_pii_capable_action if {
	input.action in _pii_capable_actions
}

audit contains msg if {
	_is_pii_capable_action
	not _contains_credit_card
	not _contains_bvn_nin
	not _contains_sa_id
	not _contains_email
	not _contains_phone
	msg := "PII audit: action may produce personal data — output logged for compliance review."
}

# ── Decision: most restrictive wins ──────────────────────────────────

decision := "deny" if {
	count(deny) > 0
}

decision := "escalate" if {
	count(deny) == 0
	count(escalate) > 0
}

decision := "audit" if {
	count(deny) == 0
	count(escalate) == 0
	count(audit) > 0
}

decision := "allow" if {
	count(deny) == 0
	count(escalate) == 0
	count(audit) == 0
}
