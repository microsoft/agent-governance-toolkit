package agt_policies_agent.human_approval

import rego.v1

# Human Approval Controls
# Universal AI agent safety control — ensures a human authorises high-risk actions
# before an agent executes them autonomously.
# Deployer configures approval-required actions, risk levels, and amount thresholds.
#
# Regulatory alignment:
#   OWASP Agentic AI Top 10 — LLM09 Overreliance / LLM06 Excessive Agency
#   EU AI Act Art. 14 — human oversight for high-risk AI systems
#   NIST AI RMF — GOVERN 1.3, MANAGE 2.4
#   CBN/NFIU — maker-checker requirement for financial institutions
#
# Config (override via data.config.human_approval.*):
#   required_actions  — set of action names always requiring human approval
#   risk_levels       — set of risk_level values (from context) requiring approval
#   amount_threshold  — numeric; transactions above this require approval
#   bulk_threshold    — record count above which bulk actions require approval

_default_required_actions := {
	"delete_account",
	"close_account",
	"bulk_delete",
	"mass_update",
	"send_bulk_email",
	"send_bulk_sms",
	"deploy_code",
	"modify_permissions",
	"grant_admin",
	"revoke_access",
	"initiate_bulk_refund",
	"approve_transfer",
	"self_approve",
}

_default_risk_levels := {"critical", "high"}

_default_amount_threshold := 1000000

_default_bulk_threshold := 500

_required_actions := s if {
	s := data.config.human_approval.required_actions
} else := _default_required_actions

_risk_levels := s if {
	s := data.config.human_approval.risk_levels
} else := _default_risk_levels

_amount_threshold := v if {
	v := data.config.human_approval.amount_threshold
} else := _default_amount_threshold

_bulk_threshold := v if {
	v := data.config.human_approval.bulk_threshold
} else := _default_bulk_threshold

# ── Context helpers ───────────────────────────────────────────────────

_risk_level := v if {
	is_string(input.context.risk_level)
	v := input.context.risk_level
} else := "low"

_amount := v if {
	is_number(input.params.amount)
	v := input.params.amount
} else := 0

_record_count := v if {
	is_number(input.params.record_count)
	v := input.params.record_count
} else := 0

# ── Escalate: explicit approval-required action ───────────────────────

escalate contains msg if {
	input.action in _required_actions
	msg := sprintf("Human approval required: '%v' is designated as a human-approval action.", [input.action])
}

# ── Escalate: context risk level ──────────────────────────────────────

escalate contains msg if {
	_risk_level in _risk_levels
	not input.action in _required_actions
	msg := sprintf("Human approval required: action risk level '%v' requires human authorisation.", [_risk_level])
}

# ── Escalate: amount threshold ────────────────────────────────────────

escalate contains msg if {
	_amount > _amount_threshold
	not input.action in _required_actions
	msg := sprintf(
		"Human approval required: transaction amount %v exceeds configured threshold %v.",
		[_amount, _amount_threshold],
	)
}

# ── Escalate: bulk operation threshold ───────────────────────────────

escalate contains msg if {
	_record_count > _bulk_threshold
	not input.action in _required_actions
	msg := sprintf(
		"Human approval required: bulk operation on %v records exceeds threshold %v.",
		[_record_count, _bulk_threshold],
	)
}

# ── Decision: most restrictive wins ──────────────────────────────────

decision := "escalate" if {
	count(escalate) > 0
}

decision := "allow" if {
	count(escalate) == 0
}
