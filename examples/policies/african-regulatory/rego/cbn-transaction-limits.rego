# agt-policies-nigeria
# Central Bank of Nigeria — Transaction Limits & Controls (Rego)
#
# Regulatory references:
#   CBN Circular FPR/DIR/GEN/CIR/07/003  — Tiered KYC transaction limits
#   CBN NIP (NIBSS Instant Payment) Framework — ₦10M per transaction cap
#   CBN USSD Banking Guidelines            — ₦100,000 daily USSD limit
#   CBN Agent Banking Guidelines           — agent transaction controls
#
# Rego advantage over YAML:
#   Checks input.params.amount directly — no regex on text output.
#   Amount enforcement is exact, not pattern-matched.
#
# Input schema expected:
#   {
#     "action":  "process_refund",
#     "params":  { "amount": 6500000, "currency": "NGN", "account": "..." },
#     "output":  "agent output text",
#     "context": { "kyc_tier": 3, "customer_verified": true }
#   }

package agt_policies_nigeria.cbn

import rego.v1

# ── Thresholds ────────────────────────────────────────────────────
nip_cap := 10000000 # CBN NIP single-transaction cap

tier3_ceiling := 5000000 # CBN Tier 3 daily limit

tier2_ceiling := 200000 # CBN Tier 2 daily limit

tier1_ceiling := 50000 # CBN Tier 1 daily limit

transfer_actions := {
	"nip_transfer", "instant_transfer", "wire_transfer",
	"transfer_funds", "send_money", "initiate_payment",
}

refund_actions := {
	"process_refund", "issue_refund", "reverse_charge",
	"credit_account", "manual_refund",
}

self_approval_actions := {
	"approve_transfer", "confirm_payment", "authorise_transaction",
	"self_approve", "auto_approve",
}

bulk_actions := {
	"bulk_transfer", "batch_payment", "mass_payment",
	"payroll_run", "bulk_disbursement",
}

# ── Deny rules ────────────────────────────────────────────────────

# CBN Maker-Checker: agent cannot self-approve transactions
deny contains msg if {
	input.action in self_approval_actions
	msg := "CBN Maker-Checker: AI agent cannot self-approve financial transactions — segregation of duties violated"
}

# CBN NIP Cap: single transaction cannot exceed ₦10,000,000
deny contains msg if {
	input.action in transfer_actions
	input.params.amount > nip_cap
	msg := sprintf(
		"CBN NIP Framework: Transaction of ₦%v exceeds ₦10,000,000 single-transaction cap — blocked",
		[input.params.amount],
	)
}

# CBN NIP Cap: detect >₦10M in text output (defence-in-depth)
deny contains msg if {
	regex.match(`(?i)(₦|NGN|naira)\s*1[0-9],?[0-9]{3},?[0-9]{3}`, input.output)
	msg := "CBN NIP Framework: Transaction amount exceeding ₦10,000,000 detected in output — blocked"
}

# ── Escalate rules (route to human approval queue) ────────────────

# CBN Tier 3: transfers between ₦5M and ₦10M require human approval
escalate contains msg if {
	input.action in transfer_actions
	input.params.amount >= tier3_ceiling
	input.params.amount <= nip_cap
	msg := sprintf(
		"CBN Tier 3: Transfer of ₦%v is at or above ₦5,000,000 daily ceiling — routed to human approval queue",
		[input.params.amount],
	)
}

# CBN Tier 2: transfers above Tier 2 ceiling for unverified customers
escalate contains msg if {
	input.action in transfer_actions
	input.params.amount > tier2_ceiling
	input.context.kyc_tier == 2
	msg := sprintf(
		"CBN Tier 2: Transfer of ₦%v exceeds ₦200,000 Tier 2 daily limit — requires verification upgrade or approval",
		[input.params.amount],
	)
}

# CBN Tier 1: any transfer above ₦50,000 for unverified customers
escalate contains msg if {
	input.action in transfer_actions
	input.params.amount > tier1_ceiling
	input.context.kyc_tier == 1
	msg := sprintf(
		"CBN Tier 1: Transfer of ₦%v exceeds ₦50,000 Tier 1 limit — KYC upgrade required",
		[input.params.amount],
	)
}

# All refunds require human approval — never autonomous
escalate contains msg if {
	input.action in refund_actions
	msg := "CBN / Fraud Controls: Refund action requires human approval — agent cannot autonomously issue refunds"
}

# Bulk payments always require human approval
escalate contains msg if {
	input.action in bulk_actions
	msg := "CBN: Bulk/batch payment requires human approval — aggregate amount must be verified"
}

# USSD transactions require approval (enforce channel limits)
escalate contains msg if {
	startswith(input.action, "ussd_")
	msg := "CBN USSD Guidelines: USSD transaction requires human review — verify ₦20,000 per-transaction / ₦100,000 daily limits"
}

# ── Audit rules (log regardless of outcome) ───────────────────────

# All financial actions must be logged for CBN examination
_action_has_financial_prefix if {
	some prefix in {"transfer_", "payment_", "refund_", "reversal_", "settlement_", "credit_", "debit_"}
	startswith(input.action, prefix)
}

audit contains msg if {
	_action_has_financial_prefix
	msg := "CBN Record-Keeping: Financial transaction action logged — required for CBN examination and NFIU reporting"
}

# ── Decision summary (top-level output) ──────────────────────────
# Callers can query: data.agt_policies_nigeria.cbn.decision

decision := "deny" if count(deny) > 0

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
