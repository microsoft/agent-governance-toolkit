# agt-policies-nigeria
# NFIU AML/CFT — Anti-Money Laundering Controls (Rego)
#
# Regulatory references:
#   Money Laundering (Prevention and Prohibition) Act 2022 (MLPPA)
#   Terrorism (Prevention and Prohibition) Act 2022 (TPPA)
#   NFIU AML/CFT Regulations 2013 (as amended)
#   CBN AML/CFT/CPF Risk-Based Supervisory Framework 2023
#   FATF Recommendations (Nigeria FATF member obligations)
#
# Rego advantage over YAML:
#   Checks input.params.amount directly — exact numeric CTR threshold.
#   ₦5,000,000 CTR enforcement is unambiguous, not text-pattern matched.
#   Structuring zone (₦4.5M–₦4.99M) catches just-under-threshold amounts
#   that YAML regex cannot reliably identify.
#
# Input schema expected:
#   {
#     "action":  "nip_transfer",
#     "params":  { "amount": 6000000, "currency": "NGN" },
#     "output":  "agent output text",
#     "context": { "kyc_verified": true }
#   }

package agt_policies_nigeria.nfiu

import rego.v1

# ── Thresholds ────────────────────────────────────────────────────
ctr_threshold := 5000000 # MLPPA s.10: Currency Transaction Report threshold

nip_cap := 10000000 # CBN NIP single-transaction cap

structuring_zone_low := 4500000 # Just-under-threshold alert zone (lower bound)

transfer_actions := {
	"transfer_funds", "send_money", "wire_transfer",
	"nip_transfer", "instant_payment", "disburse_funds",
}

# ── Deny rules ────────────────────────────────────────────────────

# MLPPA / CBN NIP: transfer exceeding ₦10M cap — hard block
deny contains msg if {
	input.action in transfer_actions
	input.params.amount > nip_cap
	msg := sprintf(
		"NFIU CTR / CBN NIP: ₦%v exceeds ₦10,000,000 NIP single-transaction cap — blocked. CTR filing required.",
		[input.params.amount],
	)
}

# MLPPA s.14: Structuring (smurfing) — explicit split pattern in output
deny contains msg if {
	regex.match(`(?i)(split(ting)?|break(ing)?\s+(up|down)|divide|multiple\s+(transfers|payments|transactions)).{0,60}(avoid|under|below).{0,30}(threshold|limit|reporting|₦5|5\s*million)`, input.output)
	msg := "NFIU Structuring (MLPPA s.14): Transaction splitting to avoid CTR threshold detected — constitutes structuring, a criminal offence"
}

# CBN AML/CFT Framework: KYC bypass attempt
deny contains msg if {
	regex.match(`(?i)(skip\s+(kyc|verification|identity\s+check)|proceed\s+without\s+(verification|kyc)|waive\s+(kyc|due\s+diligence)|bypass\s+(kyc|customer\s+verification))`, input.output)
	msg := "NFIU / CBN AML: KYC bypass blocked — proceeding without customer verification violates MLPPA and CBN AML/CFT Framework"
}

# CBN AML/CFT Framework: transaction for unverified customer
deny contains msg if {
	regex.match(`(?i)(unverified\s+customer|customer\s+not\s+verified|no\s+kyc|kyc\s+(pending|incomplete|failed)).{0,40}(proceed|transfer|payment|transaction)`, input.output)
	msg := "NFIU / CBN AML: Transaction for unverified customer blocked — KYC must be completed before processing"
}

# ── Escalate rules (route to human review) ───────────────────────

# MLPPA s.10: Exact numeric CTR threshold on structured params
escalate contains msg if {
	input.action in transfer_actions
	input.params.amount >= ctr_threshold
	input.params.amount <= nip_cap
	msg := sprintf(
		"NFIU CTR (MLPPA s.10): Transfer of ₦%v is at or above ₦5,000,000 CTR threshold — requires human review and CTR filing assessment",
		[input.params.amount],
	)
}

# NFIU STR: round-trip / layering pattern in output
escalate contains msg if {
	regex.match(`(?i)(transfer.{0,30}back|send.{0,20}return|round.?trip|circular.{0,20}transfer|layering)`, input.output)
	msg := "NFIU STR Indicator: Round-trip or layering transaction pattern detected — requires human review for STR assessment"
}

# NFIU STR: unverified or unknown counterparty
escalate contains msg if {
	regex.match(`(?i)(unknown\s+(account|beneficiary|recipient)|unverified\s+(account|party)|no\s+(kyc|verification)\s+on\s+(file|record))`, input.output)
	msg := "NFIU STR Indicator: Transfer to unverified or unknown counterparty — requires human review before execution"
}

# NFIU STR: cash-equivalent or crypto conversion
escalate contains msg if {
	regex.match(`(?i)(gift\s+card|crypto|bitcoin|usdt|stable.?coin|mobile\s+money\s+to\s+cash|convert.{0,20}to\s+cash)`, input.output)
	msg := "NFIU STR Indicator: Cash-equivalent or crypto conversion — common money laundering typology, requires human review"
}

# NFIU STR / FATF Rec. 12: Politically Exposed Person transaction
escalate contains msg if {
	regex.match(`(?i)(PEP|politically\s+exposed|government\s+official|public\s+servant|elected\s+official|minister|senator|governor).{0,40}(transfer|payment|account|transaction)`, input.output)
	msg := "NFIU STR / FATF Rec. 12: Politically Exposed Person (PEP) transaction detected — enhanced due diligence required"
}

# ── Audit rules (log regardless of outcome) ───────────────────────

# MLPPA s.6: All financial transaction events must be logged
_action_has_financial_prefix if {
	some prefix in {
		"transfer_", "payment_", "refund_", "credit_",
		"debit_", "settlement_", "reversal_", "disbursement_",
	}
	startswith(input.action, prefix)
}

audit contains msg if {
	_action_has_financial_prefix
	msg := "NFIU Record-Keeping (MLPPA s.6): Financial transaction logged — 5-year retention required for NFIU examination on demand"
}

# NFIU Structuring Alert: amount in just-under-threshold zone (₦4.5M–₦4.99M)
audit contains msg if {
	input.action in transfer_actions
	input.params.amount >= structuring_zone_low
	input.params.amount < ctr_threshold
	msg := sprintf(
		"NFIU Structuring Alert: ₦%v is just under ₦5M CTR threshold — logged for STR review. Multiple occurrences in session may indicate structuring.",
		[input.params.amount],
	)
}

# ── Decision summary ──────────────────────────────────────────────
# Callers query: data.agt_policies_nigeria.nfiu.decision
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
