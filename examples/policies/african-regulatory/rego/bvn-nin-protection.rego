# agt-policies-nigeria
# BVN / NIN Data Protection Policy (Rego)
#
# Regulatory references:
#   CBN BVN Policy Framework (2014, updated 2023)
#   NIMC Act 2026 (signed 26 June 2026) — repeals NIMC Act Cap N99 LFN 2004
#     Purpose limitation, illegal data persistence prohibition,
#     mandatory NIN prerequisite for regulated services,
#     penalties: ₦20M (corporate) / 5 years min. imprisonment (individual)
#   NDPA 2023 Schedule 1 — biometric data as sensitive personal data
#
# Rego advantage over YAML:
#   Can check structured fields (input.params.bvn_present, input.params.identifier_type,
#   input.params.persist_nin, input.context.nin_purpose) alongside output pattern matching.
#
# Input schema expected:
#   {
#     "action":  "verify_bvn",
#     "params":  { "bvn": "22345678901", "bvn_present": true, "identifier_type": "BVN",
#                  "persist_nin": false },
#     "output":  "agent output text",
#     "context": { "channel": "whatsapp", "purpose": "refund_verification",
#                  "nin_purpose": "account_opening", "nin_verified": true }
#   }

package agt_policies_nigeria.bvn_nin

import rego.v1

# ── Verification actions ──────────────────────────────────────────
bvn_verification_actions := {
	"verify_bvn", "check_bvn", "validate_bvn",
	"bvn_lookup", "nibss_bvn_verify",
}

nin_verification_actions := {
	"verify_nin", "check_nin", "validate_nin",
	"nin_lookup", "nimc_nin_verify",
}

transmission_actions := {
	"send_bvn", "transmit_bvn", "share_bvn",
	"send_nin", "transmit_nin", "share_nin",
	"post_identity", "relay_kyc",
}

# ── NIMC Act 2026 — Action sets ───────────────────────────────────
persist_actions := {
	"store_nin", "save_nin_data", "persist_identity",
	"cache_nin", "log_nin", "record_nin", "write_nin_record",
	"store_bvn", "save_bvn_data", "cache_bvn",
}

bulk_export_actions := {
	"export_nin_data", "bulk_nin_export", "download_nin_records",
	"extract_identity_records", "bulk_identity_export",
}

mandatory_nin_service_actions := {
	"open_account", "create_account", "register_voter",
	"apply_passport", "sim_registration", "land_registration",
	"pension_enrollment", "insurance_enrollment", "apply_credit",
	"tax_registration", "apply_government_service",
}

# ── Deny rules ────────────────────────────────────────────────────

# Block BVN value in agent output (label + digits pattern)
deny contains msg if {
	regex.match(`(?i)(bvn\s+is|bvn:\s*|bvn\s*=|your\s+bvn|the\s+bvn)[\s:]*[0-9]{10,11}`, input.output)
	msg := "BVN Protection: BVN value detected in agent output — blocked (NDPA Schedule 1 biometric data)"
}

# Block contextual BVN pattern in output
deny contains msg if {
	regex.match(`(?i)(bvn|bank\s+verification).{0,20}\b[0-9]{11}\b`, input.output)
	msg := "BVN Protection: BVN pattern detected in agent output — blocked to prevent credential exposure"
}

# Block NIN value in agent output
deny contains msg if {
	regex.match(`(?i)(nin\s+is|nin:\s*|nin\s*=|your\s+nin|the\s+nin)[\s:]*[0-9]{10,11}`, input.output)
	msg := "NIN Protection: NIN value detected in agent output — blocked (NDPA Schedule 1 biometric data)"
}

# Block virtual NIN (vNIN) in output
deny contains msg if {
	regex.match(`(?i)(vnin|virtual\s+nin)[\s:=]+[A-Z0-9]{16}`, input.output)
	msg := "NIN Protection: Virtual NIN (vNIN) detected in agent output — blocked"
}

# Block direct BVN/NIN transmission to external systems
deny contains msg if {
	input.action in transmission_actions
	msg := "BVN/NIN Transmission: Direct BVN/NIN transmission blocked — use NIBSS tokenised verification flow"
}

# Block BVN present in params from being passed externally
deny contains msg if {
	input.params.bvn_present == true
	input.action in transmission_actions
	msg := "BVN/NIN Transmission: BVN detected in params with external transmission action — blocked"
}

# Block BVN disclosure over conversational channels (social engineering)
deny contains msg if {
	regex.match(`(?i)(customer\s+(wants|needs|asked|requested).{0,30}(bvn|nin)|confirm.{0,20}(bvn|nin).{0,20}(over|via|through)\s+(chat|call|whatsapp|email|sms))`, input.output)
	msg := "BVN/NIN Social Engineering: Attempt to disclose BVN/NIN through conversational channel — blocked"
}

# ── NIMC Act 2026 — Deny rules ────────────────────────────────────

# Block illegal data persistence (NIMC Act 2026 — ₦20M corporate / 5yr individual penalty)
deny contains msg if {
	input.action in persist_actions
	msg := "NIMC Act 2026: Storing NIN/BVN data after verification is prohibited — illegal data persistence (₦20M corporate / 5yr individual penalty)"
}

# Block persist_nin=true flag in params
deny contains msg if {
	input.params.persist_nin == true
	msg := "NIMC Act 2026: persist_nin=true detected — NIN data may not be stored after verification completes"
}

# Block bulk NIN/identity data export
deny contains msg if {
	input.action in bulk_export_actions
	msg := "NIMC Act 2026: Bulk NIN/identity data export is prohibited — only individual authorised verifications are permitted"
}

# Block bulk_identity_export=true flag in params
deny contains msg if {
	input.params.bulk_identity_export == true
	msg := "NIMC Act 2026: bulk_identity_export=true detected — bulk identity extraction is prohibited"
}

# ── Escalate rules ────────────────────────────────────────────────

# BVN verification always requires human approval
escalate contains msg if {
	input.action in bvn_verification_actions
	msg := "BVN Verification: BVN lookup requires human approval — CBN BVN Framework mandates audit trail for all lookups"
}

# NIN verification always requires human approval
escalate contains msg if {
	input.action in nin_verification_actions
	msg := "NIN Verification: NIN lookup requires human approval — NIMC Act requires documented purpose for each lookup"
}

# NIMC Act 2026 — Purpose limitation: NIN/BVN lookup without declared purpose
escalate contains msg if {
	input.action in nin_verification_actions
	not input.context.nin_purpose
	msg := "NIMC Act 2026: NIN lookup attempted without a declared purpose — purpose limitation requires stating the reason before each verification"
}

escalate contains msg if {
	input.action in bvn_verification_actions
	not input.context.nin_purpose
	msg := "NIMC Act 2026: BVN lookup attempted without a declared purpose — purpose limitation requires stating the reason before each verification"
}

# NIMC Act 2026 — Purpose mismatch: consented purpose differs from current purpose
escalate contains msg if {
	input.context.nin_consented_purpose != ""
	input.context.purpose != ""
	input.context.nin_consented_purpose != input.context.purpose
	msg := sprintf(
		"NIMC Act 2026: Purpose mismatch — NIN was consented for '%v' but current purpose is '%v'",
		[input.context.nin_consented_purpose, input.context.purpose],
	)
}

# Escalate if identifier type is BVN/NIN in params
escalate contains msg if {
	input.params.identifier_type in {"BVN", "NIN", "bvn", "nin"}
	not input.action in transmission_actions # transmission is deny, not escalate
	msg := sprintf(
		"BVN/NIN Gate: Action '%v' involves %v identifier — requires human approval before proceeding",
		[input.action, input.params.identifier_type],
	)
}

# ── Audit rules ───────────────────────────────────────────────────

# All identity-related actions must be logged
_action_has_identity_pattern if {
	some pattern in {"bvn", "nin", "kyc", "identity_verify"}
	contains(input.action, pattern)
}

audit contains msg if {
	_action_has_identity_pattern
	msg := "BVN/NIN Audit: Identity-related action logged — NDPA s.30 and CBN BVN audit trail requirement"
}

# NIMC Act 2026 — Mandatory NIN prerequisite: regulated services require verified NIN
audit contains msg if {
	input.action in mandatory_nin_service_actions
	not input.context.nin_verified
	msg := sprintf(
		"NIMC Act 2026: Action '%v' is a mandatory-NIN service — bank accounts, SIM, passports, land transactions, pension, insurance, and consumer credit require context.nin_verified = true",
		[input.action],
	)
}

# ── Decision summary ─────────────────────────────────────────────
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
