# agt-policies-nigeria
# BVN / NIN Data Protection Policy (Rego)
#
# Regulatory references:
#   CBN BVN Policy Framework (2014, updated 2023)
#   National Identity Management Commission (NIMC) Act
#   NDPA 2023 Schedule 1 — biometric data as sensitive personal data
#
# Rego advantage over YAML:
#   Can check structured fields (input.params.bvn_present, input.params.identifier_type)
#   alongside output pattern matching — two-layer enforcement.
#
# Input schema expected:
#   {
#     "action":  "verify_bvn",
#     "params":  { "bvn": "22345678901", "bvn_present": true, "identifier_type": "BVN" },
#     "output":  "agent output text",
#     "context": { "channel": "whatsapp", "purpose": "refund_verification" }
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
