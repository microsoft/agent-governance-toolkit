# agt-policies-africa
# Rwanda Personal Data Protection — OPA Rego Policy
#
# Regulatory reference: Law No. 058/2021 of 13/10/2021 Relating to the
#                       Protection of Personal Data and Privacy
# Enforcing authority: National Cyber Security Authority (NCSA) / RISA
#                      https://dpo.gov.rw
#
# Key articles enforced:
#   Art. 3(2)  — Sensitive data definition
#   Art. 10    — Grounds for processing sensitive data
#   Art. 21    — Right against automated decisions
#   Art. 43    — Breach notification to NCSA within 48 hours
#   Art. 48    — Cross-border transfer restrictions
#   Art. 49    — Contractual safeguards for international transfers
#   Art. 50    — Data storage location requirements
#   NIDA       — Rwanda National ID (16-digit format)
#
# Criminal penalties: up to 10 years + 25M RWF for sensitive data violations
#
# Input schema expected:
#   {
#     "action":  "export_data",
#     "params":  {
#       "destination_region":  "us-east-1",
#       "destination_country": "US",
#       "record_count":        500
#     },
#     "output":  "agent output text",
#     "context": { "consent_documented": false }
#   }

package agt_policies_africa.rwanda_dpa

import rego.v1

# ── Permitted regions (Rwanda-hosted or NCSA adequacy-approved) ───
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town)
	"af-east-1",  # East Africa region placeholder
	"rwanda",
	"RW",
	"rw",
}

transfer_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote",
}

bulk_export_actions := {
	"bulk_export", "export_all", "download_all_records",
	"dump_database", "full_table_export", "batch_download_pii",
}

automated_decision_actions := {
	"auto_approve", "auto_reject", "automated_credit",
	"algorithmic_decision", "auto_score", "auto_deny",
}

# ── Deny rules ────────────────────────────────────────────────────

# Art. 43: Block breach suppression — 48-hour NCSA notification (strictest in Africa)
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+(report|notification))`, input.output)
	msg := "Rwanda Law 058/2021 Art. 43: Agent cannot suppress breach notifications — NCSA must be notified within 48 hours (strictest timeline in Africa)"
}

# Art. 3(2)/10: Block biometric data transmission
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Rwanda Law 058/2021 Art. 3(2)/10: Biometric data detected — must not be transmitted without documented lawful basis and NCSA notification"
}

# Art. 48: Block cross-border transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Rwanda Law 058/2021 Art. 48: Cross-border transfer to region '%v' blocked — destination country adequacy not established with NCSA",
		[input.params.destination_region],
	)
}

# Art. 48/49: Block transfer to non-RW country without documented consent
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "RW"
	not input.context.consent_documented == true
	msg := sprintf(
		"Rwanda Law 058/2021 Art. 48/49: Transfer to '%v' blocked — no documented consent or contractual safeguards on file",
		[input.params.destination_country],
	)
}

# NIDA: Block Rwanda National ID in output (16-digit format)
deny contains msg if {
	regex.match(`(?i)(rwanda\s+(national\s+)?id|nida\s+(id|number|no)|rwandan\s+id)[\s:=]{0,5}[0-9]{16}`, input.output)
	msg := "Rwanda Law 058/2021 Art. 43: Rwanda National ID (NIDA 16-digit) detected in agent output — blocked to prevent identity data breach"
}

# Art. 50: Block large record exports (storage location restrictions)
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Rwanda Law 058/2021 Art. 50: Export of %v records exceeds threshold — requires NCSA contractual safeguards and DPO review",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# Art. 3(2)/10: Health/medical sensitive data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription|clinical\s+data)`, input.output)
	msg := "Rwanda Law 058/2021 Art. 3(2)/10: Health/medical sensitive data detected — requires explicit consent or documented lawful basis"
}

# Art. 3(2)/10: Special category data
escalate contains msg if {
	regex.match(`(?i)(race|ethnic\s+origin|social\s+origin|political\s+opinion|religious\s+belief|philosophical\s+belief|sexual\s+(life|orientation)|family\s+(detail|data)|criminal\s+(record|conviction))`, input.output)
	msg := "Rwanda Law 058/2021 Art. 3(2)/10: Special category personal data detected — requires specific processing grounds (Art. 10)"
}

# Art. 21: Automated individual decision-making — data subject has right to human review
escalate contains msg if {
	input.action in automated_decision_actions
	msg := "Rwanda Law 058/2021 Art. 21: Automated individual decision-making — data subject has right to contest; escalate for human oversight"
}

# Art. 48: Cross-border language in output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+rwanda|cross.?border|international\s+transfer|offshore|foreign\s+server)`, input.output)
	msg := "Rwanda Law 058/2021 Art. 48: Cross-border data transfer language detected — adequacy and contractual safeguards (Art. 49) required"
}

# Art. 48: Transfer action with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Rwanda Law 058/2021 Art. 48: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# Art. 50: Moderate record exports
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Rwanda Law 058/2021 Art. 50: Export of %v records requires NCSA contractual safeguard documentation",
		[input.params.record_count],
	)
}

# Art. 50: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Rwanda Law 058/2021 Art. 50: Bulk personal data export requires documented lawful basis and NCSA notification"
}

# ── Audit rules — Art. 18 / Art. 23 / Art. 24 ───────────────────

audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Rwanda Law 058/2021 Art. 18: Personal data access logged — data subject access right and NCSA accountability requirement"
}

audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal", "delete_user", "erase_data"}
	input.action in pii_update_actions
	msg := "Rwanda Law 058/2021 Art. 23/24: Personal data modification/erasure logged — data subject rights and NCSA accountability requirement"
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
