# agt-policies-africa
# Tanzania Personal Data Protection Act 2022 — Data Protection Policy (Rego)
#
# Regulatory reference: Tanzania Personal Data Protection Act 2022
# Enforcing authority: Personal Data Protection Commission (PDPC)
#
# Input schema expected:
#   {
#     "action":  "export_data",
#     "params":  {
#       "destination_region": "us-east-1",
#       "destination_country": "US",
#       "record_count": 500
#     },
#     "output":  "agent output text",
#     "context": { "consent_documented": false, "legal_basis": "" }
#   }

package agt_policies_africa.tanzania_pdpa

import rego.v1

# ── Permitted regions (Tanzania-hosted or adequacy-approved) ──────
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town) — nearest available
	"af-east-1",  # East Africa region placeholder
	"tanzania",
	"TZ",
	"tz",
}

transfer_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote",
}

bulk_export_actions := {
	"bulk_export", "export_all", "download_all_records",
	"dump_database", "full_table_export", "batch_download_pii",
}

# ── Deny rules ────────────────────────────────────────────────────

# PDPA s.28: Block breach suppression
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, input.output)
	msg := "Tanzania PDPA s.28: Agent cannot suppress breach notifications — 72-hour PDPC reporting obligation applies"
}

# PDPA s.17: Block biometric data transmission
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Tanzania PDPA s.17: Biometric data detected — must not be transmitted without documented lawful basis"
}

# PDPA s.13: Block transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Tanzania PDPA s.13: Cross-border transfer to '%v' blocked — region not in PDPC adequacy-approved list",
		[input.params.destination_region],
	)
}

# PDPA s.13: Block transfer to non-TZ country without consent
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "TZ"
	not input.context.consent_documented == true
	msg := sprintf(
		"Tanzania PDPA s.13: Transfer to country '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# PDPA s.8: Block processing without consent
deny contains msg if {
	regex.match(`(?i)(process(ing)?|shar(ing)?|us(ing)?).{0,30}(without\s+consent|no\s+consent|bypass.{0,10}consent)`, input.output)
	msg := "Tanzania PDPA s.8: Data processing without lawful basis is prohibited — valid consent or documented legal basis required"
}

# PDPA: Block NIDA national ID in output
deny contains msg if {
	regex.match(`(?i)(nida\s+(number|no|#)|national\s+id|tanzania\s+id)[\s:=]{0,5}[0-9]{20}`, input.output)
	msg := "Tanzania PDPA: NIDA national ID number detected in agent output — blocked to prevent identity exposure"
}

# PDPA s.30: Block large record exports (>1000 records)
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Tanzania PDPA s.30: Export of %v records is disproportionate — requires Data Protection Officer review",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# PDPA s.17: Health/medical data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription)`, input.output)
	msg := "Tanzania PDPA s.17: Health/medical special category data detected — requires explicit consent or documented legal basis"
}

# PDPA s.17: Special category data
escalate contains msg if {
	regex.match(`(?i)(ethnic\s+origin|race|tribe|political\s+opinion|religious\s+belief|trade\s+union|sexual\s+orientation|criminal\s+conviction)`, input.output)
	msg := "Tanzania PDPA s.17: Special category personal data detected — explicit consent or lawful processing condition required"
}

# PDPA s.13: Cross-border language in output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+tanzania|cross.?border|international\s+transfer|offshore)`, input.output)
	msg := "Tanzania PDPA s.13: Cross-border data transfer language detected — requires PDPC adequacy verification"
}

# PDPA s.13: Transfer with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Tanzania PDPA s.13: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# PDPA s.30: Moderate record exports
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Tanzania PDPA s.30: Export of %v records requires Data Protection Officer approval",
		[input.params.record_count],
	)
}

# PDPA s.30: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Tanzania PDPA s.30: Bulk personal data export requires documented lawful basis and DPO approval"
}

# ── Audit rules ───────────────────────────────────────────────────

audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Tanzania PDPA s.25: Personal data access logged — PDPC accountability audit trail requirement"
}

audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	msg := "Tanzania PDPA s.25: Personal data modification logged — PDPC accountability audit trail requirement"
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
