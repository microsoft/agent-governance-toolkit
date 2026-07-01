# agt-policies-africa
# Ethiopia Personal Data Protection — Data Protection Policy (Rego)
#
# Regulatory reference: Ethiopia Personal Data Protection Proclamation No. 1321/2024
#                       (Enacted July 24, 2024 — Federal Negarit Gazette)
#                       Ethiopia Computer Crime Proclamation No. 958/2016
# Enforcing authority: Ethiopian Communications Authority (ECA)
#
# Key articles:
#   Art. 9   — Sensitive personal data (health, biometric, genetic, ethnic, religious)
#   Art. 18  — Principle of data transfer (adequacy requirement)
#   Art. 20  — Conditions for cross-border transfer
#   Art. 22  — Data sovereignty (critical data must remain in-country)
#   Art. 43  — Breach notification to ECA within 72 hours
#   Art. 46  — Record of processing operations
#   Art. 52  — Accountability
#   Proc. 958/2016 — Unauthorised access criminal offence
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

package agt_policies_africa.ethiopia_pdp

import rego.v1

# ── Permitted regions (Ethiopia-hosted or adequacy-approved) ──────
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town) — nearest available
	"af-east-1",  # East Africa region placeholder
	"ethiopia",
	"ET",
	"et",
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

# Art. 43: Block breach suppression — ECA must be notified within 72 hours
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, input.output)
	msg := "Ethiopia PDPP 1321/2024 Art. 43: Agent cannot suppress breach notifications — ECA must be notified within 72 hours of awareness"
}

# Art. 9: Block biometric data transmission
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Ethiopia PDPP 1321/2024 Art. 9: Biometric data detected — must not be transmitted without documented lawful basis and ECA notification"
}

# Art. 18/19: Block cross-border transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Ethiopia PDPP 1321/2024 Art. 18: Cross-border transfer to '%v' blocked — region not in ECA adequacy-approved list",
		[input.params.destination_region],
	)
}

# Art. 20: Block transfer to non-ET country without documented consent or adequacy
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "ET"
	not input.context.consent_documented == true
	msg := sprintf(
		"Ethiopia PDPP 1321/2024 Art. 20: Transfer to '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# Proclamation 958/2016: Block unauthorised access signals
deny contains msg if {
	regex.match(`(?i)(unauthori[sz]ed\s+(access|login|entry)|bypass(ing)?\s+(auth|security|login)|circumvent(ing)?\s+(access|control))`, input.output)
	msg := "Ethiopia Proclamation 958/2016: Unauthorised system access signal detected — blocked. This constitutes a criminal offence."
}

# Art. 43: Block Fayda/national ID in output (identity data breach)
# Fayda falls under Art. 2 "identifier" definition in Proclamation 1321/2024
deny contains msg if {
	regex.match(`(?i)(fayda\s+(id|number|no)|ethiopia\s+(national\s+)?id|mosip\s+id)[\s:=]{0,5}[0-9]{10,16}`, input.output)
	msg := "Ethiopia PDPP 1321/2024 Art. 43: Fayda/National ID number detected in agent output — blocked to prevent identity data breach"
}

# Art. 22: Block large record exports — data sovereignty
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Ethiopia PDPP 1321/2024 Art. 22: Export of %v records is disproportionate — requires Data Protection Officer review and ECA notification",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# Art. 9: Health/genetic sensitive data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription)`, input.output)
	msg := "Ethiopia PDPP 1321/2024 Art. 9: Health/genetic sensitive data detected — requires explicit consent or documented lawful condition"
}

# Art. 9: Special category data (ethnic, religious, political, trade union)
escalate contains msg if {
	regex.match(`(?i)(ethnic\s+origin|tribe|political\s+opinion|religious\s+belief|trade\s+union|sexual\s+orientation|criminal\s+conviction)`, input.output)
	msg := "Ethiopia PDPP 1321/2024 Art. 9: Special category personal data detected — requires explicit consent or lawful processing condition"
}

# Art. 18: Cross-border language in agent output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+ethiopia|cross.?border|international\s+transfer|offshore)`, input.output)
	msg := "Ethiopia PDPP 1321/2024 Art. 18: Cross-border data transfer language detected — requires ECA adequacy verification"
}

# Art. 20: Transfer action with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Ethiopia PDPP 1321/2024 Art. 20: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# Art. 22: Moderate record exports — data sovereignty
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Ethiopia PDPP 1321/2024 Art. 22: Export of %v records requires Data Protection Officer approval",
		[input.params.record_count],
	)
}

# Art. 22: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Ethiopia PDPP 1321/2024 Art. 22: Bulk personal data export requires documented lawful basis and ECA notification"
}

# ── Audit rules — Art. 46 / Art. 52 ─────────────────────────────

audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Ethiopia PDPP 1321/2024 Art. 46/52: Personal data access logged — record of processing operations and accountability requirement"
}

audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	msg := "Ethiopia PDPP 1321/2024 Art. 46/52: Personal data modification logged — record of processing operations and accountability requirement"
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
