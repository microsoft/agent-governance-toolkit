# agt-policies-africa
# Ethiopia Personal Data Protection — Data Protection Policy (Rego)
#
# Regulatory reference: Computer Crime Proclamation No. 958/2016 (interim)
#                       Electronic Transactions Proclamation No. 1205/2020
#                       Ethiopia Personal Data Protection Proclamation (forthcoming)
# Enforcing authority: Ethiopian Communications Authority (ECA) / MInT
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

# ECA oversight: Block breach suppression
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, input.output)
	msg := "Ethiopia: Agent cannot suppress breach notifications — ECA incident reporting obligation applies"
}

# Draft PDPP: Block biometric data transmission
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Ethiopia draft PDPP: Biometric data detected — must not be transmitted without documented lawful basis and ECA notification"
}

# Draft PDPP: Block cross-border transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Ethiopia draft PDPP: Cross-border transfer to '%v' blocked — region not in ECA adequacy-approved list",
		[input.params.destination_region],
	)
}

# Draft PDPP: Block transfer to non-ET country without consent
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "ET"
	not input.context.consent_documented == true
	msg := sprintf(
		"Ethiopia draft PDPP: Transfer to country '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# Proclamation 958/2016: Block unauthorised access signals
deny contains msg if {
	regex.match(`(?i)(unauthori[sz]ed\s+(access|login|entry)|bypass(ing)?\s+(auth|security|login)|circumvent(ing)?\s+(access|control))`, input.output)
	msg := "Ethiopia Proclamation 958/2016: Unauthorised system access signal detected — blocked. This may constitute a criminal offence."
}

# Draft PDPP: Block Fayda/national ID in output
deny contains msg if {
	regex.match(`(?i)(fayda\s+(id|number|no)|ethiopia\s+(national\s+)?id|mosip\s+id)[\s:=]{0,5}[0-9]{10,16}`, input.output)
	msg := "Ethiopia: Fayda/National ID number detected in agent output — blocked to prevent identity exposure"
}

# Draft PDPP: Block large record exports
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Ethiopia draft PDPP: Export of %v records is disproportionate — requires Data Protection Officer review",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# Draft PDPP: Health/medical data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription)`, input.output)
	msg := "Ethiopia draft PDPP: Health/medical sensitive data detected — requires explicit consent or documented legal basis"
}

# Draft PDPP: Special category data
escalate contains msg if {
	regex.match(`(?i)(ethnic\s+origin|tribe|political\s+opinion|religious\s+belief|trade\s+union|sexual\s+orientation|criminal\s+conviction)`, input.output)
	msg := "Ethiopia draft PDPP: Special category personal data detected — requires explicit consent or lawful processing condition"
}

# Draft PDPP: Cross-border language
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+ethiopia|cross.?border|international\s+transfer|offshore)`, input.output)
	msg := "Ethiopia draft PDPP: Cross-border data transfer language detected — requires ECA adequacy verification"
}

# Draft PDPP: Transfer with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Ethiopia draft PDPP: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# Draft PDPP: Moderate record exports
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Ethiopia draft PDPP: Export of %v records requires Data Protection Officer approval",
		[input.params.record_count],
	)
}

# Draft PDPP: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Ethiopia draft PDPP: Bulk personal data export requires documented lawful basis and ECA notification"
}

# ── Audit rules ───────────────────────────────────────────────────

audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Ethiopia draft PDPP: Personal data access logged — ECA accountability audit trail requirement"
}

audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	msg := "Ethiopia draft PDPP: Personal data modification logged — ECA accountability audit trail requirement"
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
