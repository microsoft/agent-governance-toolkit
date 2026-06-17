# agt-policies-africa
# Kenya Data Protection Act 2019 — Data Protection Policy (Rego)
#
# Regulatory references:
#   Kenya Data Protection Act 2019 (Kenya DPA)
#   Enforcing authority: Office of the Data Protection Commissioner (ODPC)
#
# Rego advantage over YAML:
#   Checks structured params (destination_region, record_count) directly.
#   Provides exact cross-border enforcement — not regex on output text.
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

package agt_policies_africa.kdpa

import rego.v1

# ── Permitted regions (Kenya-hosted or adequacy-approved) ─────────
# Organisations must conduct an adequacy assessment per Kenya DPA s.49
# before expanding this list.
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town) — nearest available
	"af-east-1", # Hypothetical Kenya/East Africa region placeholder
	"kenya",
	"KE",
	"ke",
}

# Cross-border transfer actions
transfer_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote",
}

# Bulk data export actions (Kenya DPA s.30 — data minimisation)
bulk_export_actions := {
	"bulk_export", "export_all", "download_all_records",
	"dump_database", "full_table_export", "batch_download_pii",
}

# ── Deny rules ────────────────────────────────────────────────────

# Kenya DPA s.41: Block breach suppression
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, input.output)
	msg := "Kenya DPA s.41: Agent cannot suppress breach notifications — 72-hour ODPC reporting obligation applies"
}

# Kenya DPA s.49: Block transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Kenya DPA s.49: Cross-border transfer to '%v' blocked — region not in ODPC adequacy-approved list",
		[input.params.destination_region],
	)
}

# Kenya DPA s.49: Block transfer to non-KE country without consent
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "KE"
	not input.context.consent_documented == true
	msg := sprintf(
		"Kenya DPA s.49: Transfer to country '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# Kenya DPA s.26: Block processing explicitly stated without consent
deny contains msg if {
	regex.match(`(?i)(process(ing)?|shar(ing)?|us(ing)?).{0,30}(without\s+consent|no\s+consent|bypass.{0,10}consent)`, input.output)
	msg := "Kenya DPA s.26: Data processing without consent is prohibited — valid consent or documented legal basis required"
}

# Kenya DPA s.25: Block biometric data transmission
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Kenya DPA s.25: Biometric data detected — must not be transmitted without documented lawful basis"
}

# Kenya DPA: Block National ID in output
deny contains msg if {
	regex.match(`(?i)(national\s+id|id\s+number|identity\s+card)[\s:=]{0,5}[0-9]{6,8}`, input.output)
	msg := "Kenya DPA: National ID number detected in agent output — blocked to prevent identity exposure"
}

# Kenya DPA s.30: Block large record exports (>1000 records)
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Kenya DPA s.30: Export of %v records is disproportionate — requires Data Protection Officer review",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# Kenya DPA s.25: Health/medical data requires approval
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription)`, input.output)
	msg := "Kenya DPA s.25: Health/medical sensitive personal data detected — requires explicit consent or documented legal basis"
}

# Kenya DPA s.25: Special category data requires approval
escalate contains msg if {
	regex.match(`(?i)(ethnic\s+origin|race|religion|political\s+opinion|sexual\s+orientation|trade\s+union|criminal\s+conviction)`, input.output)
	msg := "Kenya DPA s.25: Special category personal data detected — explicit consent or Schedule 3 condition required"
}

# Kenya DPA s.49: Cross-border language in output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+kenya|cross.?border|international\s+transfer|offshore)`, input.output)
	msg := "Kenya DPA s.49: Cross-border data transfer language detected — requires ODPC adequacy verification"
}

# Kenya DPA s.49: Transfer with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Kenya DPA s.49: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# Kenya DPA s.30: Moderate record exports (100–1000 records)
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Kenya DPA s.30: Export of %v records requires Data Protection Officer approval before execution",
		[input.params.record_count],
	)
}

# Kenya DPA s.30: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Kenya DPA s.30: Bulk personal data export requires documented lawful basis and DPO approval"
}

# ── Audit rules ───────────────────────────────────────────────────

# Kenya DPA s.31: All personal data access must be logged
audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Kenya DPA s.31: Personal data access logged — ODPC accountability audit trail requirement"
}

# Kenya DPA s.31: All personal data modifications must be logged
audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal"}
	input.action in pii_update_actions
	msg := "Kenya DPA s.31: Personal data modification logged — ODPC accountability audit trail requirement"
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
