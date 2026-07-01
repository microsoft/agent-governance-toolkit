# agt-policies-africa
# Ghana Data Protection Act 2012 (Act 843) — OPA Rego Policy
#
# Regulatory reference: Ghana Data Protection Act, 2012 (Act 843)
# Enforcing authority: Data Protection Commission (DPC) — dataprotection.org.gh
#
# Key articles enforced:
#   s.17   — Eight data protection principles
#   s.33   — Data subject participation (access, correction, deletion)
#   s.37   — Special personal data (sensitive categories)
#   s.38   — Cross-border transfer (adequacy requirement)
#   s.40   — Data security obligations
#   NIA Act 707 — Ghana Card national ID (GHA-XXXXXXXXX-X)
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

package agt_policies_africa.ghana_dpa

import rego.v1

# ── Permitted regions (Ghana-hosted or DPC adequacy-approved) ─────
# Ghana DPC has not published a formal adequacy list as of 2024.
# Closest available Africa regions used as safe defaults.
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town)
	"af-west-1",  # West Africa region placeholder
	"ghana",
	"GH",
	"gh",
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

# s.40: Block breach suppression — DPC must be notified promptly
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+(report|notification))`, input.output)
	msg := "Ghana DPA Act 843 s.40: Agent cannot suppress breach notifications — DPC and affected data subjects must be notified promptly"
}

# s.37: Block biometric data transmission
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Ghana DPA Act 843 s.37: Biometric data detected — must not be transmitted without explicit consent and DPC notification"
}

# s.38: Block cross-border transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Ghana DPA Act 843 s.38: Cross-border transfer to region '%v' blocked — destination country adequacy not verified with DPC",
		[input.params.destination_region],
	)
}

# s.38: Block transfer to non-GH country without documented consent
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "GH"
	not input.context.consent_documented == true
	msg := sprintf(
		"Ghana DPA Act 843 s.38: Transfer to '%v' blocked — no documented consent or adequacy basis on file",
		[input.params.destination_country],
	)
}

# NIA Act 707: Block Ghana Card national ID in output
# Format: GHA-XXXXXXXXX-X (GHA prefix + 9 digits + 1 check digit)
deny contains msg if {
	regex.match(`(?i)(ghana\s+(card|id|national\s+id)|GHA-[0-9]{9}-[0-9]|GHA[0-9]{10})`, input.output)
	msg := "Ghana DPA Act 843 / NIA Act 707: Ghana Card national ID detected in agent output — blocked to prevent identity data exposure"
}

# s.17: Block disproportionate record exports (data minimisation)
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Ghana DPA Act 843 s.17: Export of %v records is disproportionate — data minimisation principle requires DPC accountability",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# s.37: Health/medical special personal data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription|clinical\s+data)`, input.output)
	msg := "Ghana DPA Act 843 s.37: Health/medical special personal data detected — requires explicit consent or documented lawful basis"
}

# s.37: Special category data (ethnic, religious, political, trade union, criminal)
escalate contains msg if {
	regex.match(`(?i)(ethnic\s+origin|race|tribe|political\s+opinion|religious\s+belief|trade\s+union|sexual\s+(life|orientation)|criminal\s+(offence|conviction|record)|court\s+proceedings)`, input.output)
	msg := "Ghana DPA Act 843 s.37: Special personal data detected — requires explicit consent and restricted processing"
}

# s.38: Cross-border language in agent output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+ghana|cross.?border|international\s+transfer|offshore|foreign\s+server)`, input.output)
	msg := "Ghana DPA Act 843 s.38: Cross-border data transfer language detected — destination country adequacy must be verified with DPC"
}

# s.38: Transfer action with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Ghana DPA Act 843 s.38: Cross-border transfer with no destination metadata — cannot verify adequacy, requires human review"
}

# s.17: Moderate record exports (data minimisation principle)
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Ghana DPA Act 843 s.17: Export of %v records requires documented purpose and DPC accountability",
		[input.params.record_count],
	)
}

# s.17: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Ghana DPA Act 843 s.17: Bulk personal data export requires documented lawful purpose and DPC notification"
}

# ── Audit rules — s.33 / s.17 (accountability, participation) ────

audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Ghana DPA Act 843 s.33: Personal data access logged — data subject participation and DPC accountability requirement"
}

audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal", "delete_user", "erase_data"}
	input.action in pii_update_actions
	msg := "Ghana DPA Act 843 s.33: Personal data modification/deletion logged — data subject participation and DPC accountability requirement"
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
