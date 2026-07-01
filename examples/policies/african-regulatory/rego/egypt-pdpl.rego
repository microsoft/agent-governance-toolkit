# agt-policies-africa
# Egypt Personal Data Protection Law No. 151/2020 — OPA Rego Policy
#
# Regulatory reference: Personal Data Protection Law No. 151 of 2020
#                       Executive Regulations: PM Decree No. 1699/2021
# Enforcing authority: Personal Data Protection Centre (PDPC / MCIT)
#                      https://pdp.mcit.gov.eg
#
# Key provisions enforced:
#   Art. 1    — Sensitive data: health, genetic, biometric, financial,
#               religious, political, criminal, children's data
#   Art. 2    — Data subject rights (access, correction, objection, deletion)
#   Art. 3    — Children's data processing conditions
#   Art. 4    — Sensitive data processing restrictions
#   Art. 6    — Lawful basis for processing
#   Art. 7    — Breach notification: 72h to PDPC; 3 days to data subjects
#   Art. 8    — DPO mandatory
#   Arts. 14-15 — Cross-border transfer restrictions (equivalent protection)
#   Art. 19   — PDPC establishment
#   Art. 26   — Licensing/registration required before processing
#   Anti-Cybercrimes Law No. 175/2018 Art. 25 — Security obligations
#
# Egypt National ID: 14-digit [2|3][YYMMDD][Gov 2d][Seq 4d][Check 1d]
# Penalties: Up to EGP 5,000,000 + imprisonment
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

package agt_policies_africa.egypt_pdpl

import rego.v1

# ── Permitted regions (Egypt-hosted or PDPC adequacy-approved) ────
# PDPC has not published an adequacy list as of 2024.
# Middle East and Africa regions used as geographically nearest safe defaults.
permitted_regions := {
	"af-south-1", # AWS Africa (Cape Town)
	"me-south-1", # AWS Middle East (Bahrain) — geographically nearest
	"me-central-1", # AWS UAE — close regional option
	"egypt",
	"EG",
	"eg",
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

# Art. 7: Block breach suppression — 72h PDPC + 3-day subject notification
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+(report|notification))`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 7: Agent cannot suppress breach notifications — PDPC must be notified within 72 hours and data subjects within 3 working days"
}

# Art. 1/4: Block biometric data — triggers Art. 7 breach notification
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 1/4: Biometric sensitive data detected — must not be transmitted; breach triggers 72h PDPC notification (Art. 7)"
}

# Art. 1/7: Block Egypt National ID in output (14-digit format)
# Format: [2|3][YYMMDD][Governorate 2d][Sequential 4d][Check 1d]
deny contains msg if {
	regex.match(`(?i)(egypt(ian)?\s+(national\s+)?(id|identity|card)|national\s+id\s+(no|number|#)|رقم\s+قومي)[\s:=]{0,5}[23][0-9]{13}`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 1/7: Egyptian National ID (14-digit) detected in agent output — blocked; triggers 72h PDPC breach notification"
}

# Art. 14: Block cross-border transfer to non-permitted region
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Egypt PDPL No. 151/2020 Art. 14: Cross-border transfer to region '%v' blocked — PDPC approval or equivalent protection documentation required",
		[input.params.destination_region],
	)
}

# Art. 14/15: Block transfer to non-EG country without documented consent/derogation
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "EG"
	not input.context.consent_documented == true
	msg := sprintf(
		"Egypt PDPL No. 151/2020 Arts. 14-15: Transfer to '%v' blocked — no documented consent or Art. 15 derogation (vital interest, legal necessity, contract) on file",
		[input.params.destination_country],
	)
}

# Art. 26: Block agents advising unlicensed data processing
deny contains msg if {
	regex.match(`(?i)(process(ing)?\s+(without|skip|bypass|ignore).{0,30}(licen(s|c)e|PDPC|permit|registr)|no\s+need\s+(to\s+)?(register|licen(s|c)e|notify\s+PDPC))`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 26: Agent cannot advise bypassing PDPC licensing — processing without registration is a criminal offence (up to EGP 2,000,000 + imprisonment)"
}

# Art. 6 / s.17: Block disproportionate bulk record exports
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Egypt PDPL No. 151/2020 Art. 6/14: Export of %v records exceeds threshold — requires documented lawful basis and PDPC approval",
		[input.params.record_count],
	)
}

# ── Escalate rules ────────────────────────────────────────────────

# Art. 1/4: Health/medical sensitive data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription|clinical\s+data|psychological\s+(assessment|report|status))`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 1/4: Health/medical/genetic sensitive data detected — requires explicit consent or Art. 5 exception (PDPC)"
}

# Art. 1/4: Financial data — unique sensitive category in Egypt
escalate contains msg if {
	regex.match(`(?i)(account\s+(balance|statement|number)|credit\s+(score|report|history)|loan\s+(default|history|status)|salary\s+(slip|detail)|tax\s+(return|record)|financial\s+(statement|profile|data))`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 1/4: Financial data is a sensitive category under Egyptian law — requires explicit consent (unique provision: financial data = sensitive in Egypt)"
}

# Art. 1/4: Special category data (religious, political, criminal, racial)
escalate contains msg if {
	regex.match(`(?i)(religious\s+belief|political\s+(view|opinion)|criminal\s+(record|conviction|offence)|ethnic\s+origin|race|sexual\s+(orientation|life))`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 1/4: Special category personal data detected — requires explicit consent or Art. 5 exception (PDPC)"
}

# Art. 1/3: Children's data — classified as sensitive in Egypt (unique in Africa)
escalate contains msg if {
	regex.match(`(?i)(child(ren)?'?s?\s+(data|record|profile|information)|minor\s+(data|record|profile)|under(\s+|-)(18|sixteen|eighteen)|student\s+(record|data|profile)|guardian\s+consent)`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 1/3: Children's data is a sensitive category — requires parental/guardian consent (unique classification in African data protection law)"
}

# Art. 14: Cross-border language in output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+egypt|cross.?border|international\s+transfer|offshore|foreign\s+server)`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 14: Cross-border data transfer language detected — PDPC approval or documented Art. 15 derogation required"
}

# Art. 14: Transfer action with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Egypt PDPL No. 151/2020 Art. 14: Cross-border transfer with no destination metadata — cannot verify equivalent protection; requires PDPC review"
}

# Art. 6: Moderate record exports
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Egypt PDPL No. 151/2020 Art. 6/14: Export of %v records requires documented lawful basis and PDPC cross-border approval",
		[input.params.record_count],
	)
}

# Art. 6: Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Egypt PDPL No. 151/2020 Art. 6: Bulk personal data export requires documented lawful basis, PDPC accountability, and licensing verification"
}

# Art. 8: DPO — escalate if agent advises against DPO appointment
escalate contains msg if {
	regex.match(`(?i)(no\s+need\s+(for\s+)?(a\s+)?dpo|skip(ping)?\s+(the\s+)?dpo|don'?t\s+need\s+(a\s+)?data\s+protection\s+officer)`, input.output)
	msg := "Egypt PDPL No. 151/2020 Art. 8: DPO appointment is mandatory for all data controllers — agent cannot advise against it"
}

# ── Audit rules — Art. 2 (data subject rights) ───────────────────

audit contains msg if {
	pii_actions := {"read_user", "get_customer", "lookup_account", "fetch_profile", "query_personal", "access_pii"}
	input.action in pii_actions
	msg := "Egypt PDPL No. 151/2020 Art. 2: Personal data access logged — data subject rights (access, information) and PDPC accountability requirement"
}

audit contains msg if {
	pii_update_actions := {"update_user", "modify_profile", "patch_account", "edit_customer", "change_personal", "delete_user", "erase_data"}
	input.action in pii_update_actions
	msg := "Egypt PDPL No. 151/2020 Art. 2: Personal data modification/erasure logged — data subject rights (correction, deletion, objection) and PDPC accountability"
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
