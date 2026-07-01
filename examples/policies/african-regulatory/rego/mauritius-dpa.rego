# agt-policies-africa
# Mauritius Data Protection Act 2017 — OPA Rego Policy
#
# Regulatory reference: Data Protection Act 2017 (Act No. 20 of 2017)
#                       Proclaimed through Proclamation No. 3 of 2018
#                       Effective: January 15, 2018
#                       Replaces Data Protection Act 2004
# Enforcing authority: Data Protection Office / Data Protection Commissioner
#                      https://dataprotection.govmu.org
#
# Key provisions enforced:
#   DPA 2017 (Registration)        — Mandatory registration of ALL controllers/processors
#                                    Penalty: MUR 200,000 or 5 years imprisonment
#   DPA 2017 (DPO)                 — DPO mandatory for ALL controllers/processors
#                                    No conflict of interest (not CEO/COO/CFO/CMO/HR/IT)
#   DPA 2017 (Special Categories)  — Racial/ethnic, political, religious, trade union,
#                                    health/mental, sexual orientation, genetic/biometric,
#                                    criminal proceedings
#   DPA 2017 (Breach Notification) — 72h to Commissioner; without undue delay to subjects
#                                    if high risk (exceptions: encrypted, risk resolved,
#                                    disproportionate effort)
#   DPA 2017 (Six Principles)      — Lawfulness/fairness/transparency, purpose limitation,
#                                    minimisation, accuracy, storage limitation, rights
#   DPA 2017 (Transfer)            — Proof of appropriate safeguards to Commissioner;
#                                    derogations: consent, contract, public interest,
#                                    legal claims, vital interests, compelling legitimate
#                                    interests (non-repetitive, limited, documented)
#   DPA 2017 (Security)            — Pseudonymisation, encryption, resilience, recovery,
#                                    regular testing
#   DPA 2017 (Automated Decisions) — Transparency: subjects must be informed of logic,
#                                    significance and consequences of automated decisions
#   DPA 2017 (Electronic Marketing) — Right to object at any time
#
# Mauritius NIC: [A-Z][0-9]{6,7}  (letter + 6-7 digits, e.g. A123456 or A1234567)
# Penalties: MUR 200,000 / 5 years (registration); MUR 50,000 / 2 years (notice)
#
# ⚠️  Mauritius DPA 2017 is the most GDPR-aligned data protection law in Africa.
#     Directly modeled on EU GDPR 2016/679. DPO mandatory for ALL controllers —
#     no size threshold (stricter than GDPR which has size/processing-volume tests).
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

package agt_policies_africa.mauritius_dpa

import rego.v1

# ── Permitted regions (Mauritius-hosted or Commissioner adequacy-approved) ──
permitted_regions := {
	"af-south-1",  # AWS Africa (Cape Town) — closest widely-available region
	"af-south-2",
	"af-east-1",
	"mauritius",
	"MU",
	"mu",
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

# ── Deny rules ─────────────────────────────────────────────────────────────

# DPA 2017 (Breach Notification): 72-hour Commissioner notification
# Data subjects notified without undue delay where high risk.
# Exceptions: encrypted, risk resolved, disproportionate effort.
deny contains msg if {
	regex.match(
		`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+(report|notification))`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Breach Notification): Agent cannot suppress breach notifications — Commissioner must be notified within 72 hours; data subjects notified without undue delay where high risk"
}

# DPA 2017 (Special Categories): Biometric data — uniquely identifying
# Genetic or biometric data that uniquely identifies a person is a special category.
deny contains msg if {
	regex.match(
		`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data))`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Special Categories): Biometric data detected — uniquely identifying biometrics are a special category; must not be transmitted without documented lawful basis and safeguards"
}

# DPA 2017 (Registration): ALL controllers and processors must register.
# Registration valid 3 years; renew 3 months before expiry.
# Penalty: MUR 200,000 or 5 years imprisonment.
deny contains msg if {
	regex.match(
		`(?i)(process(ing)?\s+(without|skip|bypass|ignore).{0,30}(register|registration|Commissioner|permit)|no\s+need\s+(to\s+)?(register|notify\s+(the\s+)?Commissioner))`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Registration): Agent cannot advise bypassing Commissioner registration — all controllers and processors must register (penalty: MUR 200,000 or 5 years imprisonment)"
}

# DPA 2017 (Breach Notification / Security): Mauritius National ID Card (NIC)
# Format: [A-Z][0-9]{6,7} (letter + 6-7 digits, e.g. A123456)
# Exposure triggers 72-hour Commissioner breach notification obligation.
deny contains msg if {
	regex.match(
		`(?i)(mauritius\s+(national\s+)?(id|identity|nic|card)|national\s+(identity\s+)?card\s+(no|number|#)|NIC\s+(no|number|#))[\s:=]{0,5}[A-Z][0-9]{6,7}`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Breach Notification / Security): Mauritius National ID Card (NIC) detected in agent output — blocked; triggers Commissioner breach notification within 72 hours"
}

# DPA 2017 (Transfer): Cross-border to non-permitted region requires proof of safeguards.
# Commissioner may prohibit, suspend or condition transfers.
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_region != null
	not input.params.destination_region in permitted_regions
	msg := sprintf(
		"Mauritius DPA 2017 (Transfer): Cross-border transfer to region '%v' blocked — proof of appropriate safeguards must be filed with the Commissioner or a valid derogation (consent, contract, public interest, legal claims) established",
		[input.params.destination_region],
	)
}

# DPA 2017 (Transfer): Transfer to non-MU country without documented consent/derogation.
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country != null
	input.params.destination_country != "MU"
	not input.context.consent_documented == true
	msg := sprintf(
		"Mauritius DPA 2017 (Transfer): Transfer to '%v' blocked — no documented consent or derogation (contract, vital interest, public interest, legal claims) filed with Commissioner",
		[input.params.destination_country],
	)
}

# DPA 2017 (Transfer / Security): Large record exports without documented safeguards.
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"Mauritius DPA 2017 (Transfer / Security): Export of %v records exceeds threshold — requires proof of appropriate safeguards filed with Commissioner and documented lawful basis",
		[input.params.record_count],
	)
}

# ── Escalate rules ─────────────────────────────────────────────────────────

# DPA 2017 (Special Categories): Health/medical/genetic/mental health data
escalate contains msg if {
	regex.match(
		`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|genetic\s+(data|test)|mental\s+health|disability|prescription|clinical\s+data|psychological\s+(report|assessment))`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Special Categories): Health/genetic/mental health data detected — requires lawful basis + legitimate controller activities + appropriate safeguards filed with Commissioner"
}

# DPA 2017 (Special Categories): Racial/ethnic, political, religious, trade union,
# sexual orientation/practices/preferences, criminal proceedings
escalate contains msg if {
	regex.match(
		`(?i)(racial\s+origin|ethnic\s+origin|political\s+opinion|political\s+adherence|religious\s+belief|philosophical\s+belief|trade\s+union|sexual\s+(orientation|practice|preference)|criminal\s+(proceeding|offence|conviction|record))`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Special Categories): Special category personal data detected — requires lawful basis + controller's legitimate activities + appropriate safeguards"
}

# DPA 2017 (DPO): Mandatory for ALL controllers/processors — escalate if advised against.
escalate contains msg if {
	regex.match(
		`(?i)(no\s+need\s+(for\s+)?(a\s+)?dpo|skip(ping)?\s+(the\s+)?dpo|don'?t\s+need\s+(a\s+)?data\s+protection\s+officer|dpo\s+(is\s+)?(optional|not\s+required))`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (DPO): DPO appointment is mandatory for ALL controllers and processors — no size threshold in Mauritius (stricter than EU GDPR); escalate for compliance review"
}

# DPA 2017 (Transfer): Cross-border language in agent output
escalate contains msg if {
	regex.match(
		`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+mauritius|cross.?border|international\s+transfer|offshore|foreign\s+server)`,
		input.output,
	)
	msg := "Mauritius DPA 2017 (Transfer): Cross-border data transfer language detected — proof of appropriate safeguards must be filed with the Commissioner before data leaves Mauritius"
}

# DPA 2017 (Transfer): Transfer action with missing destination metadata
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_region
	not input.params.destination_country
	msg := "Mauritius DPA 2017 (Transfer): Cross-border transfer action with no destination metadata — destination and safeguards must be documented before Commissioner review"
}

# DPA 2017 (Transfer / Security): Moderate record exports (100-1000)
escalate contains msg if {
	input.action in transfer_actions
	input.params.record_count > 100
	input.params.record_count <= 1000
	msg := sprintf(
		"Mauritius DPA 2017 (Transfer / Security): Export of %v records requires documented lawful basis and proof of appropriate safeguards filed with Commissioner",
		[input.params.record_count],
	)
}

# DPA 2017 (Transfer / Security): Bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "Mauritius DPA 2017 (Transfer / Security): Bulk personal data export requires proof of appropriate safeguards filed with Commissioner and documented lawful basis"
}

# DPA 2017 (Automated Decisions): Transparency obligation — data subjects must be informed
# of logic, significance, and envisaged consequences before automated decisions are applied.
escalate contains msg if {
	input.action in automated_decision_actions
	msg := "Mauritius DPA 2017 (Automated Decisions): Automated decision-making including profiling — data subject must be informed of the logic involved, significance and envisaged consequences before the decision is applied"
}

# ── Audit rules — DPA 2017 (Collection / Data Subject Rights) ─────────────

# Rights: access, rectification, restriction, erasure, objection, complaint, information.
audit contains msg if {
	pii_access_actions := {
		"read_user", "get_customer", "lookup_account",
		"fetch_profile", "query_personal", "access_pii",
	}
	input.action in pii_access_actions
	msg := "Mauritius DPA 2017 (Collection / Data Subject Rights): Personal data access logged — data subject rights (access, information) and Commissioner accountability requirement"
}

audit contains msg if {
	pii_update_actions := {
		"update_user", "modify_profile", "patch_account",
		"edit_customer", "change_personal", "delete_user", "erase_data",
	}
	input.action in pii_update_actions
	msg := "Mauritius DPA 2017 (Collection / Data Subject Rights): Personal data modification/erasure logged — data subject rights (rectification, restriction, erasure) and Commissioner accountability"
}

# ── Decision summary ───────────────────────────────────────────────────────

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
