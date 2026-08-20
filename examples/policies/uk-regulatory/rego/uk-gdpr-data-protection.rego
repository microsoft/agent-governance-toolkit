# agt-policies-uk - UK GDPR + DPA 2018 (Rego reference)
# Enforcing authority: ICO. DUAA 2025 transfer and complaints reforms in force Feb/Jun 2026.
# Loaded via ACS YAML (uk-gdpr-data-protection.yaml). OPA uses Go RE2 (no lookbehind/lookahead).
#
# Input schema:
#   { "action": "export_data",
#     "params": { "destination_country": "JP", "record_count": 500 },
#     "output": "agent output text",
#     "context": { } }
#
# Config (override via data.config.uk_gdpr.* — platform/deployer only):
#   adequacy_countries — replace illustrative default set (US is never a default)
#   eu_us_data_privacy_framework — true when org is UK Extension to EU-US DPF certified
#   supplementary_measures — true when supplementary measures are documented
# Caller-set input.params adequacy/DPF/safeguards flags are ignored for transfer denies.

package agt_policies_uk.uk_gdpr

import rego.v1

# Match Agent-OS / production Rego: stringify before regex (never coerce to "").
_output_text := v if {
	is_string(input.output)
	v := input.output
} else := sprintf("%v", [object.get(input, "output", "")])

transfer_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote", "transfer_personal_data",
}

bulk_export_actions := {
	"bulk_export", "export_all", "download_all_records",
	"dump_database", "full_table_export", "batch_download_pii",
}

pii_access_actions := {
	"read_user", "get_customer", "lookup_account", "fetch_profile",
	"query_personal", "access_pii", "subject_access_request",
}

pii_update_actions := {
	"update_user", "modify_profile", "patch_account", "edit_customer",
	"change_personal", "erase_personal_data",
}

# Illustrative UK adequacy set (verify against current gov.uk list).
# US omitted from defaults — DPF-certified bridge only (see _us_transfer_allowed).
_default_adequacy_countries := {
	"GB", "EU", "EEA", "JP", "KR", "CA", "NZ", "CH", "IL", "UY",
}

adequacy_countries := s if {
	s := data.config.uk_gdpr.adequacy_countries
} else := _default_adequacy_countries

# Platform-set only — mirrors agent-os/templates/policies/gdpr.yaml us_data_transfer.
_us_transfer_allowed if {
	data.config.uk_gdpr.eu_us_data_privacy_framework == true
	data.config.uk_gdpr.supplementary_measures == true
}

_destination_permitted if {
	input.params.destination_country in adequacy_countries
}

_destination_permitted if {
	input.params.destination_country == "US"
	_us_transfer_allowed
}

# Art. 33: block breach suppression
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident)|suppress\s+(the\s+)?(breach|notification)|delay\s+(breach|incident)\s+(report|notification)|wait\s+before\s+report(ing)?\s+(to\s+)?(the\s+)?ico)`, _output_text)
	msg := "UK GDPR Art. 33: where a breach is likely to result in a risk to rights and freedoms, notify the ICO without undue delay and, where feasible, within 72 hours — agent cannot suppress or delay notification"
}

# Art. 34: block suppression of individual notification
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(tell|inform|notify)\s+(the\s+)?(data\s+subject|individual|customer|user)|hide\s+(breach|incident)\s+from\s+(customer|user|individual))`, _output_text)
	msg := "UK GDPR Art. 34: individuals must be informed without undue delay where breach poses high risk"
}

# Art. 32: block unencrypted personal data handling in output
deny contains msg if {
	regex.match(`(?i)(store|transmit|log|cache).{0,30}(personal\s+data|pii).{0,30}(unencrypted|plaintext|clear\s*text|without\s+encryption)`, _output_text)
	msg := "UK GDPR Art. 32: personal data must be processed with appropriate technical and organisational security measures proportionate to risk (encryption, access control, or equivalent safeguards)"
}

# DPA 2018 s.164A: block complaints bypass
deny contains msg if {
	regex.match(`(?i)(skip|bypass|ignore|refuse).{0,30}(data\s+protection\s+complaint|ico\s+complaint|complaints?\s+(process|procedure|handling))`, _output_text)
	msg := "DPA 2018 s.164A (DUAA): data subjects must be able to raise data protection complaints with the controller (30-day acknowledgment) before ICO escalation"
}

# NHS number in output
deny contains msg if {
	regex.match(`(?i)nhs\s*(number|no\.?)[\s:=]{0,5}[0-9]{3}[\s-]?[0-9]{3}[\s-]?[0-9]{4}`, _output_text)
	msg := "UK GDPR: NHS number detected in agent output — blocked to prevent health identity exposure"
}

# National Insurance number in output
deny contains msg if {
	regex.match(`(?i)(national\s+insurance|ni\s+number)[\s:=]{0,5}[A-Z]{2}[0-9]{6}[A-D]`, _output_text)
	msg := "UK GDPR: National Insurance number detected in agent output — blocked to prevent identity exposure"
}

# Art. 44–46: block transfer without adequacy / platform-set DPF (never caller-attested)
deny contains msg if {
	input.action in transfer_actions
	input.params.destination_country
	not _destination_permitted
	msg := sprintf(
		"UK GDPR Art. 44–46: transfer to '%v' blocked — requires adequacy, IDTA/UK Addendum safeguards, and data protection test (DUAA 'not materially lower' standard)",
		[input.params.destination_country],
	)
}

# Art. 5(1)(c): block large exports without review
deny contains msg if {
	input.action in transfer_actions
	input.params.record_count > 1000
	msg := sprintf(
		"UK GDPR Art. 5(1)(c): export of %v records is disproportionate — requires data minimisation review",
		[input.params.record_count],
	)
}

# Art. 9: special category health data
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|nhs\s+number|genetic\s+(data|test)|mental\s+health|disability|prescription)`, _output_text)
	msg := "UK GDPR Art. 9: health data is special category — requires Art. 9(2) condition and Schedule 1 DPA basis"
}

# Art. 9: other special category data
escalate contains msg if {
	regex.match(`(?i)(ethnic\s+origin|race|religion|political\s+opinion|sexual\s+orientation|trade\s+union|criminal\s+conviction|biometric\s+(template|data))`, _output_text)
	msg := "UK GDPR Art. 9: special category personal data detected — explicit consent or Schedule 1 DPA condition required"
}

# Art. 5(1)(b): purpose limitation language in output
escalate contains msg if {
	regex.match(`(?i)(reuse|repurpose|secondary\s+use|use\s+for\s+another\s+purpose).{0,40}(personal\s+data|pii)`, _output_text)
	msg := "UK GDPR Art. 5(1)(b): personal data must not be further processed incompatibly — verify compatible purpose or DUAA recognised legitimate interests before repurposing"
}

# Art. 44–46: escalate transfer action when destination not specified
escalate contains msg if {
	input.action in transfer_actions
	not input.params.destination_country
	msg := "UK GDPR Art. 44–46: cross-border transfer action — confirm adequacy coverage or binding safeguards plus documented data protection test before export"
}

# Art. 44: cross-border language without structured params
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?).{0,60}(outside\s+(the\s+)?uk|cross.?border|international\s+transfer|third\s+country|offshore)`, _output_text)
	msg := "UK GDPR Art. 44: restricted transfer language detected — verify adequacy, safeguards, and data protection test"
}

# Art. 5(1)(c): bulk export actions
escalate contains msg if {
	input.action in bulk_export_actions
	msg := "UK GDPR Art. 5(1)(c): bulk personal data export requires documented necessity and DPO review"
}

# Art. 30: personal data access audit
audit contains msg if {
	input.action in pii_access_actions
	msg := "UK GDPR Art. 5(2) / Art. 30: personal data access logged for accountability and records of processing"
}

# Art. 30: personal data modification audit
audit contains msg if {
	input.action in pii_update_actions
	msg := "UK GDPR Art. 5(2) / Art. 30: personal data modification logged for accountability and records of processing"
}

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


# Native ACS result adapters
import data.agt_policies.acs

acs_input_result := result if {
	legacy := acs.legacy_input(input, "input")
	denials := deny with input as legacy
	escalations := escalate with input as legacy
	audits := audit with input as legacy
	result := acs.normalize(denials, escalations, audits)
}

acs_pre_tool_call_result := result if {
	legacy := acs.legacy_input(input, "pre_tool_call")
	denials := deny with input as legacy
	escalations := escalate with input as legacy
	audits := audit with input as legacy
	result := acs.normalize(denials, escalations, audits)
}

acs_output_result := result if {
	legacy := acs.legacy_input(input, "output")
	denials := deny with input as legacy
	escalations := escalate with input as legacy
	audits := audit with input as legacy
	result := acs.normalize(denials, escalations, audits)
}
