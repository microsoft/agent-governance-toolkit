# agt-policies-africa
# POPIA — Protection of Personal Information Act (South Africa) — Rego
#
# Regulatory references:
#   Protection of Personal Information Act 4 of 2013 (POPIA)
#   Information Regulator (South Africa) — enforcement authority
#   POPIA commencement: 1 July 2021 (grace period ended 30 June 2022)
#
# Rego advantage over YAML:
#   Checks input.params.destination_country against a structured adequacy list
#   (POPIA s.72) — unambiguous country-code enforcement, not output regex.
#   SA ID number validated with format-aware regex (YYMMDD + 7 digits).
#
# Input schema expected:
#   {
#     "action":  "export_data",
#     "params":  {
#       "destination_country": "ZA",
#       "destination_region":  "af-south-1",
#       "record_count": 100
#     },
#     "output":  "agent output text",
#     "context": { "consent_documented": true }
#   }

package agt_policies_africa.popia

import rego.v1

# ── POPIA s.72 — Adequacy list ────────────────────────────────────
# Countries recognised as having substantially similar data protection to POPIA.
# This is a simplified starter list for governance tooling — production deployments
# must conduct their own adequacy assessments with qualified Information Officers.
adequate_countries := {
	"ZA", # South Africa (origin)
	"GB", # UK GDPR
	"DE", "FR", "IE", "NL", # EU GDPR member states
	"BE", "SE", "NO", "DK", "FI", # EU/EEA GDPR
	"CA", # Canada PIPEDA
	"NZ", # New Zealand Privacy Act 2020
	"NG", # Nigeria NDPA 2023 (aligned)
	"KE", # Kenya DPA 2019 (aligned)
}

cross_border_actions := {
	"send_to_external", "export_data", "upload_to_cloud",
	"forward_to", "relay_data", "sync_to_remote",
}

# ── Deny rules ────────────────────────────────────────────────────

# POPIA s.26(1)(f): Biometric personal information in output
deny contains msg if {
	regex.match(`(?i)(fingerprint|facial\s+recognition|retina|iris\s+scan|voice\s+print|biometric\s+(template|hash|data|record))`, input.output)
	msg := "POPIA s.26(1)(f): Biometric personal information detected in agent output — requires documented POPIA s.27 exception"
}

# POPIA s.26(1)(h): Children's personal information
deny contains msg if {
	regex.match(`(?i)(minor|child\s+(data|record|profile|account)|under\s+(18|sixteen|fourteen)|children'?s\s+(data|information|personal\s+info))`, input.output)
	msg := "POPIA s.26(1)(h): Children's personal information must not be processed by AI agents without a separate consent framework"
}

# POPIA s.19: SA ID Number (YYMMDD + 7 digits) detected in output
deny contains msg if {
	regex.match(`\b[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{7}\b`, input.output)
	msg := "POPIA s.19: SA ID Number (13-digit) detected in agent output — blocked to prevent sensitive identifier exposure"
}

# POPIA s.19: SA ID Number with contextual label
deny contains msg if {
	regex.match(`(?i)(id\s+number|identity\s+number|sa\s+id|south\s+african\s+id)[\s:=]+[0-9]{13}`, input.output)
	msg := "POPIA s.19: SA ID Number value detected in agent response — blocked"
}

# POPIA s.22: Breach notification suppression
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify|disclose)|hide\s+(the\s+)?(breach|incident|leak)|suppress\s+(alert|notification)|delay\s+(breach|incident)\s+report)`, input.output)
	msg := "POPIA s.22: Agent cannot suppress or delay breach notification — Information Regulator must be notified without unreasonable delay"
}

# POPIA s.72: Transfer to non-adequate country without consent (structured params)
deny contains msg if {
	input.action in cross_border_actions
	input.params.destination_country != null
	not input.params.destination_country in adequate_countries
	not input.context.consent_documented == true
	msg := sprintf(
		"POPIA s.72: Transfer to '%v' blocked — country not recognised as having substantially similar data protection to POPIA",
		[input.params.destination_country],
	)
}

# POPIA s.11: Purpose limitation — processing beyond original consent
deny contains msg if {
	regex.match(`(?i)(process(ing)?.{0,40}(beyond|outside|new\s+purpose|repurpose|use\s+for\s+something\s+else)|(data|information).{0,30}(without\s+(consent|permission|authorisation)))`, input.output)
	msg := "POPIA s.11: Purpose limitation — agent cannot process personal information for a purpose beyond the original consent"
}

# ── Escalate rules ────────────────────────────────────────────────

# POPIA s.72: Any cross-border transfer action requires Information Officer approval
escalate contains msg if {
	input.action in cross_border_actions
	msg := "POPIA s.72: Cross-border personal information transfer requires Information Officer approval and destination adequacy assessment"
}

# POPIA s.72: Cross-border transfer language in output
escalate contains msg if {
	regex.match(`(?i)(send(ing)?|transfer(ring)?|export(ing)?|upload(ing)?).{0,60}(outside\s+south\s+africa|cross.?border|international\s+transfer|offshore|foreign\s+server)`, input.output)
	msg := "POPIA s.72: Cross-border data transfer language detected — requires Information Officer approval"
}

# POPIA s.26(1)(e): Health / medical special personal information
escalate contains msg if {
	regex.match(`(?i)(medical\s+record|health\s+(condition|status|data)|HIV|mental\s+health|disability|chronic\s+illness|prescription|clinical)`, input.output)
	msg := "POPIA s.26(1)(e): Health/medical special personal information detected — requires explicit lawful basis under POPIA s.27"
}

# POPIA s.26(1)(b): Race / ethnic origin special personal information
escalate contains msg if {
	regex.match(`(?i)(race|ethnic\s+origin|racial\s+(group|classification)|coloured|population\s+group)`, input.output)
	msg := "POPIA s.26(1)(b): Race/ethnic origin special personal information — requires lawful basis and heightened controls"
}

# POPIA s.26(1)(g): Criminal history special personal information
escalate contains msg if {
	regex.match(`(?i)(criminal\s+(record|history|conviction|background)|prior\s+(offence|offense|conviction)|police\s+clearance)`, input.output)
	msg := "POPIA s.26(1)(g): Criminal history special personal information — requires explicit lawful processing basis"
}

# ── Audit rules ───────────────────────────────────────────────────

# POPIA s.17: All personal information access must be logged for RESPONSIBLE PARTY accountability
audit contains msg if {
	pii_actions := {
		"read_customer", "get_profile", "lookup_account",
		"fetch_record", "query_personal", "access_data",
	}
	input.action in pii_actions
	msg := "POPIA s.17: Personal information access logged — RESPONSIBLE PARTY accountability record for Information Regulator"
}

# ── Decision summary ──────────────────────────────────────────────
# Callers query: data.agt_policies_africa.popia.decision
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
