# agt-policies-india - DPDP Act 2023 + DPDP Rules 2025 (Rego reference)
# Enforcing authority: Data Protection Board of India (MeitY). Status: binding, phased.
# NOT loaded by the Agent-OS Python runtime. OPA uses Go RE2 (no lookbehind/lookahead).
#
# Input schema:
#   { "action": "transfer_personal_data",
#     "params": { "consent_logged": false, "encrypted": false },
#     "output": "agent output text" }

package agt_policies_india.dpdp

import rego.v1

_output_text := v if { is_string(input.output); v := input.output } else := ""

processing_actions := {"process_personal_data", "store_pii", "share_pii", "profile_user"}
transfer_actions := {"transfer_personal_data", "export_pii", "send_to_external"}
automated_decision_actions := {"deploy_model", "run_automated_decision", "profile_personal_data"}

# s.6: consent required before processing personal data
deny contains msg if {
	input.action in processing_actions
	not input.params.consent_logged == true
	msg := "DPDP s.6: processing personal data requires a logged, purpose-specific consent record"
}

# s.8(5): security safeguards - block unencrypted personal-data handling
deny contains msg if {
	input.action in processing_actions
	not input.params.encrypted == true
	msg := "DPDP s.8(5): personal data must be processed with reasonable security safeguards (encryption, access control)"
}

# s.8(6)+R7: cannot suppress/delay breach notification
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify)|hide\s+(the\s+)?(breach|incident)|suppress\s+(the\s+)?(breach|notification)|delay\s+breach\s+(report|notification))`, _output_text)
	msg := "DPDP s.8(6) and Rule 7: agent cannot suppress or delay breach notification to the Data Protection Board and affected Data Principals (72h detailed report)"
}

# s.16: cross-border transfer - escalate for adequacy/localization review (negative list currently empty)
escalate contains msg if {
	input.action in transfer_actions
	msg := "DPDP s.16: cross-border personal-data transfer requires review (Central-Govt restriction list plus stricter sectoral localization under RBI/SEBI)"
}

# Rule 13: SDF algorithmic due diligence - audit automated decisions on personal data
audit contains msg if {
	input.action in automated_decision_actions
	msg := "DPDP Rule 13 (Significant Data Fiduciary): verify algorithms/AI do not endanger Data Principal rights; DPIA plus annual independent audit"
}

decision := "deny" if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit" if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow" if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
