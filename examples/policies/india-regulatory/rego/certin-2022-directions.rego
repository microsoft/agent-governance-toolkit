# agt-policies-india - CERT-In Directions 2022 (Rego reference)
# Enforcing authority: CERT-In, MeitY. Status: binding (IT Act s.70B). NOT loaded at runtime. RE2.
#
# Input schema:
#   { "action": "store_logs_offshore",
#     "params": { "log_retention_days": 90, "log_storage_region": "EU", "ntp_synced": false },
#     "output": "agent output text" }

package agt_policies_india.certin

import rego.v1

_output_text := v if { is_string(input.output); v := input.output } else := ""

# Direction (ii): 6-hour reporting - cannot suppress/delay
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify)|skip\s+(the\s+)?(cert.?in\s+)?report|suppress\s+(the\s+)?(incident|breach)|delay\s+(the\s+)?(incident|breach)\s+report)`, _output_text)
	msg := "CERT-In 2022 Directions (ii): cyber incidents must be reported to CERT-In within 6 hours; suppressing/delaying is prohibited"
}

# Direction (iv): 180-day in-India log retention
deny contains msg if {
	input.params.log_retention_days < 180
	msg := sprintf("CERT-In 2022 Directions (iv): ICT logs must be retained for 180 days, configured: %v", [input.params.log_retention_days])
}

deny contains msg if {
	not input.params.log_storage_region == "IN"
	region := object.get(input.params, "log_storage_region", "unset")
	msg := sprintf("CERT-In 2022 Directions (iv): logs must be retained within India, configured region: '%v'", [region])
}

# Direction (i): NTP clock sync - escalate if not synced
escalate contains msg if {
	not input.params.ntp_synced == true
	msg := "CERT-In 2022 Directions (i): synchronise ICT system clocks to NIC/NPL NTP servers or traceable sources"
}

# No audit-tier conditions for this policy; defined empty for decision-ladder parity and
# to pass `opa check --strict` (count() on an undefined rule set is rego_unsafe_var_error).
audit := set()

decision := "deny" if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit" if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow" if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
