# agt-policies-india - Aadhaar Act 2016 s.29 + 2021 Regulations (Rego reference)
# Enforcing authority: UIDAI. Status: binding. NOT loaded at runtime. OPA Go RE2 (no lookbehind/lookahead).
#
# Input schema:
#   { "action": "display_full_aadhaar",
#     "params": { "aadhaar_masked": false },
#     "output": "agent output text" }

package agt_policies_india.aadhaar

import rego.v1

_output_text := v if { is_string(input.output); v := input.output } else := ""

public_display_actions := {"publish_aadhaar", "display_full_aadhaar", "expose_uid"}

# 2021 Regulations: unmasked 12-digit Aadhaar in output (mask first 8, show last 4)
deny contains msg if {
	regex.match(`(?i)aadhaar\D{0,15}\d{12}\b`, _output_text)
	msg := "Aadhaar Regulations 2021: mask the first 8 of 12 Aadhaar digits (only last 4 may be shown); full Aadhaar must not be output, logged, or stored unmasked"
}

# Defence-in-depth: unmasked 12-digit run near UID/UIDAI context
deny contains msg if {
	regex.match(`(?i)(uid|uidai|unique\s+id).{0,15}\d{12}\b`, _output_text)
	msg := "Aadhaar Regulations 2021: unmasked 12-digit Aadhaar number detected near UID context - must be masked (last 4 only)"
}

# s.29(1): core biometric information never shared/displayed/stored by unauthorised entities
deny contains msg if {
	regex.match(`(?i)aadhaar.{0,20}(biometric|fingerprint|iris|retina)`, _output_text)
	msg := "Aadhaar Act s.29(1): core biometric information must never be shared, displayed, or stored by unauthorised entities"
}

# s.29(2)/(3): no public display / unauthorised disclosure of Aadhaar number
deny contains msg if {
	input.action in public_display_actions
	not input.params.aadhaar_masked == true
	msg := "Aadhaar Act s.29(2)/(3): public display or unauthorised disclosure of Aadhaar number and identity information is prohibited"
}

decision := "deny" if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit" if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow" if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
