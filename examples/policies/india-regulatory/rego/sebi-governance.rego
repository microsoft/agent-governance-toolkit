# agt-policies-india - SEBI CSCRF 2024 + AI/ML Responsibility Amendment Feb 2025 (Rego reference)
# Enforcing authority: SEBI. Status: CSCRF + Feb-2025 binding; June-2025 guidelines draft. NOT loaded at runtime. RE2.
#
# Input schema:
#   { "action": "disable_audit_log",
#     "params": { "human_accountable": false, "log_storage_region": "SG", "vapt_completed": false },
#     "output": "agent output text" }

package agt_policies_india.sebi

import rego.v1

_output_text := v if { is_string(input.output); v := input.output } else := ""

ai_action_targets := {"place_order", "advise_investor", "execute_trade", "manage_portfolio"}
log_tamper_actions := {"disable_audit_log", "delete_audit_log", "make_log_mutable", "store_audit_log_offshore"}

# Feb 2025 amendment: RE solely responsible for AI/ML output; cannot disclaim
deny contains msg if {
	input.action in ai_action_targets
	not input.params.human_accountable == true
	msg := "SEBI Amendment 10 Feb 2025: regulated entity is solely responsible for AI/ML output; liability cannot be disclaimed and human accountability is required"
}

deny contains msg if {
	regex.match(`(?i)(not\s+responsible|disclaim\s+liability|no\s+human\s+accountab).{0,40}(ai|ml|model)\s+(output|decision)`, _output_text)
	msg := "SEBI Amendment 10 Feb 2025: AI/ML output liability cannot be disclaimed by the regulated entity"
}

# CSCRF 2024: immutable, India-retained audit logging
deny contains msg if {
	input.action in log_tamper_actions
	msg := "SEBI CSCRF 2024: maintain immutable, India-retained audit logging with continuous SOC monitoring"
}

deny contains msg if {
	not input.params.log_storage_region == "IN"
	region := object.get(input.params, "log_storage_region", "unset")
	msg := sprintf("SEBI CSCRF 2024: audit logs must be retained within India, configured region: '%v'", [region])
}

# CSCRF 2024: incident reporting - cannot suppress
deny contains msg if {
	regex.match(`(?i)(don'?t\s+(report|notify)|suppress|delay).{0,30}(cyber\s+)?(incident|breach)`, _output_text)
	msg := "SEBI CSCRF 2024: cyber incidents must be reported to SEBI and the relevant CERT within mandated timelines"
}

# CSCRF 2024: VAPT/audit before production - escalate
escalate contains msg if {
	input.action == "deploy_to_production"
	not input.params.vapt_completed == true
	msg := "SEBI CSCRF 2024: periodic VAPT and cyber audit, data classification, and access control are required before production"
}

# June 2025 AI/ML guidelines: DRAFT/advisory - audit only
audit contains msg if {
	regex.match(`(?i)deploy.{0,20}(ai|ml)\s+model.{0,20}(securities|trading|investor)`, _output_text)
	msg := "ADVISORY (draft, SEBI Consultation Paper 20 Jun 2025): board-approved AI governance, explainability, human-in-the-loop, and fallback plans proposed; not yet binding"
}

decision := "deny" if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit" if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow" if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
