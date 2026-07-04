# agt-policies-uk - UK GDPR Arts. 22A–22D Automated Decision-Making (Rego reference)
# DUAA 2025 s.80 in force 5 February 2026. ICO ADM guidance draft (final expected summer 2026).
# NOT loaded by the Agent-OS Python runtime.
#
# Input schema:
#   { "action": "run_automated_decision",
#     "params": { "human_review_available": false, "explanation_provided": false },
#     "output": "agent output text" }

package agt_policies_uk.ico_adm

import rego.v1

_output_text := v if {
	is_string(input.output)
	v := input.output
} else := ""

significant_decision_actions := {
	"run_automated_decision", "automated_credit_decision",
	"automated_hiring_decision", "automated_eligibility",
	"profile_for_decision", "deploy_scoring_model",
}

agentic_actions := {
	"delegate_decision", "spawn_sub_agent", "orchestrate_agent", "chain_automated_step",
}

special_category_adm_actions := {
	"automated_decision_on_health", "automated_decision_on_biometric",
	"automated_decision_on_special_category",
}

deployment_actions := {
	"deploy_model", "deploy_agent", "launch_automated_system", "scale_automated_decisions",
}

# Art. 22C(1): withhold explanation
deny contains msg if {
	regex.match(`(?i)(don'?t\s+explain|no\s+explanation|withhold\s+(the\s+)?(reason|rationale)|hide\s+how\s+(the\s+)?decision|refuse\s+to\s+explain)`, _output_text)
	msg := "UK GDPR Art. 22C(1): individuals must receive decision-specific information explaining how and why the outcome was reached"
}

# Art. 22C(2)-(3): block human review
deny contains msg if {
	regex.match(`(?i)(no\s+human\s+(review|intervention|oversight)|refuse\s+human\s+review|cannot\s+request\s+human|deny\s+human\s+intervention)`, _output_text)
	msg := "UK GDPR Art. 22C(2)-(3): individuals must be able to make representations and obtain genuine human intervention"
}

# Art. 22C(4): block contest right
deny contains msg if {
	regex.match(`(?i)(cannot\s+contest|no\s+(right\s+to\s+)?(appeal|challenge)|final\s+decision\s+—\s+no\s+recourse|waive\s+(the\s+)?right\s+to\s+contest)`, _output_text)
	msg := "UK GDPR Art. 22C(4): individuals must be able to contest the decision through an accessible process"
}

# Art. 22A + Art. 9: special category ADM
deny contains msg if {
	input.action in special_category_adm_actions
	msg := "UK GDPR Art. 22A + Art. 9: automated decisions on special category data require stricter conditions — human review required"
}

# Art. 22A: significant decision without safeguards metadata
escalate contains msg if {
	input.action in significant_decision_actions
	not input.params.human_review_available == true
	msg := "UK GDPR Art. 22A: solely automated significant decision — verify Art. 22C safeguards (information, representations, human intervention, contest)"
}

# Art. 22A: significant decision without explanation
escalate contains msg if {
	input.action in significant_decision_actions
	not input.params.explanation_provided == true
	msg := "UK GDPR Art. 22C(1): decision-specific explanation must be available to the individual"
}

# ICO March 2026: recruitment ADM language
escalate contains msg if {
	regex.match(`(?i)(reject\s+(the\s+)?(candidate|applicant)|hire\s+decision|shortlist|score\s+(the\s+)?(candidate|applicant)).{0,40}(automated|without\s+human|ai\s+only)`, _output_text)
	msg := "ICO March 2026: automated recruitment decisions are in scope of Art. 22A — review safeguards before proceeding"
}

# Art. 22A: agentic orchestration step
escalate contains msg if {
	input.action in agentic_actions
	msg := "UK GDPR Art. 22A (agentic AI): each orchestration step taking a solely automated significant decision must meet Art. 22C safeguards and Art. 28 processor contracts"
}

# Art. 35: DPIA for deployment
audit contains msg if {
	input.action in deployment_actions
	msg := "UK GDPR Art. 35: data protection impact assessment required before deploying high-risk automated decision-making"
}

# Art. 22A: significant decision audit trail
audit contains msg if {
	input.action in significant_decision_actions
	msg := "UK GDPR Art. 22A: solely automated significant decision logged — verify lawful basis and Art. 22C safeguards"
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
