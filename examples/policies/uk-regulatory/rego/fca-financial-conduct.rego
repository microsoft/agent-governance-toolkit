# agt-policies-uk - FCA Principles-Based AI Governance (Rego reference)
# FCA has no AI-specific binding rules as of 2026 — principles-based framework applies.
# NOT loaded by the Agent-OS Python runtime.
#
# Input schema:
#   { "action": "set_price",
#     "params": { "consumer_duty_assessed": false, "senior_manager_approved": false },
#     "output": "agent output text" }

package agt_policies_uk.fca_conduct

import rego.v1

_output_text := v if {
	is_string(input.output)
	v := input.output
} else := ""

pricing_actions := {
	"set_price", "adjust_rate", "calculate_premium",
	"score_creditworthiness", "determine_eligibility",
}

communication_actions := {
	"send_financial_advice", "generate_customer_communication",
	"draft_product_recommendation", "create_marketing_content",
}

third_party_ai_actions := {
	"invoke_external_ai", "call_third_party_model",
	"use_vendor_ai", "deploy_critical_third_party_ai",
}

autonomous_trading_actions := {
	"autonomous_trade", "execute_trade_without_approval",
	"self_directed_trading", "agent_place_order",
}

# PRIN 2A: consumer harm language
deny contains msg if {
	regex.match(`(?i)(mislead\s+(the\s+)?customer|hide\s+(fees|charges|risks)|exploit\s+vulnerabilit|target\s+vulnerable\s+customer|dark\s+pattern|push\s+unsuitable\s+product)`, _output_text)
	msg := "FCA Consumer Duty (PRIN 2A): agent cannot propose actions that foreseeably harm customers"
}

# PRIN 2A: fair value bypass
deny contains msg if {
	regex.match(`(?i)(skip\s+fair\s+value|bypass\s+value\s+assessment|no\s+need\s+to\s+(check|assess)\s+(fair\s+)?value|ignore\s+consumer\s+duty)`, _output_text)
	msg := "FCA Consumer Duty (PRIN 2A.4): firms must ensure products and services provide fair value"
}

# SM&CR: accountability delegation to AI
deny contains msg if {
	regex.match(`(?i)(the\s+ai\s+(decides|is\s+responsible)|algorithm\s+accountable|no\s+senior\s+manager\s+(needed|required)|delegate\s+accountability\s+to\s+(the\s+)?(model|ai|algorithm))`, _output_text)
	msg := "FCA SM&CR: senior managers remain accountable for AI risks — delegating to an algorithm does not transfer responsibility"
}

# Market conduct: autonomous trading without approval
deny contains msg if {
	input.action in autonomous_trading_actions
	not input.params.senior_manager_approved == true
	msg := "FCA market conduct: autonomous agent trading requires documented governance and senior manager approval"
}

# Consumer Duty: pricing without assessment
escalate contains msg if {
	input.action in pricing_actions
	not input.params.consumer_duty_assessed == true
	msg := "FCA Consumer Duty: AI-influenced pricing or eligibility decision — document testing for fairness and foreseeable harm"
}

# Consumer Duty: customer communications
audit contains msg if {
	input.action in communication_actions
	msg := "FCA Consumer Duty: AI-generated customer communication — verify clarity, accuracy, and information needs"
}

# Outsourcing / operational resilience: third-party AI
audit contains msg if {
	input.action in third_party_ai_actions
	msg := "FCA operational resilience: third-party AI component — map to governance, testing, and critical third-party risk"
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
