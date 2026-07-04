# agt-policies-uk - FCA Principles-Based AI Governance (OPA tests)
package agt_policies_uk.fca_conduct_test

import data.agt_policies_uk.fca_conduct as policy
import rego.v1

test_allow_benign_action if {
	policy.decision == "allow" with input as {
		"action": "draft_internal_note",
		"output": "Summarise the Consumer Duty good outcomes framework.",
	}
}

test_deny_consumer_harm if {
	policy.decision == "deny" with input as {
		"action": "draft_message",
		"output": "Hide fees from the customer in this renewal letter.",
	}
}

test_deny_fair_value_bypass if {
	policy.decision == "deny" with input as {
		"action": "draft_policy",
		"output": "Skip fair value assessment — no need to check value for this product.",
	}
}

test_deny_delegate_accountability if {
	policy.decision == "deny" with input as {
		"action": "draft_memo",
		"output": "The AI is responsible for this decision so no senior manager is needed.",
	}
}

test_deny_autonomous_trading_without_approval if {
	policy.decision == "deny" with input as {
		"action": "autonomous_trade",
		"params": {"senior_manager_approved": false},
		"output": "",
	}
}

test_allow_autonomous_trading_with_approval if {
	policy.decision == "allow" with input as {
		"action": "autonomous_trade",
		"params": {"senior_manager_approved": true},
		"output": "",
	}
}

test_escalate_pricing_without_consumer_duty_assessment if {
	policy.decision == "escalate" with input as {
		"action": "set_price",
		"params": {"consumer_duty_assessed": false},
		"output": "",
	}
}

test_audit_customer_communication if {
	policy.decision == "audit" with input as {
		"action": "generate_customer_communication",
		"output": "",
	}
}

test_audit_third_party_ai if {
	policy.decision == "audit" with input as {
		"action": "invoke_external_ai",
		"output": "",
	}
}
