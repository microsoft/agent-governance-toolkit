# agt-policies-uk - ICO Automated Decision-Making (OPA tests)
package agt_policies_uk.ico_adm_test

import data.agt_policies_uk.ico_adm as policy
import rego.v1

test_allow_benign_action if {
	policy.decision == "allow" with input as {
		"action": "web_search",
		"output": "Summarise ICO guidance on data protection impact assessments.",
	}
}

test_deny_withhold_explanation if {
	policy.decision == "deny" with input as {
		"action": "respond",
		"output": "Don't explain how the credit decision was reached.",
	}
}

test_deny_refuse_human_review if {
	policy.decision == "deny" with input as {
		"action": "respond",
		"output": "No human review is available for this automated eligibility outcome.",
	}
}

test_deny_block_contest_right if {
	policy.decision == "deny" with input as {
		"action": "respond",
		"output": "Final decision — no appeal or challenge is permitted.",
	}
}

test_deny_special_category_adm if {
	policy.decision == "deny" with input as {
		"action": "automated_decision_on_health",
		"output": "",
	}
}

test_escalate_significant_decision_without_safeguards if {
	policy.decision == "escalate" with input as {
		"action": "run_automated_decision",
		"params": {
			"human_review_available": false,
			"explanation_provided": false,
		},
		"output": "",
	}
}

test_escalate_recruitment_adm_language if {
	policy.decision == "escalate" with input as {
		"action": "draft_summary",
		"output": "Reject the candidate using an automated AI-only score.",
	}
}

test_escalate_agentic_delegation if {
	policy.decision == "escalate" with input as {
		"action": "spawn_sub_agent",
		"output": "",
	}
}

test_audit_model_deployment if {
	policy.decision == "audit" with input as {
		"action": "deploy_model",
		"output": "",
	}
}

test_audit_significant_decision_with_safeguards if {
	policy.decision == "audit" with input as {
		"action": "automated_credit_decision",
		"params": {
			"human_review_available": true,
			"explanation_provided": true,
		},
		"output": "",
	}
}
