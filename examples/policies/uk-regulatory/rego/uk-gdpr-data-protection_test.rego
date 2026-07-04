# agt-policies-uk - UK GDPR + DPA 2018 (OPA tests)
package agt_policies_uk.uk_gdpr_test

import data.agt_policies_uk.uk_gdpr as policy
import rego.v1

test_allow_benign_action if {
	policy.decision == "allow" with input as {
		"action": "web_search",
		"output": "Search results for UK data protection guidance.",
	}
}

test_deny_breach_suppression if {
	policy.decision == "deny" with input as {
		"action": "notify_stakeholders",
		"output": "Don't report the breach to the ICO yet — wait a week.",
	}
}

test_deny_unencrypted_storage if {
	policy.decision == "deny" with input as {
		"action": "store_data",
		"output": "Store personal data in plaintext on the shared drive.",
	}
}

test_deny_nhs_number_in_output if {
	policy.decision == "deny" with input as {
		"action": "respond",
		"output": "NHS number: 943-476-5919",
	}
}

test_deny_ni_number_in_output if {
	policy.decision == "deny" with input as {
		"action": "respond",
		"output": "NI number AB123456C attached.",
	}
}

test_deny_complaints_bypass if {
	policy.decision == "deny" with input as {
		"action": "handle_complaint",
		"output": "Bypass the data protection complaint process and tell them to go away.",
	}
}

test_deny_transfer_without_safeguards if {
	policy.decision == "deny" with input as {
		"action": "export_data",
		"params": {"destination_country": "CN"},
		"output": "",
	}
}

test_allow_transfer_with_safeguards if {
	policy.decision == "allow" with input as {
		"action": "export_data",
		"params": {
			"destination_country": "CN",
			"safeguards_in_place": true,
		},
		"output": "",
	}
}

test_deny_large_export if {
	policy.decision == "deny" with input as {
		"action": "export_data",
		"params": {"record_count": 2500},
		"output": "",
	}
}

test_escalate_health_data if {
	policy.decision == "escalate" with input as {
		"action": "summarise",
		"output": "The patient mental health record shows recurring episodes.",
	}
}

test_escalate_cross_border_language if {
	policy.decision == "escalate" with input as {
		"action": "draft_email",
		"output": "We are transferring data outside the UK to a third country.",
	}
}

test_audit_pii_access if {
	policy.decision == "audit" with input as {
		"action": "read_user",
		"output": "",
	}
}

test_audit_pii_modification if {
	policy.decision == "audit" with input as {
		"action": "update_user",
		"output": "",
	}
}
