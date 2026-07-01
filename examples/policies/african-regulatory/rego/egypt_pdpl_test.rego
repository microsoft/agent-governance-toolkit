# agt-policies-africa
# Tests for Egypt Personal Data Protection Law No. 151/2020
# Run: opa test policies/rego/ -v

package agt_policies_africa.egypt_pdpl_test

import data.agt_policies_africa.egypt_pdpl
import rego.v1

# ── Deny: breach suppression ──────────────────────────────────────

test_deny_breach_suppression if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Don't report this incident to the PDPC.",
		"context": {},
	}
}

test_deny_suppress_notification if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We should hide the breach from authorities.",
		"context": {},
	}
}

# ── Deny: biometric data ──────────────────────────────────────────

test_deny_fingerprint_in_output if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint template extracted and stored.",
		"context": {},
	}
}

test_deny_facial_recognition_in_output if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Facial recognition biometric data confirmed for customer.",
		"context": {},
	}
}

# ── Deny: Egypt National ID (14-digit) ───────────────────────────

test_deny_egypt_national_id_labeled if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Egyptian national id: 29801011234567",
		"context": {},
	}
}

test_deny_national_id_number_labeled if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "National ID No: 30005121234561",
		"context": {},
	}
}

# ── Deny: cross-border to non-permitted region ────────────────────

test_deny_us_east_cross_border if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 5},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_eu_west_cross_border if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "sync_to_remote",
		"params": {"destination_region": "eu-west-1", "destination_country": "FR", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Deny: unlicensed processing advice ───────────────────────────

test_deny_skip_pdpc_license if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "No need to register with PDPC for this processing activity.",
		"context": {},
	}
}

# ── Deny: large record export ─────────────────────────────────────

test_deny_record_count_1001 if {
	count(egypt_pdpl.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 1001},
		"output": "", "context": {},
	}
}

# ── Allow: permitted regions ──────────────────────────────────────

test_allow_egypt_region if {
	egypt_pdpl.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "egypt", "destination_country": "EG", "record_count": 5},
		"output": "", "context": {},
	}
}

test_allow_me_south_1 if {
	egypt_pdpl.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "me-south-1", "destination_country": "EG", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Escalate: health / medical data ──────────────────────────────

test_escalate_health_data if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer medical record shows hypertension diagnosis.",
		"context": {},
	}
}

test_escalate_hiv_status if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer HIV status is negative.",
		"context": {},
	}
}

test_escalate_psychological_assessment if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer psychological assessment shows anxiety disorder.",
		"context": {},
	}
}

# ── Escalate: financial sensitive data (unique Egypt provision) ───

test_escalate_credit_score if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer credit score is 720.",
		"context": {},
	}
}

test_escalate_account_balance if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer account balance is EGP 250,000.",
		"context": {},
	}
}

test_escalate_loan_default if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer has a loan default history on record.",
		"context": {},
	}
}

# ── Escalate: special category data ──────────────────────────────

test_escalate_religious_belief if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's religious belief is Coptic Christian.",
		"context": {},
	}
}

test_escalate_political_opinion if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's political view noted in account file.",
		"context": {},
	}
}

test_escalate_criminal_record if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer has a criminal conviction on record.",
		"context": {},
	}
}

# ── Escalate: children's data (unique Egypt sensitive category) ───

test_escalate_children_data if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Children's data for this account includes school records.",
		"context": {},
	}
}

test_escalate_minor_profile if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Minor profile created for customer under-18.",
		"context": {},
	}
}

# ── Escalate: cross-border ────────────────────────────────────────

test_escalate_cross_border_output if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Transferring customer data outside Egypt to our cloud provider.",
		"context": {},
	}
}

test_escalate_missing_destination if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"record_count": 10},
		"output": "", "context": {},
	}
}

test_escalate_record_count_500 if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 500},
		"output": "", "context": {},
	}
}

test_escalate_bulk_export if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "bulk_export",
		"params": {}, "output": "", "context": {},
	}
}

# ── Escalate: DPO advice ──────────────────────────────────────────

test_escalate_skip_dpo if {
	count(egypt_pdpl.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "No need for a DPO for this processing.",
		"context": {},
	}
}

# ── Audit: PII access / modification ─────────────────────────────

test_audit_read_user if {
	count(egypt_pdpl.audit) > 0 with input as {
		"action": "read_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_get_customer if {
	count(egypt_pdpl.audit) > 0 with input as {
		"action": "get_customer",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_update_user if {
	count(egypt_pdpl.audit) > 0 with input as {
		"action": "update_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_erase_data if {
	count(egypt_pdpl.audit) > 0 with input as {
		"action": "erase_data",
		"params": {}, "output": "", "context": {},
	}
}

# ── Decision rules ────────────────────────────────────────────────

test_decision_deny_biometric if {
	egypt_pdpl.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Iris scan biometric template confirmed.",
		"context": {},
	}
}

test_decision_deny_national_id if {
	egypt_pdpl.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Egyptian national id: 29901011234562",
		"context": {},
	}
}

test_decision_deny_breach_suppression if {
	egypt_pdpl.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "We should delay breach notification to the PDPC.",
		"context": {},
	}
}

test_decision_escalate_financial_data if {
	egypt_pdpl.decision == "escalate" with input as {
		"action": "respond",
		"params": {},
		"output": "Customer credit history and loan default status retrieved.",
		"context": {},
	}
}

test_decision_escalate_children if {
	egypt_pdpl.decision == "escalate" with input as {
		"action": "respond",
		"params": {},
		"output": "Student record for minor on file.",
		"context": {},
	}
}

test_decision_audit_pii_access if {
	egypt_pdpl.decision == "audit" with input as {
		"action": "lookup_account",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_allow_normal_action if {
	egypt_pdpl.decision == "allow" with input as {
		"action": "get_exchange_rate",
		"params": {}, "output": "USD/EGP rate is 48.5.", "context": {},
	}
}
