# agt-policies-africa
# Tests for Mauritius Data Protection Act 2017 policy
# Run: opa test policies/rego/ -v

package agt_policies_africa.mauritius_dpa_test

import data.agt_policies_africa.mauritius_dpa
import rego.v1

# ── Deny: breach suppression ──────────────────────────────────────

test_deny_breach_suppression if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We should delay breach notification to the Commissioner.",
		"context": {},
	}
}

test_deny_suppress_incident_notification if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Don't disclose this breach to anyone right now.",
		"context": {},
	}
}

# ── Deny: biometric data ──────────────────────────────────────────

test_deny_fingerprint_in_output if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint template extracted and stored.",
		"context": {},
	}
}

test_deny_facial_recognition_in_output if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Facial recognition hash confirmed customer identity.",
		"context": {},
	}
}

# ── Deny: registration bypass ─────────────────────────────────────

test_deny_registration_bypass if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "There is no need to register with the Commissioner for a small startup.",
		"context": {},
	}
}

# ── Deny: Mauritius National ID Card (NIC) ────────────────────────
# NIC format: 1 letter + 13 digits (14 chars total), e.g. A1234567890123

test_deny_mauritius_nic_in_output if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer NIC No: A1234567890123 — account verified.",
		"context": {},
	}
}

test_deny_mauritius_national_identity_card if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Mauritius National ID: B9876543012345",
		"context": {},
	}
}

test_deny_mauritius_nic_14_char_format if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Please confirm NIC number: C0000000000001 before proceeding.",
		"context": {},
	}
}

test_allow_mauritius_nic_short_format_no_match if {
	count(mauritius_dpa.deny) == 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Reference code: A123456 confirmed.",
		"context": {},
	}
}

# ── Deny: cross-border to non-permitted region ────────────────────

test_deny_us_east_cross_border if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 5},
		"output": "",
		"context": {"consent_documented": false},
	}
}

test_deny_eu_west_cross_border if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "send_to_external",
		"params": {"destination_region": "eu-west-1", "destination_country": "EU", "record_count": 10},
		"output": "",
		"context": {"consent_documented": false},
	}
}

# ── Deny: large record export ─────────────────────────────────────

test_deny_large_record_export if {
	count(mauritius_dpa.deny) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "ap-southeast-1", "record_count": 5000},
		"output": "",
		"context": {},
	}
}

# ── Allow: permitted regions ──────────────────────────────────────

test_allow_permitted_region_mauritius if {
	mauritius_dpa.decision == "allow" with input as {
		"action": "respond",
		"params": {"destination_region": "mauritius", "record_count": 50},
		"output": "Transaction completed. Data stays in Mauritius.",
		"context": {},
	}
}

test_allow_permitted_region_af_south_1 if {
	mauritius_dpa.decision == "allow" with input as {
		"action": "respond",
		"params": {"destination_region": "af-south-1"},
		"output": "Backup complete.",
		"context": {"consent_documented": true},
	}
}

# ── Escalate: health / genetic / mental health data ───────────────

test_escalate_health_condition if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "User's health condition is diabetes, documented in their medical record.",
		"context": {},
	}
}

test_escalate_hiv_status if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Patient HIV test result recorded.",
		"context": {},
	}
}

test_escalate_genetic_data if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Genetic test results for patient A have been loaded into the system.",
		"context": {},
	}
}

test_escalate_mental_health if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Psychological assessment report indicates mild depression.",
		"context": {},
	}
}

# ── Escalate: special category data ──────────────────────────────

test_escalate_racial_origin if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer racial origin has been noted in their profile.",
		"context": {},
	}
}

test_escalate_ethnic_origin if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Data includes ethnic origin information from the application form.",
		"context": {},
	}
}

test_escalate_political_opinion if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Political opinion of the applicant was recorded during onboarding.",
		"context": {},
	}
}

test_escalate_religious_belief if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Religious belief: Hindu — captured at registration.",
		"context": {},
	}
}

test_escalate_trade_union_membership if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Trade union membership flagged in background check.",
		"context": {},
	}
}

test_escalate_sexual_orientation if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "The data set includes sexual orientation preferences.",
		"context": {},
	}
}

test_escalate_criminal_proceedings if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Criminal proceedings against this individual are pending.",
		"context": {},
	}
}

# ── Escalate: DPO bypass ─────────────────────────────────────────

test_escalate_dpo_bypass if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "There is no need for a DPO at your company size.",
		"context": {},
	}
}

# ── Escalate: cross-border language in output ─────────────────────

test_escalate_cross_border_language if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We are transferring this data outside Mauritius to our EU servers.",
		"context": {},
	}
}

# ── Escalate: cross-border action missing destination ─────────────

test_escalate_cross_border_missing_destination if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "send_to_external",
		"params": {"record_count": 200},
		"output": "",
		"context": {},
	}
}

# ── Escalate: moderate record export (100–1000) ───────────────────

test_escalate_moderate_record_export if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "af-east-1", "destination_country": "KE", "record_count": 500},
		"output": "",
		"context": {"consent_documented": true},
	}
}

# ── Escalate: bulk export actions ─────────────────────────────────

test_escalate_bulk_export if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "bulk_export",
		"params": {},
		"output": "Starting bulk export of all customer records.",
		"context": {},
	}
}

test_escalate_dump_database if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "dump_database",
		"params": {},
		"output": "",
		"context": {},
	}
}

# ── Escalate: automated decision-making ──────────────────────────

test_escalate_auto_approve if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "auto_approve",
		"params": {},
		"output": "Loan application auto-approved based on credit profile.",
		"context": {},
	}
}

test_escalate_auto_reject if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "auto_reject",
		"params": {},
		"output": "Account opening auto-rejected by scoring model.",
		"context": {},
	}
}

test_escalate_algorithmic_decision if {
	count(mauritius_dpa.escalate) > 0 with input as {
		"action": "algorithmic_decision",
		"params": {},
		"output": "Risk score computed. Algorithmic decision applied.",
		"context": {},
	}
}

# ── Audit: personal data access ──────────────────────────────────

test_audit_read_user if {
	count(mauritius_dpa.audit) > 0 with input as {
		"action": "read_user",
		"params": {},
		"output": "User profile retrieved.",
		"context": {},
	}
}

test_audit_get_customer if {
	count(mauritius_dpa.audit) > 0 with input as {
		"action": "get_customer",
		"params": {},
		"output": "Customer record fetched.",
		"context": {},
	}
}

test_audit_update_user if {
	count(mauritius_dpa.audit) > 0 with input as {
		"action": "update_user",
		"params": {},
		"output": "User profile updated.",
		"context": {},
	}
}

test_audit_erase_data if {
	count(mauritius_dpa.audit) > 0 with input as {
		"action": "erase_data",
		"params": {},
		"output": "Data erasure request processed.",
		"context": {},
	}
}

# ── Decision: priority enforcement ───────────────────────────────

test_decision_deny_biometric if {
	mauritius_dpa.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Biometric template: iris scan ABC confirmed.",
		"context": {},
	}
}

test_decision_escalate_health if {
	mauritius_dpa.decision == "escalate" with input as {
		"action": "respond",
		"params": {},
		"output": "Patient clinical data shows elevated risk markers.",
		"context": {},
	}
}

test_decision_allow_clean if {
	mauritius_dpa.decision == "allow" with input as {
		"action": "respond",
		"params": {},
		"output": "Payment processed successfully. Reference: TXN-20260619-001.",
		"context": {},
	}
}
