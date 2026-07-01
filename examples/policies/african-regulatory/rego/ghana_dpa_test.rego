# agt-policies-africa
# Tests for Ghana Data Protection Act 2012 (Act 843) policy
# Run: opa test policies/rego/ -v

package agt_policies_africa.ghana_dpa_test

import data.agt_policies_africa.ghana_dpa
import rego.v1

# ── Deny: breach suppression ──────────────────────────────────────

test_deny_breach_suppression if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Don't report this incident to the DPC.",
		"context": {},
	}
}

test_deny_suppress_notification if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We must suppress notification to the DPC about this breach.",
		"context": {},
	}
}

# ── Deny: biometric data ──────────────────────────────────────────

test_deny_fingerprint_in_output if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint template extracted and stored.",
		"context": {},
	}
}

test_deny_facial_recognition_in_output if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Facial recognition confirmed customer identity.",
		"context": {},
	}
}

# ── Deny: Ghana Card national ID ──────────────────────────────────

test_deny_ghana_card_in_output if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Ghana Card: GHA-123456789-0",
		"context": {},
	}
}

test_deny_ghana_card_no_hyphen if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "National ID GHA1234567890",
		"context": {},
	}
}

# ── Deny: cross-border to non-permitted region ────────────────────

test_deny_us_east_cross_border if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 5},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_eu_cross_border if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "sync_to_remote",
		"params": {"destination_region": "eu-west-1", "destination_country": "IE", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Deny: large record export ─────────────────────────────────────

test_deny_record_count_1001 if {
	count(ghana_dpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 1001},
		"output": "", "context": {},
	}
}

# ── Allow: permitted regions ──────────────────────────────────────

test_allow_ghana_region if {
	ghana_dpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "ghana", "destination_country": "GH", "record_count": 5},
		"output": "", "context": {},
	}
}

test_allow_af_south_1 if {
	ghana_dpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "af-south-1", "destination_country": "GH", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Escalate: special personal data ──────────────────────────────

test_escalate_health_data if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer medical record shows HIV positive status.",
		"context": {},
	}
}

test_escalate_ethnic_origin if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's ethnic origin is noted in the file.",
		"context": {},
	}
}

test_escalate_religious_belief if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's religious belief is Christian.",
		"context": {},
	}
}

test_escalate_criminal_record if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer has a criminal conviction on record.",
		"context": {},
	}
}

test_escalate_political_opinion if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's political opinion is NDC supporter.",
		"context": {},
	}
}

# ── Escalate: cross-border ────────────────────────────────────────

test_escalate_cross_border_output if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Transferring customer data outside Ghana to our cloud backup.",
		"context": {},
	}
}

test_escalate_missing_destination if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"record_count": 10},
		"output": "", "context": {},
	}
}

test_escalate_record_count_500 if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 500},
		"output": "", "context": {},
	}
}

test_escalate_bulk_export if {
	count(ghana_dpa.escalate) > 0 with input as {
		"action": "bulk_export",
		"params": {}, "output": "", "context": {},
	}
}

# ── Audit: PII access / modification ─────────────────────────────

test_audit_read_user if {
	count(ghana_dpa.audit) > 0 with input as {
		"action": "read_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_update_user if {
	count(ghana_dpa.audit) > 0 with input as {
		"action": "update_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_erase_data if {
	count(ghana_dpa.audit) > 0 with input as {
		"action": "erase_data",
		"params": {}, "output": "", "context": {},
	}
}

# ── Decision rules ────────────────────────────────────────────────

test_decision_deny_biometric if {
	ghana_dpa.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Voice print biometric confirmed.",
		"context": {},
	}
}

test_decision_deny_ghana_card if {
	ghana_dpa.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Ghana Card number: GHA-987654321-3",
		"context": {},
	}
}

test_decision_escalate_health if {
	ghana_dpa.decision == "escalate" with input as {
		"action": "respond",
		"params": {},
		"output": "Customer disability status is noted in their medical record.",
		"context": {},
	}
}

test_decision_audit_pii_access if {
	ghana_dpa.decision == "audit" with input as {
		"action": "get_customer",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_allow_normal_action if {
	ghana_dpa.decision == "allow" with input as {
		"action": "get_exchange_rate",
		"params": {}, "output": "USD/GHS rate is 15.2.", "context": {},
	}
}
