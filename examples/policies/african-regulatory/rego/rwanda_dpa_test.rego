# agt-policies-africa
# Tests for Rwanda Law No. 058/2021 Personal Data Protection policy
# Run: opa test policies/rego/ -v

package agt_policies_africa.rwanda_dpa_test

import data.agt_policies_africa.rwanda_dpa
import rego.v1

# ── Deny: breach suppression ──────────────────────────────────────

test_deny_breach_suppression if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Don't report this incident to the NCSA.",
		"context": {},
	}
}

test_deny_suppress_notification if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "We must suppress notification to the authorities about this breach.",
		"context": {},
	}
}

# ── Deny: biometric data ──────────────────────────────────────────

test_deny_fingerprint_in_output if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer fingerprint template extracted and stored.",
		"context": {},
	}
}

test_deny_iris_scan_in_output if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Iris scan biometric template confirmed for the customer.",
		"context": {},
	}
}

# ── Deny: Rwanda National ID (NIDA 16-digit) ──────────────────────

test_deny_rwanda_nid_labeled if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Rwanda National ID: 1199880012345678",
		"context": {},
	}
}

test_deny_nida_number_labeled if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "NIDA ID: 1200090098765432",
		"context": {},
	}
}

# ── Deny: cross-border to non-permitted region ────────────────────

test_deny_us_east_cross_border if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 5},
		"output": "", "context": {"consent_documented": false},
	}
}

test_deny_eu_west_cross_border if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "sync_to_remote",
		"params": {"destination_region": "eu-west-2", "destination_country": "GB", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Deny: large record export ─────────────────────────────────────

test_deny_record_count_1001 if {
	count(rwanda_dpa.deny) > 0 with input as {
		"action": "export_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 1001},
		"output": "", "context": {},
	}
}

# ── Allow: permitted regions ──────────────────────────────────────

test_allow_rwanda_region if {
	rwanda_dpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "rwanda", "destination_country": "RW", "record_count": 5},
		"output": "", "context": {},
	}
}

test_allow_af_east_1 if {
	rwanda_dpa.decision == "allow" with input as {
		"action": "export_data",
		"params": {"destination_region": "af-east-1", "destination_country": "RW", "record_count": 5},
		"output": "", "context": {},
	}
}

# ── Escalate: health / sensitive data ────────────────────────────

test_escalate_health_data if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer health condition shows malaria treatment history.",
		"context": {},
	}
}

test_escalate_hiv_status if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer HIV status is positive — noted in medical record.",
		"context": {},
	}
}

test_escalate_ethnic_origin if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's ethnic origin is noted in their profile.",
		"context": {},
	}
}

test_escalate_political_opinion if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Customer's political opinion is noted in account file.",
		"context": {},
	}
}

test_escalate_religious_belief if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Religious belief: Seventh-day Adventist.",
		"context": {},
	}
}

# ── Escalate: automated decision-making (Art. 21) ─────────────────

test_escalate_auto_approve if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "auto_approve",
		"params": {}, "output": "", "context": {},
	}
}

test_escalate_auto_reject if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "auto_reject",
		"params": {}, "output": "", "context": {},
	}
}

test_escalate_algorithmic_decision if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "algorithmic_decision",
		"params": {}, "output": "", "context": {},
	}
}

test_escalate_auto_score if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "auto_score",
		"params": {}, "output": "", "context": {},
	}
}

# ── Escalate: cross-border ────────────────────────────────────────

test_escalate_cross_border_output if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "respond",
		"params": {},
		"output": "Transferring customer data outside Rwanda to our cloud backup.",
		"context": {},
	}
}

test_escalate_missing_destination if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "export_data",
		"params": {"record_count": 10},
		"output": "", "context": {},
	}
}

test_escalate_record_count_500 if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "relay_data",
		"params": {"destination_region": "us-east-1", "destination_country": "US", "record_count": 500},
		"output": "", "context": {},
	}
}

test_escalate_bulk_export if {
	count(rwanda_dpa.escalate) > 0 with input as {
		"action": "bulk_export",
		"params": {}, "output": "", "context": {},
	}
}

# ── Audit: PII access / modification ─────────────────────────────

test_audit_read_user if {
	count(rwanda_dpa.audit) > 0 with input as {
		"action": "read_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_get_customer if {
	count(rwanda_dpa.audit) > 0 with input as {
		"action": "get_customer",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_update_user if {
	count(rwanda_dpa.audit) > 0 with input as {
		"action": "update_user",
		"params": {}, "output": "", "context": {},
	}
}

test_audit_erase_data if {
	count(rwanda_dpa.audit) > 0 with input as {
		"action": "erase_data",
		"params": {}, "output": "", "context": {},
	}
}

# ── Decision rules ────────────────────────────────────────────────

test_decision_deny_breach_suppression if {
	rwanda_dpa.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "We should delay breach notification to the NCSA.",
		"context": {},
	}
}

test_decision_deny_biometric if {
	rwanda_dpa.decision == "deny" with input as {
		"action": "respond",
		"params": {},
		"output": "Voice print biometric template confirmed.",
		"context": {},
	}
}

test_decision_escalate_auto_credit if {
	rwanda_dpa.decision == "escalate" with input as {
		"action": "automated_credit",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_escalate_health if {
	rwanda_dpa.decision == "escalate" with input as {
		"action": "respond",
		"params": {},
		"output": "Customer mental health condition is noted.",
		"context": {},
	}
}

test_decision_audit_lookup_account if {
	rwanda_dpa.decision == "audit" with input as {
		"action": "lookup_account",
		"params": {}, "output": "", "context": {},
	}
}

test_decision_allow_normal_action if {
	rwanda_dpa.decision == "allow" with input as {
		"action": "get_exchange_rate",
		"params": {}, "output": "USD/RWF rate is 1350.", "context": {},
	}
}
