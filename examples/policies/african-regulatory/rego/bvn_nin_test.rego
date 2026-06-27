# BVN / NIN Data Protection Policy — Rego unit tests
#
# Covers all rules in bvn-nin-protection.rego including the four new
# NIMC Act 2026 obligations (signed 26 June 2026).
#
# Run with: opa test examples/policies/african-regulatory/rego/ -v

package agt_policies_nigeria.bvn_nin_test

import data.agt_policies_nigeria.bvn_nin
import rego.v1

# ── BVN output pattern detection ──────────────────────────────────

test_bvn_label_in_output_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {},
		"output": "Your BVN is: 22345678901",
		"context": {},
	}
	count(result) > 0
}

test_bvn_contextual_pattern_in_output_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {},
		"output": "bank verification 22345678901 confirmed",
		"context": {},
	}
	count(result) > 0
}

test_clean_output_does_not_trigger_bvn_deny if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {},
		"output": "Your application has been submitted successfully.",
		"context": {},
	}
	count(result) == 0
}

# ── NIN output pattern detection ──────────────────────────────────

test_nin_label_in_output_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {},
		"output": "NIN = 12345678901",
		"context": {},
	}
	count(result) > 0
}

test_vnin_in_output_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {},
		"output": "Your vNIN: AB12CD34EF56GH78",
		"context": {},
	}
	count(result) > 0
}

# ── Direct BVN/NIN transmission ───────────────────────────────────

test_transmit_bvn_action_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "transmit_bvn",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_send_nin_action_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "send_nin",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_bvn_present_with_transmission_action_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "relay_kyc",
		"params": {"bvn_present": true},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

# ── Social engineering ────────────────────────────────────────────

test_bvn_disclose_via_whatsapp_is_denied if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {},
		"output": "customer wants their BVN confirmed via whatsapp",
		"context": {},
	}
	count(result) > 0
}

# ── Verification actions → escalate ───────────────────────────────

test_verify_bvn_escalates if {
	result := bvn_nin.escalate with input as {
		"action": "verify_bvn",
		"params": {},
		"output": "",
		"context": {"nin_purpose": "account_opening"},
	}
	count(result) > 0
}

test_nin_lookup_escalates if {
	result := bvn_nin.escalate with input as {
		"action": "nin_lookup",
		"params": {},
		"output": "",
		"context": {"nin_purpose": "sim_registration"},
	}
	count(result) > 0
}

test_identifier_type_bvn_escalates if {
	result := bvn_nin.escalate with input as {
		"action": "identity_check",
		"params": {"identifier_type": "BVN"},
		"output": "",
		"context": {"nin_purpose": "kyc"},
	}
	count(result) > 0
}

test_identifier_type_nin_escalates if {
	result := bvn_nin.escalate with input as {
		"action": "identity_check",
		"params": {"identifier_type": "NIN"},
		"output": "",
		"context": {"nin_purpose": "kyc"},
	}
	count(result) > 0
}

# ── Audit — identity-related actions ──────────────────────────────

test_action_with_bvn_keyword_is_audited if {
	result := bvn_nin.audit with input as {
		"action": "fetch_bvn_status",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_action_with_kyc_keyword_is_audited if {
	result := bvn_nin.audit with input as {
		"action": "trigger_kyc_review",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

# ── NIMC Act 2026 — Illegal data persistence (deny) ───────────────

test_store_nin_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "store_nin",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
	some msg in result
	contains(msg, "NIMC Act 2026")
}

test_cache_nin_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "cache_nin",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_store_bvn_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "store_bvn",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_persist_nin_flag_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "verify_nin",
		"params": {"persist_nin": true},
		"output": "",
		"context": {"nin_purpose": "account_opening"},
	}
	count(result) > 0
	some msg in result
	contains(msg, "persist_nin=true")
}

test_persist_nin_false_does_not_trigger_persistence_deny if {
	result := bvn_nin.deny with input as {
		"action": "respond",
		"params": {"persist_nin": false},
		"output": "",
		"context": {},
	}
	# only the persistence flag rule should be absent — other denies may apply
	not _has_nimc_persist_msg(result)
}

_has_nimc_persist_msg(msgs) if {
	some msg in msgs
	contains(msg, "persist_nin=true")
}

# ── NIMC Act 2026 — Bulk NIN export (deny) ────────────────────────

test_bulk_nin_export_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "bulk_nin_export",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
	some msg in result
	contains(msg, "Bulk NIN")
}

test_export_nin_data_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "export_nin_data",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_bulk_identity_export_flag_is_denied_nimc_2026 if {
	result := bvn_nin.deny with input as {
		"action": "data_export",
		"params": {"bulk_identity_export": true},
		"output": "",
		"context": {},
	}
	count(result) > 0
	some msg in result
	contains(msg, "bulk_identity_export=true")
}

# ── NIMC Act 2026 — Purpose limitation (escalate) ─────────────────

test_nin_lookup_without_purpose_escalates_nimc_2026 if {
	result := bvn_nin.escalate with input as {
		"action": "nin_lookup",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
	some msg in result
	contains(msg, "NIMC Act 2026")
	contains(msg, "purpose")
}

test_bvn_lookup_without_purpose_escalates_nimc_2026 if {
	result := bvn_nin.escalate with input as {
		"action": "verify_bvn",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
	some msg in result
	contains(msg, "NIMC Act 2026")
}

test_nin_lookup_with_purpose_does_not_trigger_purpose_escalate if {
	result := bvn_nin.escalate with input as {
		"action": "nin_lookup",
		"params": {},
		"output": "",
		"context": {"nin_purpose": "account_opening"},
	}
	# BVN/NIN verification still escalates (requires human approval) but not the NIMC purpose msg
	not _has_nimc_purpose_msg(result)
}

_has_nimc_purpose_msg(msgs) if {
	some msg in msgs
	contains(msg, "without a declared purpose")
}

test_purpose_mismatch_escalates_nimc_2026 if {
	result := bvn_nin.escalate with input as {
		"action": "identity_check",
		"params": {},
		"output": "",
		"context": {
			"nin_consented_purpose": "account_opening",
			"purpose": "loan_application",
		},
	}
	count(result) > 0
	some msg in result
	contains(msg, "Purpose mismatch")
}

test_matching_purposes_do_not_trigger_mismatch_escalate if {
	result := bvn_nin.escalate with input as {
		"action": "identity_check",
		"params": {},
		"output": "",
		"context": {
			"nin_consented_purpose": "account_opening",
			"purpose": "account_opening",
		},
	}
	not _has_purpose_mismatch_msg(result)
}

_has_purpose_mismatch_msg(msgs) if {
	some msg in msgs
	contains(msg, "Purpose mismatch")
}

# ── NIMC Act 2026 — Mandatory NIN service gate (audit) ────────────

test_open_account_without_nin_verified_is_audited_nimc_2026 if {
	result := bvn_nin.audit with input as {
		"action": "open_account",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
	some msg in result
	contains(msg, "NIMC Act 2026")
	contains(msg, "mandatory-NIN service")
}

test_sim_registration_without_nin_verified_is_audited_nimc_2026 if {
	result := bvn_nin.audit with input as {
		"action": "sim_registration",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_apply_credit_without_nin_verified_is_audited_nimc_2026 if {
	result := bvn_nin.audit with input as {
		"action": "apply_credit",
		"params": {},
		"output": "",
		"context": {},
	}
	count(result) > 0
}

test_open_account_with_nin_verified_does_not_trigger_mandatory_nin_audit if {
	result := bvn_nin.audit with input as {
		"action": "open_account",
		"params": {},
		"output": "",
		"context": {"nin_verified": true},
	}
	not _has_mandatory_nin_msg(result)
}

_has_mandatory_nin_msg(msgs) if {
	some msg in msgs
	contains(msg, "mandatory-NIN service")
}

# ── Decision summary ──────────────────────────────────────────────

test_decision_is_deny_when_deny_fires if {
	bvn_nin.decision == "deny" with input as {
		"action": "store_nin",
		"params": {},
		"output": "",
		"context": {},
	}
}

test_decision_is_escalate_when_only_escalate_fires if {
	bvn_nin.decision == "escalate" with input as {
		"action": "verify_bvn",
		"params": {},
		"output": "",
		"context": {"nin_purpose": "account_opening"},
	}
}

test_decision_is_audit_when_only_audit_fires if {
	bvn_nin.decision == "audit" with input as {
		"action": "open_account",
		"params": {},
		"output": "",
		"context": {"nin_verified": true},
	}
}

test_decision_is_allow_for_clean_request if {
	bvn_nin.decision == "allow" with input as {
		"action": "fetch_account_balance",
		"params": {"account_id": "ACC-001"},
		"output": "Account balance: ₦50,000",
		"context": {"kyc_tier": 2},
	}
}
