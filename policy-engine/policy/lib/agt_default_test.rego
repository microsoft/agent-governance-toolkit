# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.defaults_test

import data.agt.defaults
import data.agt.patterns
import rego.v1

base_snapshot := {
	"intervention_point": "pre_tool_call",
	"snapshot": {"envelope": {"budgets": {"tool_call_count": 0, "token_count": 0, "elapsed_seconds": 0, "cost_usd": 0}}},
	"annotations": {},
	"tool": {},
	"policy_target": {"value": "benign text"},
}

test_default_allows_with_empty_config if {
	defaults.verdict == {"decision": "allow"} with input as base_snapshot
		with data.agt.defaults.config as {}
}

test_budget_exceeded_denies if {
	verdict := defaults.verdict with input as object.union(base_snapshot, {"snapshot": {"envelope": {"budgets": {"tool_call_count": 20, "token_count": 0, "elapsed_seconds": 0, "cost_usd": 0}}}})
		with data.agt.defaults.config as {"budgets": {"tool_call_count": 10, "token_count": 99999, "elapsed_seconds": 9999, "cost_usd": 9999}}
	verdict.decision == "deny"
	verdict.reason == "budget_tool_calls_exceeded"
}

test_malformed_budget_counter_denies if {
	verdict := defaults.verdict with input as object.union(base_snapshot, {"snapshot": {"envelope": {"budgets": {"tool_call_count": 0, "token_count": "999999", "elapsed_seconds": 0, "cost_usd": 0}}}})
		with data.agt.defaults.config as {"budgets": {"tool_call_count": 99999, "token_count": 1, "elapsed_seconds": 9999, "cost_usd": 9999}}
	verdict.decision == "deny"
	verdict.reason == "budget_counter_invalid"
}

test_confidence_low_denies if {
	pi := object.union(base_snapshot, {"annotations": {"confidence": {"score": 0.2}}})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"confidence": {"min_score": 0.5}}
	verdict.decision == "deny"
	verdict.reason == "confidence_below_threshold"
}

test_content_hash_mismatch_denies if {
	pi := object.union(base_snapshot, {
		"tool": {"content_hash": "sha256:abc"},
		"snapshot": {
			"envelope": base_snapshot.snapshot.envelope,
			"tool_call": {"content_hash": "sha256:zzz"},
		},
	})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"content_hash": {"enforce": true}}
	verdict.decision == "deny"
	verdict.reason == "tool_content_hash_mismatch"
}

test_egress_denies if {
	pi := object.union(base_snapshot, {
		"tool": {"security_labels": ["allowed.com"]},
		"snapshot": {
			"envelope": base_snapshot.snapshot.envelope,
			"tool_call": {"args": {"url": "https://attacker.com/x"}},
		},
	})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"egress": {}}
	verdict.decision == "deny"
	verdict.reason == "egress_destination_not_allowed"
}

test_pattern_denies if {
	pi := object.union(base_snapshot, {"policy_target": {"value": "ssn 111-22-3333"}})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"patterns": {"patterns": [patterns.pii_ssn], "reason": "pii_detected"}}
	verdict.decision == "deny"
	verdict.reason == "pii_detected"
}

test_redact_transforms if {
	pi := object.union(base_snapshot, {"policy_target": {"value": "ssn 111-22-3333"}})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"redact": {"patterns": [patterns.pii_ssn]}}
	verdict.decision == "transform"
	verdict.transform.path == "$policy_target"
	verdict.transform.value == "ssn [REDACTED]"
}

test_drift_warns if {
	pi := object.union(base_snapshot, {"annotations": {"drift_score": 0.8}})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"drift": {"warn_threshold": 0.5}}
	verdict.decision == "warn"
	verdict.reason == "drift_detected"
}

test_approval_escalates if {
	verdict := defaults.verdict with input as base_snapshot
		with data.agt.defaults.config as {"approval": {"required": true, "approvers": ["alice"]}}
	verdict.decision == "escalate"
	verdict.reason == "approval_required"
}

test_ifc_violation_denies_at_input_intervention_point if {
	pi := {
		"intervention_point": "input",
		"snapshot": {
			"envelope": base_snapshot.snapshot.envelope,
			"input": {"ifc": {"source_labels": ["secret"]}},
		},
		"annotations": {},
		"tool": {},
		"policy_target": {"value": ""},
	}
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {"ifc": {"sink_clearance": "internal"}}
	verdict.decision == "deny"
	verdict.reason == "ifc_clearance_violation"
}

test_severity_ranking_deny_beats_transform if {
	pi := object.union(base_snapshot, {"policy_target": {"value": "ssn 111-22-3333"}, "annotations": {"confidence": {"score": 0.1}}})
	verdict := defaults.verdict with input as pi
		with data.agt.defaults.config as {
			"confidence": {"min_score": 0.5},
			"redact": {"patterns": [patterns.pii_ssn]},
		}
	verdict.decision == "deny"
	verdict.reason == "confidence_below_threshold"
}

test_missing_config_falls_through_to_allow if {
	defaults.verdict == {"decision": "allow"} with input as base_snapshot
}
