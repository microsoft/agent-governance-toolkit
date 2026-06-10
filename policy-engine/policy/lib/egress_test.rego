# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.egress_test

import data.agt.egress
import rego.v1

input_with_dest(host) := {
	"tool": {"security_labels": ["api.example.com", "*.trusted.com"]},
	"snapshot": {"tool_call": {"args": {"url": host}}},
}

test_host_of_extracts_hostname if {
	egress.host_of("https://api.example.com/path") == "api.example.com"
	egress.host_of("http://api.example.com:8080") == "api.example.com"
	egress.host_of("api.example.com") == "api.example.com"
	egress.host_of("api.example.com/v1/foo") == "api.example.com"
}

test_exact_match_in_allowlist_emits_no_verdict if {
	not egress.deny_egress({}) with input as input_with_dest("https://api.example.com/v1")
}

test_glob_wildcard_matches if {
	not egress.deny_egress({}) with input as input_with_dest("https://web.trusted.com/x")
}

test_off_allowlist_denies if {
	verdict := egress.deny_egress({}) with input as input_with_dest("https://attacker.example.org/x")
	verdict.decision == "deny"
	verdict.reason == "egress_destination_not_allowed"
}

test_explicit_allowlist_overrides_tool_security_labels if {
	verdict := egress.deny_egress({"allowlist": ["allowed.com"]}) with input as input_with_dest("https://api.example.com/v1")
	verdict.decision == "deny"
}

test_destination_paths_override if {
	rules := {"destination_paths": [["annotations", "egress", "destination"]]}
	host_input := {
		"tool": {"security_labels": ["allowed.com"]},
		"annotations": {"egress": {"destination": "https://allowed.com/x"}},
	}
	not egress.deny_egress(rules) with input as host_input
}

test_missing_destination_emits_no_verdict if {
	not egress.deny_egress({}) with input as {"tool": {"security_labels": ["x"]}, "snapshot": {}}
}

test_missing_allowlist_treats_as_empty_and_denies if {
	verdict := egress.deny_egress({}) with input as {"tool": {}, "snapshot": {"tool_call": {"args": {"url": "https://x.com/"}}}}
	verdict.decision == "deny"
}
