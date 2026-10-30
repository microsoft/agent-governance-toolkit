# agt-policies-india - SEBI CSCRF 2024 (OPA tests)
package agt_policies_india.sebi_test

import data.agt_policies_india.sebi
import rego.v1

unrelated := {"action": "read_file", "params": {}}

test_no_denial_for_an_unrelated_action_carrying_no_parameters if {
	denials := sebi.deny with input as unrelated
	count(denials) == 0
}

# A declared audit-log storage action with no region must still deny.
test_log_region_denies_a_storage_action_with_no_declared_region if {
	denials := sebi.deny with input as {"action": "store_audit_log", "params": {}}
	count(denials) == 1
}

test_log_region_silent_when_region_is_india if {
	denials := sebi.deny with input as {"action": "store_audit_log", "params": {"log_storage_region": "IN"}}
	count(denials) == 0
}

test_log_region_denies_when_region_is_offshore if {
	denials := sebi.deny with input as {"action": "configure_audit_log", "params": {"log_storage_region": "SG"}}
	count(denials) == 1
}

# log_storage_actions and log_tamper_actions are disjoint, so a tamper action
# produces exactly one denial rather than two.
test_tamper_action_produces_exactly_one_denial if {
	denials := sebi.deny with input as {"action": "store_audit_log_offshore", "params": {}}
	count(denials) == 1
}

test_unrelated_action_allows if {
	sebi.decision == "allow" with input as unrelated
}

test_benign_output_allowed_through_the_adapter if {
	result := sebi.acs_output_result with input as {"snapshot": {"output": {"content": "Here is the quarterly summary you asked for."}}}
	result.decision == "allow"
}

test_benign_tool_call_allowed_through_the_adapter if {
	result := sebi.acs_pre_tool_call_result with input as {"snapshot": {"tool_call": {"name": "read_file", "args": {"path": "/tmp/report.csv"}}}}
	result.decision == "allow"
}
