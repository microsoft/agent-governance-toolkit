# agt-policies-india - SEBI CSCRF 2024 (OPA tests)
package agt_policies_india.sebi_test

import data.agt_policies_india.sebi
import rego.v1

unrelated := {"action": "read_file", "params": {}}

test_log_region_silent_when_field_absent if {
	denials := sebi.deny with input as unrelated
	count(denials) == 0
}

test_log_region_silent_when_region_is_india if {
	denials := sebi.deny with input as {"action": "store_audit_log", "params": {"log_storage_region": "IN"}}
	count(denials) == 0
}

test_log_region_denies_when_region_is_offshore if {
	denials := sebi.deny with input as {"action": "store_audit_log", "params": {"log_storage_region": "SG"}}
	count(denials) == 1
}

test_unrelated_action_allows if {
	sebi.decision == "allow" with input as unrelated
}

# The realistic path, through the shipped result adapter rather than a direct rule
# query. acs-result.rego sets params to {} on the output interception and maps
# params to the tool call's arguments at pre_tool_call, so a rule that fires on an
# absent field denies every evaluation the runtime performs.
test_benign_output_allowed_through_the_adapter if {
	result := sebi.acs_output_result with input as {"snapshot": {"output": {"content": "Here is the quarterly summary you asked for."}}}
	result.decision == "allow"
}

test_benign_tool_call_allowed_through_the_adapter if {
	result := sebi.acs_pre_tool_call_result with input as {"snapshot": {"tool_call": {"name": "read_file", "args": {"path": "/tmp/report.csv"}}}}
	result.decision == "allow"
}
