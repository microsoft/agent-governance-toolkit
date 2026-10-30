# agt-policies-india - CERT-In Directions 2022 (OPA tests)
package agt_policies_india.certin_test

import data.agt_policies_india.certin
import rego.v1

# An action unrelated to logging, carrying no logging parameters at all.
unrelated := {"action": "read_file", "params": {}}

# These two assert the whole deny set, not one rule, which is deliberate. A rule
# that fires on an absent field cannot be contained: it adds a denial to every
# evaluation, so no other rule in the policy can be tested in isolation while it
# is present. The retention rule below is already written so an absent field
# leaves it undefined; these tests pin that and the containment together.
test_no_denial_for_an_unrelated_action_carrying_no_parameters if {
	denials := certin.deny with input as unrelated
	count(denials) == 0
}

test_only_the_retention_rule_fires_for_short_retention if {
	denials := certin.deny with input as {"action": "set_log_retention", "params": {"log_retention_days": 90}}
	count(denials) == 1
}

# Direction (iv), in-India log storage.
test_log_region_silent_when_region_is_india if {
	denials := certin.deny with input as {"action": "store_logs", "params": {"log_storage_region": "IN"}}
	count(denials) == 0
}

test_log_region_denies_when_region_is_offshore if {
	denials := certin.deny with input as {"action": "store_logs", "params": {"log_storage_region": "SG"}}
	count(denials) == 1
}

# Direction (i), NTP clock synchronisation.
test_ntp_silent_when_field_absent if {
	escalations := certin.escalate with input as unrelated
	count(escalations) == 0
}

test_ntp_silent_when_synced if {
	escalations := certin.escalate with input as {"action": "configure_ntp", "params": {"ntp_synced": true}}
	count(escalations) == 0
}

test_ntp_escalates_when_explicitly_not_synced if {
	escalations := certin.escalate with input as {"action": "configure_ntp", "params": {"ntp_synced": false}}
	count(escalations) == 1
}

# End to end: an unrelated action with no declared logging parameters must allow.
test_unrelated_action_allows if {
	certin.decision == "allow" with input as unrelated
}

# The realistic path, through the shipped result adapter rather than a direct rule
# query. acs-result.rego sets params to {} on the output interception and maps
# params to the tool call's arguments at pre_tool_call, so a rule that fires on an
# absent field denies every evaluation the runtime performs.
test_benign_output_allowed_through_the_adapter if {
	result := certin.acs_output_result with input as {"snapshot": {"output": {"content": "Here is the quarterly summary you asked for."}}}
	result.decision == "allow"
}

test_benign_tool_call_allowed_through_the_adapter if {
	result := certin.acs_pre_tool_call_result with input as {"snapshot": {"tool_call": {"name": "read_file", "args": {"path": "/tmp/report.csv"}}}}
	result.decision == "allow"
}
