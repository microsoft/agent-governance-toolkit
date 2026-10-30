# agt-policies-india - CERT-In Directions 2022 (OPA tests)
package agt_policies_india.certin_test

import data.agt_policies_india.certin
import rego.v1

# An action unrelated to logging or clocks, carrying no parameters at all. This is
# also the shape the result adapters produce: acs-result.rego sets params to {} on
# the output interception and maps params to the tool call's arguments at
# pre_tool_call, so an unguarded parameter rule denies every evaluation.
unrelated := {"action": "read_file", "params": {}}

test_no_denial_for_an_unrelated_action_carrying_no_parameters if {
	denials := certin.deny with input as unrelated
	count(denials) == 0
}

# Direction (iv), in-India log storage. A declared logging action with no region
# must still deny, which is why the object.get default is kept.
test_log_region_denies_a_logging_action_with_no_declared_region if {
	denials := certin.deny with input as {"action": "store_logs_offshore", "params": {}}
	count(denials) == 1
}

test_log_region_silent_when_region_is_india if {
	denials := certin.deny with input as {"action": "store_logs_offshore", "params": {"log_storage_region": "IN"}}
	count(denials) == 0
}

test_log_region_denies_when_region_is_offshore if {
	denials := certin.deny with input as {"action": "store_logs_offshore", "params": {"log_storage_region": "SG"}}
	count(denials) == 1
}

# Direction (iv), 180-day retention. Isolated on a non-logging action so the
# region rule cannot contribute a second denial to this assertion.
test_only_the_retention_rule_fires_for_short_retention if {
	denials := certin.deny with input as {"action": "set_log_retention", "params": {"log_retention_days": 90}}
	count(denials) == 1
}

# Direction (i), NTP clock synchronisation.
test_ntp_silent_for_an_unrelated_action if {
	escalations := certin.escalate with input as unrelated
	count(escalations) == 0
}

test_ntp_escalates_a_clock_action_with_no_declared_sync_state if {
	escalations := certin.escalate with input as {"action": "disable_ntp", "params": {}}
	count(escalations) == 1
}

test_ntp_silent_when_synced if {
	escalations := certin.escalate with input as {"action": "set_external_untrusted_ntp", "params": {"ntp_synced": true}}
	count(escalations) == 0
}

test_ntp_escalates_when_explicitly_not_synced if {
	escalations := certin.escalate with input as {"action": "set_external_untrusted_ntp", "params": {"ntp_synced": false}}
	count(escalations) == 1
}

test_unrelated_action_allows if {
	certin.decision == "allow" with input as unrelated
}

# The paths the runtime actually uses, through the shipped result adapter.
test_benign_output_allowed_through_the_adapter if {
	result := certin.acs_output_result with input as {"snapshot": {"output": {"content": "Here is the quarterly summary you asked for."}}}
	result.decision == "allow"
}

test_benign_tool_call_allowed_through_the_adapter if {
	result := certin.acs_pre_tool_call_result with input as {"snapshot": {"tool_call": {"name": "read_file", "args": {"path": "/tmp/report.csv"}}}}
	result.decision == "allow"
}
