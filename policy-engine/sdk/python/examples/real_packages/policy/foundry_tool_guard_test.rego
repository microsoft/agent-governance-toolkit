# Unit tests for the Foundry tool-guard policy. Run with `opa test policy`.
package agent_control_specification.foundry_tool_guard_test

import rego.v1

import data.agent_control_specification.foundry_tool_guard

# A safe judge label lets the tool call proceed.
test_pre_tool_call_allows_safe if {
	foundry_tool_guard.verdict.decision == "allow" with input as {
		"intervention_point": "pre_tool_call",
		"annotations": {"intent_judge": {"label": "safe"}},
	}
}

# A destructive label denies before the tool runs.
test_pre_tool_call_denies_destructive if {
	verdict := foundry_tool_guard.verdict with input as {
		"intervention_point": "pre_tool_call",
		"annotations": {"intent_judge": {"label": "destructive"}},
	}
	verdict.decision == "deny"
	verdict.reason == "destructive_tool_argument"
}

# A missing or unusable label fails closed to deny.
test_pre_tool_call_fails_closed_without_label if {
	verdict := foundry_tool_guard.verdict with input as {
		"intervention_point": "pre_tool_call",
		"annotations": {},
	}
	verdict.decision == "deny"
	verdict.reason == "intent_judge_unavailable"
}

# The label comparison is exact, mirroring the Python policy this bundle
# replaced: an unexpected casing such as "Safe" denies.
test_pre_tool_call_denies_unexpected_casing if {
	verdict := foundry_tool_guard.verdict with input as {
		"intervention_point": "pre_tool_call",
		"annotations": {"intent_judge": {"label": "Safe"}},
	}
	verdict.decision == "deny"
	verdict.reason == "destructive_tool_argument"
}

# A seam with no matching rule falls through to the generic verdict, which
# fails closed instead of silently allowing.
test_unbound_intervention_point_fails_closed if {
	verdict := foundry_tool_guard.verdict with input as {
		"intervention_point": "pre_llm_call",
		"annotations": {},
	}
	verdict.decision == "deny"
	verdict.reason == "unbound_intervention_point"
}

# The post_tool_call seam binds no judge here, so it allows.
test_post_tool_call_allows if {
	foundry_tool_guard.verdict.decision == "allow" with input as {
		"intervention_point": "post_tool_call",
		"annotations": {},
	}
}
