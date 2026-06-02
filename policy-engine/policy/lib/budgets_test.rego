# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.budgets_test

import data.agt.budgets
import rego.v1

snapshot_with(values) := {"snapshot": {"envelope": {"budgets": values}}}

test_tool_call_count_reads_envelope if {
	budgets.tool_call_count == 7 with input as snapshot_with({"tool_call_count": 7})
}

test_token_count_reads_envelope if {
	budgets.token_count == 1024 with input as snapshot_with({"token_count": 1024})
}

test_missing_budgets_defaults_to_zero if {
	budgets.tool_call_count == 0 with input as {"snapshot": {"envelope": {}}}
	budgets.token_count == 0 with input as {"snapshot": {"envelope": {}}}
	budgets.elapsed_seconds == 0 with input as {"snapshot": {"envelope": {}}}
	budgets.cost_usd == 0 with input as {"snapshot": {"envelope": {}}}
}

test_present_malformed_counter_is_not_coerced_to_zero if {
	not budgets.token_count with input as snapshot_with({"token_count": "999999"})
	budgets.malformed_budget_counter("token_count") with input as snapshot_with({"token_count": "999999"})
	budgets.malformed_budget_counter("elapsed_seconds") with input as snapshot_with({"elapsed_seconds": null})
}

test_max_tool_calls_under_limit_does_not_match if {
	not budgets.max_tool_calls_exceeded(10) with input as snapshot_with({"tool_call_count": 3})
}

test_max_tool_calls_at_limit_matches if {
	budgets.max_tool_calls_exceeded(10) with input as snapshot_with({"tool_call_count": 10})
}

test_max_tokens_exceeded_matches if {
	budgets.max_tokens_exceeded(1000) with input as snapshot_with({"token_count": 1200})
}

test_timeout_exceeded_matches if {
	budgets.timeout_exceeded(60) with input as snapshot_with({"elapsed_seconds": 90.5})
}

test_max_cost_exceeded_matches if {
	budgets.max_cost_exceeded(1.5) with input as snapshot_with({"cost_usd": 2.0})
}

test_deny_if_budget_exceeded_returns_no_verdict_when_under_limits if {
	not budgets.deny_if_budget_exceeded({
		"tool_call_count": 100,
		"token_count": 10000,
		"elapsed_seconds": 600,
		"cost_usd": 5,
	}) with input as snapshot_with({
		"tool_call_count": 1,
		"token_count": 50,
		"elapsed_seconds": 1.5,
		"cost_usd": 0.01,
	})
}

test_deny_if_budget_exceeded_malformed_counter if {
	verdict := budgets.deny_if_budget_exceeded({"tool_call_count": 9999, "token_count": 1, "elapsed_seconds": 9999, "cost_usd": 9999}) with input as snapshot_with({"token_count": "999999"})
	verdict.decision == "deny"
	verdict.reason == "budget_counter_invalid"
}

test_deny_if_budget_exceeded_tool_calls if {
	verdict := budgets.deny_if_budget_exceeded({"tool_call_count": 5, "token_count": 99999, "elapsed_seconds": 9999, "cost_usd": 9999}) with input as snapshot_with({"tool_call_count": 5})
	verdict.decision == "deny"
	verdict.reason == "budget_tool_calls_exceeded"
}

test_deny_if_budget_exceeded_tokens if {
	verdict := budgets.deny_if_budget_exceeded({"tool_call_count": 9999, "token_count": 100, "elapsed_seconds": 9999, "cost_usd": 9999}) with input as snapshot_with({"token_count": 200})
	verdict.decision == "deny"
	verdict.reason == "budget_tokens_exceeded"
}

test_deny_if_budget_exceeded_timeout if {
	verdict := budgets.deny_if_budget_exceeded({"tool_call_count": 9999, "token_count": 99999, "elapsed_seconds": 30, "cost_usd": 9999}) with input as snapshot_with({"elapsed_seconds": 45.2})
	verdict.decision == "deny"
	verdict.reason == "budget_timeout_exceeded"
}

test_deny_if_budget_exceeded_cost if {
	verdict := budgets.deny_if_budget_exceeded({"tool_call_count": 9999, "token_count": 99999, "elapsed_seconds": 9999, "cost_usd": 1.0}) with input as snapshot_with({"cost_usd": 2.5})
	verdict.decision == "deny"
	verdict.reason == "budget_cost_exceeded"
}

test_missing_snapshot_does_not_emit_verdict if {
	not budgets.deny_if_budget_exceeded({"tool_call_count": 10, "token_count": 10, "elapsed_seconds": 10, "cost_usd": 10}) with input as {}
}
