# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock budget helpers. These rules read the
# `input.snapshot.envelope.budgets` block per AGT-SNAPSHOT-1.0.md §1 and emit
# AGT verdicts per SPECIFICATION.md §13.1. A budget is exceeded when
# the host-tracked counter has already reached the configured limit. The
# helpers fail safe when a counter or threshold is absent. Present malformed
# counters fail closed instead of being coerced to zero.

package agt.budgets

import rego.v1

budget_counter_names := {"tool_call_count", "token_count", "elapsed_seconds", "cost_usd"}

budget_counter_present(name) if {
	_ := input.snapshot.envelope.budgets[name]
}

malformed_budget_counter(name) if {
	budget_counter_names[name]
	value := input.snapshot.envelope.budgets[name]
	not is_number(value)
}

budget_counter(name) := value if {
	value := input.snapshot.envelope.budgets[name]
	is_number(value)
} else := 0 if {
	not budget_counter_present(name)
}

tool_call_count := budget_counter("tool_call_count")

token_count := budget_counter("token_count")

elapsed_seconds := budget_counter("elapsed_seconds")

cost_usd := budget_counter("cost_usd")

max_tool_calls_exceeded(limit) if {
	is_number(limit)
	tool_call_count >= limit
}

max_tokens_exceeded(limit) if {
	is_number(limit)
	token_count >= limit
}

timeout_exceeded(limit) if {
	is_number(limit)
	elapsed_seconds >= limit
}

max_cost_exceeded(limit) if {
	is_number(limit)
	cost_usd >= limit
}

deny_if_budget_exceeded(thresholds) := verdict if {
	some name in budget_counter_names
	malformed_budget_counter(name)
	verdict := {
		"decision": "deny",
		"reason": "budget_counter_invalid",
		"message": sprintf("budget counter %s must be a number", [name]),
	}
} else := verdict if {
	max_tool_calls_exceeded(thresholds.tool_call_count)
	verdict := {
		"decision": "deny",
		"reason": "budget_tool_calls_exceeded",
		"message": sprintf("tool_call_count %v reached limit %v", [tool_call_count, thresholds.tool_call_count]),
	}
} else := verdict if {
	max_tokens_exceeded(thresholds.token_count)
	verdict := {
		"decision": "deny",
		"reason": "budget_tokens_exceeded",
		"message": sprintf("token_count %v reached limit %v", [token_count, thresholds.token_count]),
	}
} else := verdict if {
	timeout_exceeded(thresholds.elapsed_seconds)
	verdict := {
		"decision": "deny",
		"reason": "budget_timeout_exceeded",
		"message": sprintf("elapsed_seconds %v reached limit %v", [elapsed_seconds, thresholds.elapsed_seconds]),
	}
} else := verdict if {
	max_cost_exceeded(thresholds.cost_usd)
	verdict := {
		"decision": "deny",
		"reason": "budget_cost_exceeded",
		"message": sprintf("cost_usd %v reached limit %v", [cost_usd, thresholds.cost_usd]),
	}
}
