# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.workshop.lab1

import rego.v1

result := {
    "decision": "deny",
    "reason": "code_execution_blocked",
} if {
    input.policy_target.value.tool_name == "execute_code"
} else := {
    "decision": "deny",
    "reason": "write_operation_blocked",
} if {
    startswith(input.policy_target.value.tool_name, "write_")
} else := {
    "decision": "deny",
    "reason": "token_budget_exceeded",
} if {
    input.policy_target.value.token_count > 2000
} else := {
    "decision": "allow",
    "reason": "safe",
}
