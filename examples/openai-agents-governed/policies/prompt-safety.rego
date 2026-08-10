# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.openai_agents

import rego.v1

blocked if regex.match(`(?i)ignore\s+previous\s+instructions`, sprintf("%v", [input.policy_target.value]))

result := {"decision": "deny", "reason": "prompt_injection"} if blocked
result := {"decision": "allow", "reason": "safe"} if not blocked
