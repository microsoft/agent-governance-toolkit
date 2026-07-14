# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.maf.devops

import rego.v1

blocked if regex.match(`(?i)(kubectl\s+delete|drop\s+database|disable\s+rollback)`, sprintf("%v", [input.policy_target.value]))

result := {"decision": "deny", "reason": "devops_safety"} if blocked
result := {"decision": "allow", "reason": "safe"} if not blocked
