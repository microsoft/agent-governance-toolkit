# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.maf.support

import rego.v1

blocked if regex.match(`(?i)ignore\s+previous\s+instructions`, sprintf("%v", [input.policy_target.value]))

result := {"decision": "deny", "reason": "support_safety"} if blocked
result := {"decision": "allow", "reason": "safe"} if not blocked
