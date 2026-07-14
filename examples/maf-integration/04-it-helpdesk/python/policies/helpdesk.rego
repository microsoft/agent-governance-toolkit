# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.maf.helpdesk

import rego.v1

blocked if regex.match(`(?i)(rm\s+-rf|disable\s+security|dump\s+credentials)`, sprintf("%v", [input.policy_target.value]))

result := {"decision": "deny", "reason": "helpdesk_safety"} if blocked
result := {"decision": "allow", "reason": "safe"} if not blocked
