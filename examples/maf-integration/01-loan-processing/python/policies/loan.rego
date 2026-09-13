# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.maf.loan

import rego.v1

blocked if regex.match(`(?i)(\b\d{3}-\d{2}-\d{4}\b|social security|tax records?)`, sprintf("%v", [input.policy_target.value]))

result := {"decision": "deny", "reason": "loan_safety"} if blocked
result := {"decision": "allow", "reason": "safe"} if not blocked
