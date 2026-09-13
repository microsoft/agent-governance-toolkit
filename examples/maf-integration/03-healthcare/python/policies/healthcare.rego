# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.maf.healthcare

import rego.v1

blocked if regex.match(`(?i)(MRN[:\s]*\d{6,}|\b\d{3}-\d{2}-\d{4}\b)`, sprintf("%v", [input.policy_target.value]))

result := {"decision": "deny", "reason": "healthcare_safety"} if blocked
result := {"decision": "allow", "reason": "safe"} if not blocked
