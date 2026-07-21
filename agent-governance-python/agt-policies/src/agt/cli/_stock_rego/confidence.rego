# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.confidence

import rego.v1

score := value if {
	value := input.annotations.confidence.score
	is_number(value)
}

below(threshold) if {
	is_number(threshold)
	value := score
	value < threshold
}

deny_if_low_confidence(threshold) := verdict if {
	below(threshold)
	verdict := {
		"decision": "deny",
		"reason": "confidence_below_threshold",
		"message": sprintf("confidence %v below threshold %v", [score, threshold]),
	}
}
