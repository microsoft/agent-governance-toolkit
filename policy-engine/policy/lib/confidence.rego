# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock confidence gate. Hosts attach a self-assessed confidence score
# under `input.annotations.confidence.score` (range 0..1) and this library
# denies the action with `confidence_below_threshold` when the score falls
# under the manifest-configured minimum.

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
