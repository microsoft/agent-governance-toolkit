# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock drift gate. Hosts run a behaviour-drift detector outside the
# policy engine and attach its score under `input.annotations.drift_score`
# (a host annotator name agreed in the manifest). This library issues a
# warn verdict per SPECIFICATION.md §13.1 when the score crosses the
# configured threshold so a host can flag the run without blocking.

package agt.drift

import rego.v1

score := value if {
	value := input.annotations.drift_score
	is_number(value)
}

drift_exceeds(threshold) if {
	is_number(threshold)
	value := score
	value >= threshold
}

warn_if_drift(threshold) := verdict if {
	drift_exceeds(threshold)
	verdict := {
		"decision": "warn",
		"reason": "drift_detected",
		"message": sprintf("drift_score %v reached threshold %v", [score, threshold]),
	}
}
