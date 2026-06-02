# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock redaction transform. Combines `agt.patterns` regex matching with
# the AGT transform verdict shape (SPECIFICATION.md §14). The
# returned verdict carries `transform.path = "$policy_target"` and a fully
# replaced value, so the dispatcher can apply the substitution without
# additional logic on the host side. The substitution runs in Rego via
# `regex.replace` over a combined alternation, keeping it deterministic
# across SDKs and avoiding recursive Rego rules.

package agt.redact

import data.agt.patterns
import rego.v1

default_replacement := "[REDACTED]"

combined_pattern(pats) := pattern if {
	is_array(pats)
	count(pats) > 0
	parts := [sprintf("(?:%s)", [p]) | some p in pats]
	pattern := concat("|", parts)
}

apply_patterns(text, pats, replacement) := result if {
	is_string(text)
	pattern := combined_pattern(pats)
	result := regex.replace(text, pattern, replacement)
}

effective_replacement(replacement) := replacement if {
	is_string(replacement)
} else := default_replacement

redact_text(text, pats, replacement) := verdict if {
	patterns.matches_any(text, pats)
	rep := effective_replacement(replacement)
	new_value := apply_patterns(text, pats, rep)
	verdict := {
		"decision": "transform",
		"reason": "redaction_applied",
		"transform": {
			"path": "$policy_target",
			"value": new_value,
		},
	}
}
