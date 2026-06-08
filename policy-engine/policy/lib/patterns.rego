# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock pattern helpers. The PII regex set tracks the canonical Python
# source list in agent-os/src/agent_os/integrations/base.py::PII_PATTERNS.
# Helpers expose the first match span and an AGT deny verdict per
# SPECIFICATION.md §13.1 for callers that want a simple block on PII.

package agt.patterns

import rego.v1

# Per agent_os.integrations.base.PII_PATTERNS. Patterns are anchored with
# word boundaries where the source uses them; the secrets pattern is case
# insensitive via the inline (?i) flag accepted by the Go RE2 engine.

pii_ssn := `\b\d{3}[\s.\-]?\d{2}[\s.\-]?\d{4}\b`

pii_email := `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`

pii_phone := `\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b`

pii_credit_card := `\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14})\b`

pii_secret := `(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+`

pii_patterns := [
	pii_ssn,
	pii_email,
	pii_phone,
	pii_credit_card,
	pii_secret,
]

matches_any(text, patterns) if {
	is_string(text)
	is_array(patterns)
	some pattern in patterns
	regex.match(pattern, text)
}

first_match(text, patterns) := match if {
	is_string(text)
	is_array(patterns)
	scored := [hit |
		some idx, pattern in patterns
		found := regex.find_n(pattern, text, 1)
		count(found) > 0
		span_start := indexof(text, found[0])
		span_start >= 0
		hit := {
			"pattern": pattern,
			"pattern_index": idx,
			"match": found[0],
			"span_start": span_start,
			"span_end": span_start + count(found[0]),
		}
	]
	count(scored) > 0
	match := earliest(scored)
}

earliest(hits) := winner if {
	count(hits) > 0
	some i
	winner := hits[i]
	every other in hits {
		not earlier_than(other, winner)
	}
}

earlier_than(a, b) if {
	a.span_start < b.span_start
} else if {
	a.span_start == b.span_start
	a.pattern_index < b.pattern_index
}

deny_if_pattern(text, patterns, reason) := verdict if {
	hit := first_match(text, patterns)
	verdict := {
		"decision": "deny",
		"reason": reason,
		"message": sprintf("matched pattern %v at offset %v", [hit.pattern, hit.span_start]),
	}
}
