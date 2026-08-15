# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.patterns

import rego.v1

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

# ``indexof(text, "")`` is undefined in OPA, so a pattern whose leftmost match
# is zero-length (``[0-9]*``, a bare ``*`` glob) would drop out of the scored
# comprehension and leave first_match undefined. matches_any still reports a
# match, so a caller that gates on matches_any and then reads a verdict from
# first_match would fall through to allow.
#
# OPA's regex builtins return the matched text, never its position, so a
# zero-length match has no recoverable offset: ``(?m)$`` matches at the end of
# the subject, not at 0. Report 0 as a deterministic placeholder. The span is
# diagnostic only -- it feeds the deny message and the earliest() tie-break,
# and nothing outside this file reads it -- so the decision is unaffected, but
# a deny whose only matching pattern is zero-width may name offset 0 and, where
# a longer match also exists, may name the zero-width pattern instead.
match_start(_, matched) := 0 if {
	matched == ""
}

match_start(text, matched) := start if {
	matched != ""
	start := indexof(text, matched)
}

first_match(text, patterns) := match if {
	is_string(text)
	is_array(patterns)
	scored := [hit |
		some idx, pattern in patterns
		found := regex.find_n(pattern, text, 1)
		count(found) > 0
		span_start := match_start(text, found[0])
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
