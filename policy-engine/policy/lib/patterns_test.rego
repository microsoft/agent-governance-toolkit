# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.patterns_test

import data.agt.patterns
import rego.v1

test_ssn_regex_matches if {
	patterns.matches_any("My ssn is 123-45-6789 please", [patterns.pii_ssn])
}

test_email_regex_matches if {
	patterns.matches_any("ping me at alice@example.com tomorrow", [patterns.pii_email])
}

test_credit_card_regex_matches if {
	patterns.matches_any("card 4111111111111111 expires soon", [patterns.pii_credit_card])
}

test_secret_regex_matches_case_insensitive if {
	patterns.matches_any("api_key=abc123def", [patterns.pii_secret])
	patterns.matches_any("API_KEY = sk-deadbeef", [patterns.pii_secret])
}

test_phone_regex_matches if {
	patterns.matches_any("call (415) 555-1212 now", [patterns.pii_phone])
}

test_no_match_returns_nothing if {
	not patterns.matches_any("nothing sensitive here", patterns.pii_patterns)
	not patterns.first_match("nothing sensitive here", patterns.pii_patterns)
}

test_first_match_returns_match_metadata if {
	hit := patterns.first_match("ssn 111-22-3333 in plain text", [patterns.pii_ssn])
	hit.pattern == patterns.pii_ssn
	hit.match == "111-22-3333"
	hit.span_start == 4
	hit.span_end == 15
}

test_first_match_picks_earliest_span if {
	hit := patterns.first_match("alice@x.com then 111-22-3333", patterns.pii_patterns)
	hit.match == "alice@x.com"
	hit.span_start == 0
}

test_deny_if_pattern_emits_deny_verdict if {
	verdict := patterns.deny_if_pattern("ssn 123-45-6789 detected", patterns.pii_patterns, "pii_detected")
	verdict.decision == "deny"
	verdict.reason == "pii_detected"
}

test_deny_if_pattern_no_match_returns_nothing if {
	not patterns.deny_if_pattern("benign text", patterns.pii_patterns, "pii_detected")
}

test_non_string_input_does_not_match if {
	not patterns.matches_any(123, patterns.pii_patterns)
	not patterns.first_match({"x": 1}, patterns.pii_patterns)
}
