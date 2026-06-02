# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.redact_test

import data.agt.patterns
import data.agt.redact
import rego.v1

test_redact_text_returns_transform_verdict if {
	verdict := redact.redact_text("ssn 111-22-3333 in plain text", [patterns.pii_ssn], "[REDACTED]")
	verdict.decision == "transform"
	verdict.reason == "redaction_applied"
	verdict.transform.path == "$policy_target"
	verdict.transform.value == "ssn [REDACTED] in plain text"
}

test_redact_text_handles_multiple_patterns if {
	text := "alice@x.com then ssn 111-22-3333 here"
	verdict := redact.redact_text(text, patterns.pii_patterns, "[X]")
	verdict.decision == "transform"
	verdict.transform.value == "[X] then ssn [X] here"
}

test_redact_text_no_match_returns_nothing if {
	not redact.redact_text("benign", patterns.pii_patterns, "[X]")
}

test_redact_text_default_replacement if {
	verdict := redact.redact_text("ssn 111-22-3333", [patterns.pii_ssn], null)
	verdict.transform.value == "ssn [REDACTED]"
}

test_redact_text_path_rooted_at_policy_target if {
	verdict := redact.redact_text("email a@b.com here", [patterns.pii_email], "[X]")
	startswith(verdict.transform.path, "$policy_target")
}

test_redact_text_handles_non_string_input if {
	not redact.redact_text(123, patterns.pii_patterns, "[X]")
}

test_combined_pattern_joins_with_alternation if {
	pattern := redact.combined_pattern(["a", "b", "c"])
	pattern == "(?:a)|(?:b)|(?:c)"
}
