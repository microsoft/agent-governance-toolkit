# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The previous policy emitted a v4
# `effects: [redact ...]` payload from the redact_from factory across
# post_tool_call and output. The Rust core hard-rejects any verdict
# with an `effects` key, so the factory now produces an AGT D1.1
# Transform verdict that ships the redacted text directly.
package agent_control_specification.document_dlp_test

import data.agent_control_specification.document_dlp as guard
import rego.v1

test_post_tool_call_secret_transform if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"tool": {"name": "datastore_lookup_documents"},
		"policy_target": {"value": {"text": "leak api_key: abcd1234 here"}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_secret_in_tool_result"
	verdict.transform.path == "$policy_target.text"
	verdict.transform.value == "leak [SECRET-REDACTED] here"
}

test_post_tool_call_ssn_transform if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"tool": {"name": "datastore_lookup_documents"},
		"policy_target": {"value": {"text": "ssn 123-45-6789 found"}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_ssn_in_tool_result"
	verdict.transform.value == "ssn [SSN-REDACTED] found"
}

test_output_secret_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "before password=hunter2 after"}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_secret_in_output"
	verdict.transform.value == "before [SECRET-REDACTED] after"
}

test_send_email_unverified_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "datastore_send_email"},
		"policy_target": {"value": {}},
		"snapshot": {"recipient_verified": false},
	}
	verdict.decision == "deny"
	verdict.reason == "send_email_requires_verified_recipient"
}

# Regression for the redaction fail-open. The shared transform helper used
# to replace only the first regex match, so a second distinct sensitive
# value in the same text was emitted in cleartext. These two cases assert
# that every match is redacted, across both redaction patterns (SSN and
# secret) and both intervention points (output and post_tool_call).
test_output_redacts_every_ssn if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "Patient A SSN 123-45-6789. Patient B SSN 987-65-4321."}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_ssn_in_output"
	verdict.transform.value == "Patient A SSN [SSN-REDACTED]. Patient B SSN [SSN-REDACTED]."
}

test_post_tool_call_redacts_every_secret if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"tool": {"name": "datastore_lookup_documents"},
		"policy_target": {"value": {"text": "api_key: AKIA111 and password: hunter2"}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_secret_in_tool_result"
	verdict.transform.value == "[SECRET-REDACTED] and [SECRET-REDACTED]"
}

# Passthrough: text with no sensitive value must not produce a transform.
test_output_clean_text_allows if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "All clear, nothing sensitive in this message."}},
	}
	verdict.decision == "allow"
}
