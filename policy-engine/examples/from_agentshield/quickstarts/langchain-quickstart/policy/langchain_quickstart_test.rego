# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The Rust core rejects any verdict with
# an `effects` key, so the two output redact sites now ship an AGT D1.1
# Transform verdict.
package agent_control_specification.langchain_quickstart_test

import data.agent_control_specification.langchain_quickstart as guard
import rego.v1

test_output_ssn_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "ssn 123-45-6789 here"}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_ssn_in_response"
	verdict.transform.path == "$policy_target.text"
	verdict.transform.value == "ssn [SSN-REDACTED] here"
}

test_output_card_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "card 4111 1111 1111 1111 used"}},
	}
	verdict.decision == "transform"
	verdict.transform.value == "card [CARD-REDACTED] used"
}

test_read_file_sensitive_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "read_file"},
		"policy_target": {"value": {"path": "/etc/passwd"}},
	}
	verdict.decision == "deny"
	verdict.reason == "read_file_path_allowlist"
}
