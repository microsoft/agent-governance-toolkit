# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The previous policy emitted a v4
# `effects: [redact ...]` payload at post_tool_call / output for the
# single PII regex match. The Rust core hard-rejects any verdict with
# an `effects` key, so the two sites now ship an AGT D1.1 Transform
# verdict that replaces the redacted text directly.
package agent_control_specification.workiq_collaboration_dlp_test

import data.agent_control_specification.workiq_collaboration_dlp as guard
import rego.v1

test_post_tool_call_pii_transform if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"tool": {"name": "workiq_get_document"},
		"policy_target": {"value": {"value": "ssn 123-45-6789 trailing"}},
	}
	verdict.decision == "transform"
	verdict.reason == "pii_redact_tool_output"
	verdict.transform.path == "$policy_target.value"
	verdict.transform.value == "ssn [PII REDACTED] trailing"
}

test_output_pii_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "contact alice@example.com please"}},
	}
	verdict.decision == "transform"
	verdict.reason == "pii_redaction"
	verdict.transform.value == "contact [REDACTED] please"
}

test_restricted_document_to_slack_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "slack_post_message"},
		"policy_target": {"value": {}},
		"snapshot": {"document_sensitivity": "restricted"},
	}
	verdict.decision == "deny"
	verdict.reason == "restricted_document_to_slack"
}
