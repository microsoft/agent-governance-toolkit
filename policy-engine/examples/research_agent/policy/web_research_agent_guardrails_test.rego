# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The previous policy emitted an
# `effects: [redact ...]` payload at post_tool_call / output for the
# single secret_scan match. The Rust core hard-rejects any verdict
# carrying an `effects` key, so the two sites now compute the redacted
# string at policy time and ship it inside an AGT D1.1 Transform
# verdict.
package agent_control_specification.web_research_agent_guardrails_test

import data.agent_control_specification.web_research_agent_guardrails as guard
import rego.v1

test_post_tool_call_secret_transform_replaces_match if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"annotations": {"secret_scan": "secret_present"},
		"policy_target": {"value": "logs API_KEY=abcd1234 trailing"},
	}
	verdict.decision == "transform"
	verdict.reason == "secret_redacted"
	verdict.transform.path == "$policy_target"
	verdict.transform.value == "logs [REDACTED_SECRET] trailing"
}

test_output_secret_transform_replaces_match if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"annotations": {"secret_scan": "secret_present"},
		"policy_target": {"value": "before TOKEN=xyz123 after"},
	}
	verdict.decision == "transform"
	verdict.transform.value == "before [REDACTED_SECRET] after"
}

test_post_tool_call_very_large_warns_unchanged if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"annotations": {"content_size": "very_large"},
		"policy_target": {"value": "big content"},
	}
	verdict.decision == "warn"
}

test_http_fetch_disallowed_domain_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "http_fetch"},
		"annotations": {"url_scope": "disallowed_domain"},
	}
	verdict.decision == "deny"
}
