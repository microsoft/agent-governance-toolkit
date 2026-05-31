# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The previous policy emitted a v4
# `effects: [redact ...]` payload at post_tool_call / output when the
# secret_scan annotator flagged the content. The Rust core hard-rejects
# any verdict with an `effects` key, so the two sites now emit a
# Transform verdict per AGT D1.1 that replaces the policy target with
# a placeholder.
package agent_control_specification.software_engineering_assistant_guardrails_test

import data.agent_control_specification.software_engineering_assistant_guardrails as guard
import rego.v1

test_post_tool_call_secret_redacts_via_transform if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"annotations": {"secret_scan": "secret_present"},
		"policy_target": {"value": "AWS_SECRET_ACCESS_KEY=abcd1234"},
	}
	verdict.decision == "transform"
	verdict.reason == "secret_redacted"
	verdict.transform.path == "$policy_target"
	verdict.transform.value == "[REDACTED_SECRET]"
}

test_output_secret_redacts_via_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"annotations": {"secret_scan": "secret_present"},
		"policy_target": {"value": "TOKEN=ghp_xxx"},
	}
	verdict.decision == "transform"
	verdict.transform.value == "[REDACTED_SECRET]"
}

test_output_without_secret_allows if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"annotations": {"secret_scan": "clean"},
		"policy_target": {"value": "harmless"},
	}
	verdict.decision == "allow"
}

test_run_shell_destructive_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "run_shell"},
		"annotations": {"shell_command_risk": "destructive"},
	}
	verdict.decision == "deny"
}
