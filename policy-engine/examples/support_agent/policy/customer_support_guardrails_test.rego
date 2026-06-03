# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The previous policy emitted a v4
# `effects` array carrying three pattern-based redacts (email, phone,
# card). The Rust core hard-rejects any verdict with an `effects` key,
# so post_tool_call / output now deny per AGT D1.3 until the multi-
# pattern redaction moves to an annotator.
package agent_control_specification.customer_support_guardrails_test

import data.agent_control_specification.customer_support_guardrails as guard
import rego.v1

test_post_tool_call_pii_denies_per_d1_3 if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"annotations": {"pii_scan": "pii_present"},
		"policy_target": {"value": "Email: a@b.com Phone: 555-555-5555"},
	}
	verdict.decision == "deny"
	verdict.reason == "pii_detected"
}

test_output_pii_denies_per_d1_3 if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"annotations": {"pii_scan": "pii_present"},
		"policy_target": {"value": "Card 4111 1111 1111 1111"},
	}
	verdict.decision == "deny"
	verdict.reason == "pii_detected"
}

test_post_tool_call_passes_through_without_pii if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"annotations": {"pii_scan": "clean"},
		"policy_target": {"value": "harmless"},
	}
	verdict.decision == "allow"
}

test_send_email_external_warns_unchanged if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "send_email"},
		"annotations": {"recipient_scope": "external"},
	}
	verdict.decision == "warn"
}
