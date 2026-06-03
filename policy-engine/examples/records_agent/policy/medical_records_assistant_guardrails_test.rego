# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The Rust core rejects any verdict
# that carries an `effects` key with `runtime_error:policy_output_invalid`,
# so the three PHI redaction sites in
# `medical_records_assistant_guardrails.rego` MUST emit a `transform`
# verdict per AGT-DELTA D1.1.
package agent_control_specification.medical_records_assistant_guardrails_test

import data.agent_control_specification.medical_records_assistant_guardrails as guard
import rego.v1

test_post_model_call_redacts_phi_via_transform if {
	verdict := guard.post_model_call_verdict with input as {
		"intervention_point": "post_model_call",
		"annotations": {"phi_scan": "phi_present"},
		"policy_target": {"value": "Patient John Smith has hypertension"},
	}
	verdict.decision == "transform"
	verdict.reason == "phi_redacted"
	verdict.transform.path == "$policy_target.value"
	verdict.transform.value == "[REDACTED PHI]"
}

test_post_tool_call_redacts_phi_via_transform if {
	verdict := guard.post_tool_call_verdict with input as {
		"intervention_point": "post_tool_call",
		"annotations": {"phi_scan": "phi_present"},
		"policy_target": {"value": "DOB 1980-01-01 SSN 111-22-3333"},
	}
	verdict.decision == "transform"
	verdict.transform.value == "[REDACTED PHI]"
}

test_output_redacts_phi_via_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"annotations": {"phi_scan": "phi_present"},
		"policy_target": {"value": "MRN-123 records summary"},
	}
	verdict.decision == "transform"
	verdict.transform.value == "[REDACTED PHI]"
}

test_post_model_call_passes_through_without_phi if {
	verdict := guard.post_model_call_verdict with input as {
		"intervention_point": "post_model_call",
		"annotations": {"phi_scan": "clean"},
		"policy_target": {"value": "harmless"},
	}
	verdict.decision == "allow"
}
