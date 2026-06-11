# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The Rust core rejects any verdict with
# an `effects` key, so the two output redact sites now ship an AGT D1.1
# Transform verdict.
package agent_control_specification.crewai_invoice_quickstart_test

import data.agent_control_specification.crewai_invoice_quickstart as guard
import rego.v1

test_output_ssn_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "ssn 123-45-6789 noted"}},
	}
	verdict.decision == "transform"
	verdict.reason == "redact_ssn_in_final_reply"
	verdict.transform.path == "$policy_target.text"
	verdict.transform.value == "ssn [SSN-REDACTED] noted"
}

test_output_card_transform if {
	verdict := guard.output_verdict with input as {
		"intervention_point": "output",
		"policy_target": {"value": {"text": "card 4111 1111 1111 1111 used"}},
	}
	verdict.decision == "transform"
	verdict.transform.value == "card [CARD-REDACTED] used"
}

test_approve_payment_non_allowlisted_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "approve_payment"},
		"policy_target": {"value": {}},
		"snapshot": {"vendor": "BAD_GUY", "amount": 1000, "fraud_score": 10, "invoice_id": "i1"},
	}
	verdict.decision == "deny"
	verdict.reason == "approve_payment_requires_allowlisted_vendor"
}
