# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT-DELTA D1 regression tests. The Rust core rejects any verdict with
# an `effects` key, so the two output redact sites now ship an AGT D1.1
# Transform verdict.
package agent_control_specification.autogen_team_quickstart_test

import data.agent_control_specification.autogen_team_quickstart as guard
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

test_create_account_without_kyc_denies if {
	verdict := guard.pre_tool_call_verdict with input as {
		"intervention_point": "pre_tool_call",
		"tool": {"name": "create_account"},
		"policy_target": {"value": {}},
		"snapshot": {},
	}
	verdict.decision == "deny"
	verdict.reason == "create_account_requires_kyc"
}
