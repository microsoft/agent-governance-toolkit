# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.content_hash_test

import data.agt.content_hash
import rego.v1

test_matching_hashes_emit_no_verdict if {
	not content_hash.deny_if_mismatch with input as {
		"tool": {"content_hash": "sha256:abc"},
		"snapshot": {"tool_call": {"content_hash": "sha256:abc"}},
	}
}

test_missing_observed_hash_when_declared_denies if {
	verdict := content_hash.deny_if_mismatch with input as {
		"tool": {"content_hash": "sha256:abc"},
		"snapshot": {"tool_call": {}},
	}
	verdict.decision == "deny"
	verdict.reason == "tool_content_hash_mismatch"
}

test_mismatch_denies if {
	verdict := content_hash.deny_if_mismatch with input as {
		"tool": {"content_hash": "sha256:abc"},
		"snapshot": {"tool_call": {"content_hash": "sha256:def"}},
	}
	verdict.decision == "deny"
	verdict.reason == "tool_content_hash_mismatch"
}

test_manifest_did_not_declare_emits_no_verdict if {
	not content_hash.deny_if_mismatch with input as {
		"tool": {},
		"snapshot": {"tool_call": {"content_hash": "sha256:abc"}},
	}
}

test_neither_present_emits_no_verdict if {
	not content_hash.deny_if_mismatch with input as {"tool": {}, "snapshot": {"tool_call": {}}}
}

test_non_string_declared_hash_treated_as_undeclared if {
	not content_hash.deny_if_mismatch with input as {
		"tool": {"content_hash": 123},
		"snapshot": {"tool_call": {"content_hash": "sha256:abc"}},
	}
}
