# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock tool content-hash gate. The manifest tool catalog MAY declare a
# `content_hash` per AGT-MANIFEST §9. AGT-SNAPSHOT-1.0.md §2.5 lets the host
# attach `tool_call.content_hash` to the snapshot. This library denies the
# tool invocation when the declared hash and the observed hash disagree or
# when the manifest required a hash that the snapshot did not carry.

package agt.content_hash

import rego.v1

declared_hash := value if {
	value := input.tool.content_hash
	is_string(value)
}

observed_hash := value if {
	value := input.snapshot.tool_call.content_hash
	is_string(value)
}

declared_present if {
	is_string(input.tool.content_hash)
}

observed_present if {
	is_string(input.snapshot.tool_call.content_hash)
}

deny_if_mismatch := verdict if {
	declared_present
	not observed_present
	verdict := {
		"decision": "deny",
		"reason": "tool_content_hash_mismatch",
		"message": "manifest declared tool.content_hash but snapshot.tool_call.content_hash was missing",
	}
} else := verdict if {
	declared_present
	observed_present
	declared_hash != observed_hash
	verdict := {
		"decision": "deny",
		"reason": "tool_content_hash_mismatch",
		"message": sprintf("declared %v but observed %v", [declared_hash, observed_hash]),
	}
}
