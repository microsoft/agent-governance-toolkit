# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.ifc_test

import data.agt.ifc
import rego.v1

test_clearance_dominates_data_allows if {
	ifc.flow_allowed("secret", ["confidential"])
	ifc.max_sensitivity(["confidential"]) == "confidential"
	ifc.verdict("secret", ["confidential"]).decision == "allow"
}

test_data_exceeds_clearance_denies if {
	not ifc.flow_allowed("internal", ["confidential"])
	verdict := ifc.deny("internal", ["confidential"])
	verdict.decision == "deny"
	verdict.reason == "ifc_clearance_violation"
}

test_incomparable_labels_deny_fail_closed if {
	lattice := {"dominates": {
		"public": ["public"],
		"pii": ["public", "pii"],
		"pci": ["public", "pci"],
	}}
	not ifc.flow_allowed_with_lattice(lattice, "pii", ["pci"])
	verdict := ifc.deny_with_lattice(lattice, "pii", ["pci"])
	verdict.reason == "ifc_clearance_violation"
}

test_missing_and_empty_labels_deny_fail_closed if {
	not ifc.flow_allowed("secret", [])
	verdict := ifc.deny("secret", [])
	verdict.decision == "deny"
	verdict.reason == "ifc_clearance_violation"
}

test_multi_label_uses_max_sensitivity if {
	labels := ["public", "confidential", "internal"]
	ifc.max_sensitivity(labels) == "confidential"
	ifc.flow_allowed("secret", labels)
	not ifc.flow_allowed("internal", labels)
}

test_verdict_propagating_returns_joined_label if {
	verdict := ifc.verdict_propagating("secret", ["public", "confidential", "internal"])
	verdict.decision == "allow"
	verdict.result_labels == ["confidential"]
}

test_verdict_propagating_deny_omits_result_labels if {
	verdict := ifc.verdict_propagating("internal", ["confidential"])
	verdict.decision == "deny"
	verdict.reason == "ifc_clearance_violation"
	not verdict.result_labels
}

test_source_labels_reads_agt_input_path if {
	ifc.source_labels == ["confidential"] with input as {"snapshot": {"input": {"ifc": {"source_labels": ["confidential"]}}}}
}

test_source_labels_defaults_to_empty if {
	ifc.source_labels == [] with input as {"snapshot": {}}
	ifc.source_labels == [] with input as {}
}

test_result_labels_reads_agt_output_path if {
	ifc.result_labels == ["internal"] with input as {"snapshot": {"response": {"ifc": {"result_labels": ["internal"]}}}}
}

test_result_labels_defaults_to_empty if {
	ifc.result_labels == [] with input as {"snapshot": {}}
}

test_allow_if_dominates_returns_verdict if {
	allow := ifc.allow_if_dominates("secret", ["internal"])
	allow.decision == "allow"
	deny := ifc.allow_if_dominates("public", ["secret"])
	deny.decision == "deny"
	deny.reason == "ifc_clearance_violation"
}

test_does_not_read_upstream_ifc_path if {
	# The upstream library reads `input.snapshot.ifc.source_labels`. AGT
	# hosts put source labels under `input.snapshot.input.ifc.source_labels`.
	# Confirm the AGT helper sees nothing at the upstream path.
	ifc.source_labels == [] with input as {"snapshot": {"ifc": {"source_labels": ["secret"]}}}
}
