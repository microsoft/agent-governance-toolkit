package agent_control_specification.lib.ifc_test

import data.agent_control_specification.lib.ifc
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

test_unrecognized_labels_deny_fail_closed if {
	not ifc.flow_allowed("secret", ["unknown"])
	verdict := ifc.deny("secret", ["unknown"])
	verdict.decision == "deny"
}

test_multi_label_inflow_uses_maximum_sensitivity if {
	labels := ["public", "confidential", "internal"]
	ifc.max_sensitivity(labels) == "confidential"
	ifc.flow_allowed("secret", labels)
	not ifc.flow_allowed("internal", labels)
}

test_propagating_allow_returns_joined_label if {
	verdict := ifc.verdict_propagating("secret", ["public", "confidential", "internal"])
	verdict.decision == "allow"
	verdict.result_labels == ["confidential"]
}

test_propagating_deny_omits_result_labels if {
	verdict := ifc.verdict_propagating("internal", ["confidential"])
	verdict.decision == "deny"
	verdict.reason == "ifc_clearance_violation"
	not verdict.result_labels
}

test_propagating_with_lattice_returns_joined_label if {
	lattice := {"dominates": {
		"public": ["public"],
		"internal": ["public", "internal"],
		"confidential": ["public", "internal", "confidential"],
		"secret": ["public", "internal", "confidential", "secret"],
	}}
	verdict := ifc.verdict_propagating_with_lattice(lattice, "secret", ["internal", "public"])
	verdict.decision == "allow"
	verdict.result_labels == ["internal"]
}
