package agent_control_specification.lib.ifc

import rego.v1

default_lattice := {"dominates": {
	"public": ["public"],
	"internal": ["public", "internal"],
	"confidential": ["public", "internal", "confidential"],
	"secret": ["public", "internal", "confidential", "secret"],
}}

dominates(clearance, label) if {
	dominates_with_lattice(default_lattice, clearance, label)
}

dominates_with_lattice(lattice, clearance, label) if {
	is_string(clearance)
	is_string(label)
	dominance := object.get(lattice, "dominates", {})
	labels := object.get(dominance, clearance, [])
	some dominated in labels
	dominated == label
}

max_sensitivity(labels) := label if {
	label := max_sensitivity_with_lattice(default_lattice, labels)
}

max_sensitivity_with_lattice(lattice, labels) := label if {
	count(labels) > 0
	label := labels[_]
	every other in labels {
		dominates_with_lattice(lattice, label, other)
	}
}

flow_allowed(clearance, labels) if {
	flow_allowed_with_lattice(default_lattice, clearance, labels)
}

flow_allowed_with_lattice(lattice, clearance, labels) if {
	is_string(clearance)
	is_array(labels)
	count(labels) > 0
	sensitivity := max_sensitivity_with_lattice(lattice, labels)
	dominates_with_lattice(lattice, clearance, sensitivity)
}

allow(clearance, labels) := {"decision": "allow"} if {
	flow_allowed(clearance, labels)
}

allow_with_lattice(lattice, clearance, labels) := {"decision": "allow"} if {
	flow_allowed_with_lattice(lattice, clearance, labels)
}

deny(clearance, labels) := verdict if {
	not flow_allowed(clearance, labels)
	verdict := violation(clearance, labels)
}

deny_with_lattice(lattice, clearance, labels) := verdict if {
	not flow_allowed_with_lattice(lattice, clearance, labels)
	verdict := violation(clearance, labels)
}

verdict(clearance, labels) := verdict if {
	not flow_allowed(clearance, labels)
	verdict := violation(clearance, labels)
} else := {"decision": "allow"} if {
	flow_allowed(clearance, labels)
}

verdict_with_lattice(lattice, clearance, labels) := verdict if {
	not flow_allowed_with_lattice(lattice, clearance, labels)
	verdict := violation(clearance, labels)
} else := {"decision": "allow"} if {
	flow_allowed_with_lattice(lattice, clearance, labels)
}

violation(clearance, labels) := {
	"decision": "deny",
	"reason": "ifc_clearance_violation",
	"message": sprintf("IFC clearance violation for sink clearance %v and data labels %v.", [clearance, labels]),
}

# Propagated labels describe the data flowing OUT of a sink. Under a join
# semilattice the label of the produced data is the least upper bound of the
# incoming source labels, which `max_sensitivity` computes. The host persists
# these with the produced data and re-supplies them as source labels later.
propagated_labels(labels) := [max_sensitivity(labels)] if {
	count(labels) > 0
} else := []

propagated_labels_with_lattice(lattice, labels) := [max_sensitivity_with_lattice(lattice, labels)] if {
	count(labels) > 0
} else := []

# Like `verdict`, but an allow also returns `result_labels` so the core can hand
# the propagated label back to the host for use on subsequent evaluations.
verdict_propagating(clearance, labels) := verdict if {
	not flow_allowed(clearance, labels)
	verdict := violation(clearance, labels)
} else := {"decision": "allow", "result_labels": propagated_labels(labels)} if {
	flow_allowed(clearance, labels)
}

verdict_propagating_with_lattice(lattice, clearance, labels) := verdict if {
	not flow_allowed_with_lattice(lattice, clearance, labels)
	verdict := violation(clearance, labels)
} else := {"decision": "allow", "result_labels": propagated_labels_with_lattice(lattice, labels)} if {
	flow_allowed_with_lattice(lattice, clearance, labels)
}
