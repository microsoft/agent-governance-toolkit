# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock IFC label-flow library. This file replaces the upstream
# `agent_control_specification.lib.ifc` library for AGT users authoring
# manifests against the AGT snapshot shape. The function surface
# (`dominates`, `max_sensitivity`, `flow_allowed`, `allow`, `deny`,
# `verdict`, `verdict_propagating`, and their `_with_lattice` variants)
# matches the upstream library so policies authored against the AGT helpers
# remain familiar. The snapshot paths are AGT-correct per
# AGT-SNAPSHOT-1.0.md §2.2 (input) and §2.7 (output):
# `input.snapshot.input.ifc.source_labels` at the `input` intervention
# point, and `input.snapshot.response.ifc.result_labels` at `output`. The
# upstream `agent_control_specification.lib.ifc` library reads
# `input.snapshot.ifc.*`, which the AGT host SDKs do not populate and which
# would therefore fail closed on every call. AGT users MUST import
# `data.agt.ifc` rather than the upstream package.

package agt.ifc

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

verdict(clearance, labels) := value if {
	not flow_allowed(clearance, labels)
	value := violation(clearance, labels)
} else := {"decision": "allow"} if {
	flow_allowed(clearance, labels)
}

verdict_with_lattice(lattice, clearance, labels) := value if {
	not flow_allowed_with_lattice(lattice, clearance, labels)
	value := violation(clearance, labels)
} else := {"decision": "allow"} if {
	flow_allowed_with_lattice(lattice, clearance, labels)
}

violation(clearance, labels) := {
	"decision": "deny",
	"reason": "ifc_clearance_violation",
	"message": sprintf("IFC clearance violation for sink clearance %v and data labels %v.", [clearance, labels]),
}

propagated_labels(labels) := [max_sensitivity(labels)] if {
	count(labels) > 0
} else := []

propagated_labels_with_lattice(lattice, labels) := [max_sensitivity_with_lattice(lattice, labels)] if {
	count(labels) > 0
} else := []

verdict_propagating(clearance, labels) := value if {
	not flow_allowed(clearance, labels)
	value := violation(clearance, labels)
} else := {"decision": "allow", "result_labels": propagated_labels(labels)} if {
	flow_allowed(clearance, labels)
}

verdict_propagating_with_lattice(lattice, clearance, labels) := value if {
	not flow_allowed_with_lattice(lattice, clearance, labels)
	value := violation(clearance, labels)
} else := {"decision": "allow", "result_labels": propagated_labels_with_lattice(lattice, labels)} if {
	flow_allowed_with_lattice(lattice, clearance, labels)
}

# Convenience helper that reads AGT snapshot source labels at the input
# intervention point.
source_labels := value if {
	value := input.snapshot.input.ifc.source_labels
	is_array(value)
} else := []

# Convenience helper that reads AGT snapshot result labels at the output
# intervention point.
result_labels := value if {
	value := input.snapshot.response.ifc.result_labels
	is_array(value)
} else := []

# allow_if_dominates is the AGT shorthand for the no-write-down policy.
# The sink clearance must dominate every source label on the AGT snapshot.
allow_if_dominates(sink_clearance, labels) := value if {
	value := verdict(sink_clearance, labels)
}
