# Ported from AgentShield examples/policies/ifc-email-assistant.yaml
#
# Snapshot contract: ACS is stateless, so source exposure and destination
# clearance are supplied by the host on every send_email evaluation as
# snapshot.exposure and snapshot.destination_clearance. exposure is an array of
# labels from {pii, financial, health}. destination_clearance is one of
# public, internal, confidential, restricted. Missing or unknown values fail
# closed for the egress sink.
package agent_control_specification.ifc_email_assistant

import rego.v1

default verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}

verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

snapshot := object.get(input, "snapshot", {})
exposure := object.get(snapshot, "exposure", null)
clearance := object.get(snapshot, "destination_clearance", null)

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "ifc_egress_block",
	"message": "Exposure exceeds the destination's clearance, egress blocked.",
} if {
	input.intervention_point == "pre_tool_call"
	input.tool.name == "send_email"
	not ifc_send_allowed
}

ifc_send_allowed if {
	is_array(exposure)
	valid_clearance(clearance)
	not unsafe_exposure_label
	not pii_exceeds_clearance
	not financial_exceeds_clearance
	not health_exceeds_clearance
}

unsafe_exposure_label if {
	some label in exposure
	not label in {"pii", "financial", "health"}
}

pii_exceeds_clearance if { "pii" in exposure; clearance_rank(clearance) < clearance_rank("internal") }
financial_exceeds_clearance if { "financial" in exposure; clearance_rank(clearance) < clearance_rank("confidential") }
health_exceeds_clearance if { "health" in exposure; clearance_rank(clearance) < clearance_rank("restricted") }

valid_clearance(c) if c in {"public", "internal", "confidential", "restricted"}
clearance_rank("public") := 0
clearance_rank("internal") := 1
clearance_rank("confidential") := 2
clearance_rank("restricted") := 3
