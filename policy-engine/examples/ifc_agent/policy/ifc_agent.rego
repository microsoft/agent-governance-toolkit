package agent_control_specification.ifc_agent

import data.agent_control_specification.lib.ifc
import rego.v1

default verdict := {"decision": "allow"}

default pre_tool_call_verdict := {"decision": "allow"}

verdict := pre_tool_call_verdict if {
	input.intervention_point == "pre_tool_call"
}

source_labels := object.get(object.get(input.snapshot, "ifc", {}), "source_labels", [])

sink_clearance := object.get(input.tool, "clearance", "")

pre_tool_call_verdict := ifc.verdict_propagating(sink_clearance, source_labels) if {
	input.intervention_point == "pre_tool_call"
}
