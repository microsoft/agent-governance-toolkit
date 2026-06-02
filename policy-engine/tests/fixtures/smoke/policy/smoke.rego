package agent_control_specification.smoke

import rego.v1

# Shared smoke policy for integration testing.
#
# Every intervention point denies deterministically when the JSON-encoded
# policy target contains the sentinel string "BLOCKME". The two tool points
# additionally deny when the invoked tool is named "danger_tool". This lets an
# integration test drive a benign call (allowed) and a malicious call (denied)
# at each of the eight intervention points without any annotators.

default verdict := {"decision": "allow"}
default agent_startup_verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_model_call_verdict := {"decision": "allow"}
default post_model_call_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}
default agent_shutdown_verdict := {"decision": "allow"}

# Generic dispatch query (used by SDKs that bind a single verdict rule).
verdict := agent_startup_verdict if { input.intervention_point == "agent_startup" }
verdict := input_verdict if { input.intervention_point == "input" }
verdict := pre_model_call_verdict if { input.intervention_point == "pre_model_call" }
verdict := post_model_call_verdict if { input.intervention_point == "post_model_call" }
verdict := pre_tool_call_verdict if { input.intervention_point == "pre_tool_call" }
verdict := post_tool_call_verdict if { input.intervention_point == "post_tool_call" }
verdict := output_verdict if { input.intervention_point == "output" }
verdict := agent_shutdown_verdict if { input.intervention_point == "agent_shutdown" }

# True when the encoded policy target carries the deny sentinel.
target_has_sentinel if {
	contains(json.marshal(input.policy_target.value), "BLOCKME")
}

deny_for(point) := {
	"decision": "deny",
	"reason": sprintf("%s_sentinel_detected", [point]),
	"message": sprintf("Smoke policy blocked %s because the target contained BLOCKME.", [point]),
}

agent_startup_verdict := deny_for("agent_startup") if {
	input.intervention_point == "agent_startup"
	target_has_sentinel
}

input_verdict := deny_for("input") if {
	input.intervention_point == "input"
	target_has_sentinel
}

pre_model_call_verdict := deny_for("pre_model_call") if {
	input.intervention_point == "pre_model_call"
	target_has_sentinel
}

post_model_call_verdict := deny_for("post_model_call") if {
	input.intervention_point == "post_model_call"
	target_has_sentinel
}

pre_tool_call_verdict := deny_for("pre_tool_call") if {
	input.intervention_point == "pre_tool_call"
	input.tool.name == "danger_tool"
}

pre_tool_call_verdict := deny_for("pre_tool_call") if {
	input.intervention_point == "pre_tool_call"
	target_has_sentinel
}

post_tool_call_verdict := deny_for("post_tool_call") if {
	input.intervention_point == "post_tool_call"
	input.tool.name == "danger_tool"
}

post_tool_call_verdict := deny_for("post_tool_call") if {
	input.intervention_point == "post_tool_call"
	target_has_sentinel
}

output_verdict := deny_for("output") if {
	input.intervention_point == "output"
	target_has_sentinel
}

agent_shutdown_verdict := deny_for("agent_shutdown") if {
	input.intervention_point == "agent_shutdown"
	target_has_sentinel
}
