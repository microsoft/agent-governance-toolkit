package acs.demo

import rego.v1

# Comprehensive demo policy exercised by all four SDKs.
#
# Decisions demonstrated:
#   allow      - default, benign traffic
#   deny       - target (or tool name) trips a hard block
#   transform  - target carries a secret and is rewritten (AGT transform verdict)
#   warn       - target asks for a soft warning, value is left unchanged
#
# Sentinels (case-sensitive, matched against the JSON-encoded policy target):
#   "BLOCKME"  -> deny
#   "SECRET"   -> transform (redact)
#   "WARNME"   -> warn
# Tool name "danger_tool" is always denied at pre_tool_call.

default verdict := {"decision": "allow"}
default agent_startup_verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_model_call_verdict := {"decision": "allow"}
default post_model_call_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}
default agent_shutdown_verdict := {"decision": "allow"}

encoded := json.marshal(input.policy_target.value)

has_block if contains(encoded, "BLOCKME")
has_secret if contains(encoded, "SECRET")
has_warn if contains(encoded, "WARNME")

deny_for(point) := {
	"decision": "deny",
	"reason": sprintf("%s_blocked", [point]),
	"message": sprintf("Demo policy denied %s because the target contained BLOCKME.", [point]),
}

# Redact the entire policy target value. Works for string and object targets.
redact_for(point) := {
	"decision": "transform",
	"reason": sprintf("%s_redacted", [point]),
	"message": sprintf("Demo policy redacted a secret at %s.", [point]),
	"transform": {
		"path": "$policy_target",
		"value": "[REDACTED BY POLICY]",
	},
}

warn_for(point) := {
	"decision": "warn",
	"reason": sprintf("%s_warned", [point]),
	"message": sprintf("Demo policy warned at %s; value left unchanged.", [point]),
}

# ---- input ----
input_verdict := deny_for("input") if { input.intervention_point == "input"; has_block }
input_verdict := redact_for("input") if { input.intervention_point == "input"; not has_block; has_secret }
input_verdict := warn_for("input") if { input.intervention_point == "input"; not has_block; not has_secret; has_warn }

# ---- pre_model_call ----
pre_model_call_verdict := deny_for("pre_model_call") if { input.intervention_point == "pre_model_call"; has_block }

# ---- post_model_call ----
post_model_call_verdict := redact_for("post_model_call") if { input.intervention_point == "post_model_call"; not has_block; has_secret }
post_model_call_verdict := deny_for("post_model_call") if { input.intervention_point == "post_model_call"; has_block }

# ---- pre_tool_call ----
pre_tool_call_verdict := deny_for("pre_tool_call") if { input.intervention_point == "pre_tool_call"; input.tool.name == "danger_tool" }
pre_tool_call_verdict := deny_for("pre_tool_call") if { input.intervention_point == "pre_tool_call"; has_block }

# ---- post_tool_call ----
post_tool_call_verdict := redact_for("post_tool_call") if { input.intervention_point == "post_tool_call"; not has_block; has_secret }
post_tool_call_verdict := deny_for("post_tool_call") if { input.intervention_point == "post_tool_call"; has_block }

# ---- output ----
output_verdict := deny_for("output") if { input.intervention_point == "output"; has_block }
output_verdict := redact_for("output") if { input.intervention_point == "output"; not has_block; has_secret }

# Generic dispatch (kept in sync for hosts that bind a single verdict rule).
verdict := agent_startup_verdict if { input.intervention_point == "agent_startup" }
verdict := input_verdict if { input.intervention_point == "input" }
verdict := pre_model_call_verdict if { input.intervention_point == "pre_model_call" }
verdict := post_model_call_verdict if { input.intervention_point == "post_model_call" }
verdict := pre_tool_call_verdict if { input.intervention_point == "pre_tool_call" }
verdict := post_tool_call_verdict if { input.intervention_point == "post_tool_call" }
verdict := output_verdict if { input.intervention_point == "output" }
verdict := agent_shutdown_verdict if { input.intervention_point == "agent_shutdown" }
