# Ported from AgentShield/examples/policies/channel-governance/whatsapp.yaml
package agent_control_specification.cg_whatsapp

import rego.v1

default verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}

verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "message_dlp_block",
	"message": "WhatsApp session secret detected in message content.",
} if {
	input.intervention_point == "pre_tool_call"
	message_dlp_secret_present
} else := {
	"decision": "deny",
	"reason": "dangerous_channel_operation",
	"message": "WhatsApp destination or resource is not on the allowlist.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	dangerous_operation
} else := {
	"decision": "deny",
	"reason": "channel_resource_not_allowlisted",
	"message": "WhatsApp destination or resource is not on the allowlist.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	not destination_allowed
} else := {
	"decision": "deny",
	"reason": "channel_operation_not_allowlisted",
	"message": "WhatsApp destination or resource is not on the allowlist.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	not operation_allowlisted
} else := {
	"decision": "escalate",
	"reason": "channel_operation_requires_approval",
	"message": "WhatsApp messaging or media operation requires human approval.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	approval_operation
}

args := object.get(object.get(input, "policy_target", {}), "value", {})
tool_name := object.get(object.get(input, "tool", {}), "name", "")
destination := object.get(args, "destination", "")
operation := lower(sprintf("%v", [object.get(args, "operation", "send")]))
annotations := object.get(input, "annotations", {})
message_dlp := object.get(annotations, "message_dlp", {})

message_dlp_secret_present if object.get(message_dlp, "secret_present", false) == true

message_dlp_secret_present if object.get(message_dlp, "category", "") == "whatsapp_session_secret"

is_channel_tool if tool_name in {"whatsapp.send_message", "whatsapp.credential_store"}

destination_allowed if destination in {"+15550202020", "+15550202021", "ops-group"}

operation_allowlisted if operation in {"media", "send"}

approval_operation if operation in {"media", "send"}

dangerous_operation if operation in {"credential_store", "session_write", "admin"}

dangerous_operation if tool_name == "whatsapp.credential_store"

