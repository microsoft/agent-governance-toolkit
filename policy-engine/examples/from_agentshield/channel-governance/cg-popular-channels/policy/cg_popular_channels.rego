# Ported from AgentShield/examples/policies/channel-governance/popular-channels.yaml
package agent_control_specification.cg_popular_channels

import rego.v1

default verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}

verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "message_dlp_block",
	"message": "Messaging-channel provider token detected in message content.",
} if {
	input.intervention_point == "pre_tool_call"
	message_dlp_secret_present
} else := {
	"decision": "deny",
	"reason": "dangerous_channel_operation",
	"message": "Messaging channel destination or operation is not on the allowlist.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	dangerous_operation
} else := {
	"decision": "deny",
	"reason": "channel_resource_not_allowlisted",
	"message": "Messaging channel destination or operation is not on the allowlist.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	not destination_allowed
} else := {
	"decision": "deny",
	"reason": "channel_operation_not_allowlisted",
	"message": "Messaging channel destination or operation is not on the allowlist.",
} if {
	input.intervention_point == "pre_tool_call"
	is_channel_tool
	not operation_allowlisted
} else := {
	"decision": "escalate",
	"reason": "channel_operation_requires_approval",
	"message": "Outbound messaging-channel operation requires human approval.",
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

message_dlp_secret_present if object.get(message_dlp, "category", "") == "provider_token"

is_channel_tool if tool_name in {"channel.send_message"}

destination_allowed if destination in {"slack:engineering", "discord:incident-response", "google_chat:spaces/support", "imessage:ops-oncall", "signal:+15550101010", "telegram:@ops_bot", "whatsapp:+15550202020"}

operation_allowlisted if operation in {"send", "read", "edit", "media"}

approval_operation if operation in {"send", "read", "edit", "media"}

dangerous_operation if operation in {"delete", "admin", "credential_store"}

