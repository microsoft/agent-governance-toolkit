# Ported from AgentShield examples/policies/endpoint-governance.yaml
#
# Endpoint allowlist is represented as one synthetic ACS tool, http.request.
# The host snapshot for http.request must provide args {"method": "...", "path": "..."}.
# api_tier is endpoint-derived state from GET /api/v1/users/{user_id}; ACS is
# stateless, so the host supplies it as snapshot.api_tier on each evaluation.
package agent_control_specification.endpoint_governance

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"
verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

input_text := object.get(object.get(input.policy_target, "value", {}), "text", "")
args := object.get(object.get(input, "policy_target", {}), "value", {})
snapshot := object.get(input, "snapshot", {})
method := upper(object.get(args, "method", ""))
path := object.get(args, "path", "")

input_verdict := {
	"decision": "deny",
	"reason": "sql_injection_block",
	"message": "SQL injection attempt detected in user input.",
} if {
	input.intervention_point == "input"
	regex.match(`(?i)(drop|delete|truncate)\s+(table|database)`, input_text)
}

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "admin_endpoint_forbidden",
	"message": "Admin endpoints are forbidden.",
} if {
	is_http_request
	regex.match(`^/admin/.*$`, path)
} else := {
	"decision": "deny",
	"reason": "user_modify_requires_admin_tier",
	"message": "Only admin-tier access can modify users.",
} if {
	is_user_modify
	object.get(snapshot, "api_tier", null) != "admin"
} else := {
	"decision": "deny",
	"reason": "endpoint_not_on_allowlist",
	"message": "Endpoint not on the allowlist.",
} if {
	is_http_request
	not endpoint_allowed
} else := {
	"decision": "escalate",
	"reason": "user_profile_modify_requires_approval",
	"message": "User profile modification requires approval.",
} if {
	is_user_modify
	object.get(snapshot, "api_tier", null) == "admin"
} else := {
	"decision": "escalate",
	"reason": "payment_requires_approval",
	"message": "Payment endpoint requires approval.",
} if {
	is_payment_post
} else := {
	"decision": "warn",
	"reason": "internal_api_audit",
	"message": "Internal API call audit warning.",
} if {
	is_internal
}

is_http_request if input.tool.name == "http.request"

is_user_path if regex.match(`^/api/v1/users/[^/]+$`, path)
is_payment_path if regex.match(`^/api/v1/payments/[^/]+$`, path)
is_internal if regex.match(`^/internal/.*$`, path)
is_user_modify if { is_http_request; is_user_path; method in {"PUT", "DELETE"} }
is_payment_post if { is_http_request; is_payment_path; method == "POST" }

endpoint_allowed if { is_http_request; path == "/api/v1/health"; method == "GET" }
endpoint_allowed if { is_http_request; is_user_path; method == "GET" }
endpoint_allowed if { is_user_modify }
endpoint_allowed if { is_payment_post }
endpoint_allowed if { is_http_request; is_internal }
