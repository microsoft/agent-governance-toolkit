package agent_control_specification.web_research_agent_guardrails

import rego.v1

SECRET_PATTERN := "(API_KEY|TOKEN|SECRET)=[A-Za-z0-9_-]+"

default verdict := {"decision": "allow"}
default agent_startup_verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_model_call_verdict := {"decision": "allow"}
default post_model_call_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}
default agent_shutdown_verdict := {"decision": "allow"}

verdict := agent_startup_verdict if { input.intervention_point == "agent_startup" }
verdict := input_verdict if { input.intervention_point == "input" }
verdict := pre_model_call_verdict if { input.intervention_point == "pre_model_call" }
verdict := post_model_call_verdict if { input.intervention_point == "post_model_call" }
verdict := pre_tool_call_verdict if { input.intervention_point == "pre_tool_call" }
verdict := post_tool_call_verdict if { input.intervention_point == "post_tool_call" }
verdict := output_verdict if { input.intervention_point == "output" }
verdict := agent_shutdown_verdict if { input.intervention_point == "agent_shutdown" }

input_verdict := {
    "decision": "deny",
    "reason": "deny",
    "message": ""
} if {
    input.intervention_point == "input"
    input.intervention_point == "input"
    input.annotations.input_risk == "prompt_injection"
}

pre_tool_call_verdict := {
    "decision": "deny",
    "reason": "deny",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "http_fetch"
    input.annotations.url_scope == "disallowed_domain"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "http_fetch"
    input.annotations.url_scope == "sensitive_domain"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "post_webhook"
}

# Redaction is tried before the size warning. The other order lets a large
# result carrying a secret take the warn branch, and warn does not change the
# value, so the secret reaches the caller.
post_tool_call_verdict := {
    "decision": "transform",
    "reason": "secret_redacted",
    "message": "",
    "transform": {
        "path": "$target",
        "value": redacted
    }
} if {
    input.intervention_point == "post_tool_call"
    input.annotations.secret_scan == "secret_present"
    is_string(input.policy_target.value)
    # regex.replace rewrites every match. Redacting only the first left any
    # later secret in the same string untouched.
    redacted := regex.replace(input.policy_target.value, SECRET_PATTERN, "[REDACTED_SECRET]")
    redacted != input.policy_target.value
}
else := {
    "decision": "warn",
    "reason": "warn",
    "message": ""
} if {
    input.intervention_point == "post_tool_call"
    input.annotations.content_size == "very_large"
}

output_verdict := {
    "decision": "warn",
    "reason": "warn",
    "message": ""
} if {
    input.intervention_point == "output"
    input.intervention_point == "output"
    input.annotations.content_size == "very_large"
}
else := {
    "decision": "transform",
    "reason": "secret_redacted",
    "message": "",
    "transform": {
        "path": "$target",
        "value": redacted
    }
} if {
    input.intervention_point == "output"
    input.intervention_point == "output"
    input.annotations.secret_scan == "secret_present"
    is_string(input.policy_target.value)
    matches := regex.find_n("(API_KEY|TOKEN|SECRET)=[A-Za-z0-9_-]+", input.policy_target.value, 1)
    count(matches) > 0
    redacted := replace(input.policy_target.value, matches[0], "[REDACTED_SECRET]")
}
