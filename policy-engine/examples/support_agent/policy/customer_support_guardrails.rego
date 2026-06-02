package agent_control_specification.customer_support_guardrails

import rego.v1

default verdict := {"decision": "allow"}
default agent_startup_verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_model_call_verdict := {"decision": "allow"}
default post_model_call_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}
default agent_shutdown_verdict := {"decision": "allow"}

# AGT-DELTA D1.3: multi-pattern redaction (email + phone + card) is a
# stateful operation that does not fit a single Transform verdict's
# {path, value} body. Until the AGT D1.3 follow-up moves multi-pattern
# redaction into an annotator that pre-processes the policy target, the
# policy MUST deny when PII is detected at post_tool_call / output.

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
    input.tool.name == "issue_refund"
    input.annotations.refund_risk == "fraudulent"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "issue_refund"
    input.annotations.refund_risk == "high_value"
}
else := {
    "decision": "warn",
    "reason": "warn",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "send_email"
    input.annotations.recipient_scope == "external"
}

post_tool_call_verdict := {
    "decision": "deny",
    "reason": "pii_detected",
    "message": "Tool result contains PII (email/phone/card) and multi-pattern redaction is not yet expressible as a single AGT D1.1 transform."
} if {
    input.intervention_point == "post_tool_call"
    input.intervention_point == "post_tool_call"
    input.annotations.pii_scan == "pii_present"
}

output_verdict := {
    "decision": "deny",
    "reason": "pii_detected",
    "message": "Output contains PII (email/phone/card) and multi-pattern redaction is not yet expressible as a single AGT D1.1 transform."
} if {
    input.intervention_point == "output"
    input.intervention_point == "output"
    input.annotations.pii_scan == "pii_present"
}
