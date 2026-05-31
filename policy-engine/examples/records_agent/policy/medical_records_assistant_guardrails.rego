package agent_control_specification.medical_records_assistant_guardrails

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

post_model_call_verdict := {
    "decision": "transform",
    "reason": "phi_redacted",
    "message": "",
    "transform": {
        "path": "$policy_target.value",
        "value": "[REDACTED PHI]"
    }
} if {
    input.intervention_point == "post_model_call"
    input.intervention_point == "post_model_call"
    input.annotations.phi_scan == "phi_present"
}

pre_tool_call_verdict := {
    "decision": "deny",
    "reason": "deny",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "fetch_record"
    input.annotations.access_scope == "unauthorized"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "fetch_record"
    input.annotations.access_scope == "sensitive_record"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "export_data"
}

post_tool_call_verdict := {
    "decision": "transform",
    "reason": "phi_redacted",
    "message": "",
    "transform": {
        "path": "$policy_target.value",
        "value": "[REDACTED PHI]"
    }
} if {
    input.intervention_point == "post_tool_call"
    input.intervention_point == "post_tool_call"
    input.annotations.phi_scan == "phi_present"
}

output_verdict := {
    "decision": "transform",
    "reason": "phi_redacted",
    "message": "",
    "transform": {
        "path": "$policy_target.value",
        "value": "[REDACTED PHI]"
    }
} if {
    input.intervention_point == "output"
    input.intervention_point == "output"
    input.annotations.phi_scan == "phi_present"
}
