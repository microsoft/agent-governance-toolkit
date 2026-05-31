package agent_control_specification.software_engineering_assistant_guardrails

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
else := {
    "decision": "deny",
    "reason": "deny",
    "message": ""
} if {
    input.intervention_point == "input"
    input.intervention_point == "input"
    input.annotations.input_risk == "secret_exfiltration"
}

pre_tool_call_verdict := {
    "decision": "deny",
    "reason": "deny",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "run_shell"
    input.annotations.shell_command_risk == "destructive"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "run_shell"
    input.annotations.shell_command_risk == "outside_workspace_write"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "run_shell"
    input.annotations.shell_command_risk == "package_install"
}
else := {
    "decision": "escalate",
    "reason": "escalate",
    "message": ""
} if {
    input.intervention_point == "pre_tool_call"
    input.intervention_point == "pre_tool_call"
    input.tool.name == "write_file"
    input.annotations.write_path_risk == "outside_workspace"
}

post_tool_call_verdict := {
    "decision": "transform",
    "reason": "secret_redacted",
    "message": "",
    "transform": {
        "path": "$policy_target",
        "value": "[REDACTED_SECRET]"
    }
} if {
    input.intervention_point == "post_tool_call"
    input.intervention_point == "post_tool_call"
    input.annotations.secret_scan == "secret_present"
}

output_verdict := {
    "decision": "transform",
    "reason": "secret_redacted",
    "message": "",
    "transform": {
        "path": "$policy_target",
        "value": "[REDACTED_SECRET]"
    }
} if {
    input.intervention_point == "output"
    input.intervention_point == "output"
    input.annotations.secret_scan == "secret_present"
}
else := {
    "decision": "allow",
    "reason": "allow",
    "message": ""
} if {
    input.intervention_point == "output"
    input.intervention_point == "output"
}
