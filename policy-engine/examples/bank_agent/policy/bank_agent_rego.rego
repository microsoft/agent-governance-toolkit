package agent_control_specification.bank_agent_rego

import rego.v1

# Parity demo policy template. The manifest binds each intervention point to
# its matching <point>_verdict query; verdict is a generic dispatch query.
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
    "reason": "input_classifier_high_risk",
    "message": "The request is too risky for this demo bank agent."
} if {
    input.intervention_point == "input"
    input.annotations.prompt_classifier.risk_score >= 0.95
}

pre_model_call_verdict := {
    "decision": "transform",
    "reason": "large_transfer_instruction_added",
    "message": "A high-value transfer reminder was added before the model call.",
    "transform": {
        "path": "$policy_target.messages",
        "value": array.concat(input.policy_target.value.messages, [{
            "role": "system",
            "content": "Do not execute high-value transfers without explicit approval."
        }])
    }
} if {
    input.intervention_point == "pre_model_call"
    input.annotations.model_request_classifier.contains_large_transfer == true
}

post_model_call_verdict := {
    "decision": "deny",
    "reason": "model_suggested_approval_bypass",
    "message": "The model response suggested bypassing an approval path."
} if {
    input.intervention_point == "post_model_call"
    contains(lower(input.policy_target.value.message.content), "bypass approval")
}

pre_tool_call_verdict := {
    "decision": "escalate",
    "reason": "large_wire_transfer_requires_review",
    "message": "Wire transfers of 10000 or more require a human approval route."
} if {
    input.intervention_point == "pre_tool_call"
    input.tool.name == "wire_transfer"
    input.policy_target.value.amount >= 10000
}

post_tool_call_verdict := {
    "decision": "transform",
    "reason": "tool_result_account_identifier_redacted",
    "message": "The account identifier was redacted before the result returned to the agent.",
    "transform": {
        "path": "$policy_target.account_id",
        "value": "ACCOUNT-REDACTED"
    }
} if {
    input.intervention_point == "post_tool_call"
    input.policy_target.value.account_id != ""
}

output_verdict := {
    "decision": "transform",
    "reason": "output_account_identifier_redacted",
    "message": "The final response contained an account identifier and was redacted.",
    "transform": {
        "path": "$policy_target.text",
        "value": regex.replace(input.policy_target.value.text, "CHK-[0-9]+", "ACCOUNT-REDACTED")
    }
} if {
    input.intervention_point == "output"
    matches := regex.find_n("CHK-[0-9]+", input.policy_target.value.text, 1)
    count(matches) > 0
}

agent_shutdown_verdict := {
    "decision": "warn",
    "reason": "shutdown_audit_contains_blocked_action",
    "message": "Persist the shutdown audit summary with the blocked action record."
} if {
    input.intervention_point == "agent_shutdown"
    count(input.policy_target.value.blocked_actions) > 0
}
