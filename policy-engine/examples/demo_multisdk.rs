// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agent_control_specification::{AgentControl, AgentControlInterruption, Decision, JsonValue};
use serde_json::json;

const MANIFEST_PATH: &str =
    "/home/liamcrumm/port/agt-acs/policy-engine/demo_multisdk/manifest.yaml";

fn reason(interruption: &AgentControlInterruption) -> String {
    interruption
        .intervention_point_result()
        .verdict
        .reason
        .clone()
        .unwrap_or_else(|| "none".to_string())
}

fn print_allow(label: &str, value: &JsonValue) {
    println!("ALLOW {label} value {value}");
}

fn print_deny(label: &str, interruption: &AgentControlInterruption) {
    println!("DENY {label} reason {}", reason(interruption));
}

fn print_xform(label: &str, value: &JsonValue) {
    println!("XFORM {label} value {value}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let control = AgentControl::from_path(MANIFEST_PATH)?;

    println!("RUST SDK");

    match control.run(json!({"text": "hello there"}), |_| json!({"reply": "hi"})) {
        Ok(result) => print_allow("run", &result.value),
        Err(interruption) => print_deny("run", &interruption),
    }

    match control.run(json!({"text": "do BLOCKME now"}), |input| input) {
        Ok(result) => print_allow("run_block", &result.value),
        Err(interruption) => print_deny("run_block", &interruption),
    }

    match control.run(json!({"text": "here is my SECRET"}), |input| input) {
        Ok(result)
            if result.input_intervention_point_result.verdict.decision == Decision::Transform =>
        {
            print_xform("run_secret", &result.value)
        }
        Ok(result) => print_allow("run_secret", &result.value),
        Err(interruption) => print_deny("run_secret", &interruption),
    }

    match control.run_tool("echo_tool", json!({"text": "ping"}), |args| args) {
        Ok(result) => print_allow("tool_echo", &result.value),
        Err(interruption) => print_deny("tool_echo", &interruption),
    }

    match control.run_tool("danger_tool", json!({}), |args| args) {
        Ok(result) => print_allow("tool_danger", &result.value),
        Err(interruption) => print_deny("tool_danger", &interruption),
    }

    match control.run_tool(
        "payments_tool",
        json!({"amt": 1}),
        |_| json!({"result": "SECRET receipt"}),
    ) {
        Ok(result)
            if result
                .post_tool_call_intervention_point_result
                .verdict
                .decision
                == Decision::Transform =>
        {
            print_xform("tool_payments", &result.value)
        }
        Ok(result) => print_allow("tool_payments", &result.value),
        Err(interruption) => print_deny("tool_payments", &interruption),
    }

    match control.run_model(
        json!({"messages": [{"role": "user", "content": "hello"}]}),
        |_| json!({"content": "all good"}),
    ) {
        Ok(result) => print_allow("model", &result.value),
        Err(interruption) => print_deny("model", &interruption),
    }

    match control.run_model(
        json!({"messages": [{"role": "user", "content": "hello"}]}),
        |_| json!({"content": "the SECRET is 42"}),
    ) {
        Ok(result)
            if result
                .post_model_call_intervention_point_result
                .verdict
                .decision
                == Decision::Transform =>
        {
            print_xform("model_secret", &result.value)
        }
        Ok(result) => print_allow("model_secret", &result.value),
        Err(interruption) => print_deny("model_secret", &interruption),
    }

    Ok(())
}
