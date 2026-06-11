use agent_control_specification::{AgentControl, JsonValue};
use agent_control_specification_mcp::{params, GuardedMcpToolExecutor};
use rmcp::model::JsonObject;
use serde_json::{json, Map};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let control = AgentControl::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/smoke/manifest.yaml"
    ))?;
    let guarded = GuardedMcpToolExecutor::new(control, |args: JsonValue| async move {
        if args["response_mode"].as_str() == Some("blocked_output") {
            Ok::<_, agent_control_specification_mcp::McpGuardError>(json!(
                "BLOCKME returned by real rmcp tool path"
            ))
        } else {
            Ok::<_, agent_control_specification_mcp::McpGuardError>(json!(format!(
                "echo: {}",
                args["message"].as_str().unwrap_or_default()
            )))
        }
    });

    let allowed = guarded
        .call(params("echo_tool", args(json!({ "message": "hello" }))))
        .await?;
    assert!(serde_json::to_string(&allowed)?.contains("echo: hello"));

    let blocked = guarded
        .call(params(
            "echo_tool",
            args(json!({ "message": "BLOCKME only in args" })),
        ))
        .await
        .unwrap_err();
    assert!(blocked.to_string().contains("pre_tool_call"));
    Ok(())
}

fn args(value: serde_json::Value) -> JsonObject {
    match value {
        serde_json::Value::Object(map) => map,
        _ => Map::new(),
    }
}
