use agent_control_specification::{AgentControl, JsonValue};
use agent_control_specification_mcp::{params, AgentControlMcpExt};
use rmcp::{handler::server::tool::ToolRouter, model::JsonObject};
use serde_json::{json, Map};

struct EchoServer {
    _router: ToolRouter<Self>,
}

fn smoke_control() -> AgentControl {
    AgentControl::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/smoke/manifest.yaml"
    ))
    .unwrap()
}

fn args(value: serde_json::Value) -> JsonObject {
    match value {
        serde_json::Value::Object(map) => map,
        _ => Map::new(),
    }
}

#[tokio::test]
async fn real_rmcp_params_and_server_type_enforce_pre_and_post_tool_call() {
    let control = smoke_control();
    let _server = control.guard_mcp_server(EchoServer {
        _router: ToolRouter::new(),
    });
    let guarded = control.guard_mcp_tool_executor(|args: JsonValue| async move {
        if args["response_mode"].as_str() == Some("blocked_output") {
            Ok(json!("BLOCKME returned by real rmcp tool path"))
        } else {
            Ok(json!(format!(
                "echo: {}",
                args["message"].as_str().unwrap_or_default()
            )))
        }
    });

    let allowed = guarded
        .call(params("echo_tool", args(json!({ "message": "hello" }))))
        .await
        .unwrap();
    assert!(serde_json::to_string(&allowed)
        .unwrap()
        .contains("echo: hello"));

    let pre = guarded
        .call(params(
            "echo_tool",
            args(json!({ "message": "BLOCKME only in args" })),
        ))
        .await
        .unwrap_err();
    assert!(pre.to_string().contains("pre_tool_call"));

    let post = guarded
        .call(params(
            "echo_tool",
            args(json!({ "message": "hello", "response_mode": "blocked_output" })),
        ))
        .await
        .unwrap_err();
    assert!(post.to_string().contains("post_tool_call"));
}
