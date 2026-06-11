use agent_control_specification::AgentControl;
use agent_control_specification::JsonValue;
use agent_control_specification_openai::{AgentControlOpenAiExt, OpenAiGuardError};
use async_openai::types::chat::{ChatCompletionMessageToolCall, FunctionCall};
use serde_json::{json, Value};

fn smoke_control() -> AgentControl {
    AgentControl::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/smoke/manifest.yaml"
    ))
    .unwrap()
}

fn tool_call(name: &str, args: Value) -> ChatCompletionMessageToolCall {
    ChatCompletionMessageToolCall {
        id: "call_1".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

#[tokio::test]
async fn real_openai_tool_call_enforces_pre_and_post_tool_call() {
    let guarded = smoke_control().guard_openai_tool_executor(|args: JsonValue| async move {
        if args["response_mode"].as_str() == Some("blocked_output") {
            Ok(json!("BLOCKME returned by real async-openai tool path"))
        } else {
            Ok(json!(format!(
                "echo: {}",
                args["message"].as_str().unwrap_or_default()
            )))
        }
    });

    let allowed = guarded
        .call(tool_call("echo_tool", json!({ "message": "hello" })))
        .await
        .unwrap();
    assert!(serde_json::to_string(&allowed)
        .unwrap()
        .contains("echo: hello"));

    let pre = guarded
        .call(tool_call(
            "echo_tool",
            json!({ "message": "BLOCKME only in args" }),
        ))
        .await
        .unwrap_err();
    assert!(pre.to_string().contains("pre_tool_call"));

    let post = guarded
        .call(tool_call(
            "echo_tool",
            json!({ "message": "hello", "response_mode": "blocked_output" }),
        ))
        .await
        .unwrap_err();
    assert!(post.to_string().contains("post_tool_call"));

    let danger = guarded
        .call(tool_call("danger_tool", json!({ "message": "hello" })))
        .await;
    assert!(danger.is_err() || matches!(danger, Err(OpenAiGuardError::Blocked { .. })));
}
