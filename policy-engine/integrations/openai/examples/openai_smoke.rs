use agent_control_specification::AgentControl;
use agent_control_specification::JsonValue;
use agent_control_specification_openai::GuardedOpenAiToolExecutor;
use async_openai::types::chat::{ChatCompletionMessageToolCall, FunctionCall};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let control = AgentControl::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/smoke/manifest.yaml"
    ))?;
    let guarded = GuardedOpenAiToolExecutor::new(control, |args: JsonValue| async move {
        if args["response_mode"].as_str() == Some("blocked_output") {
            Ok::<_, agent_control_specification_openai::OpenAiGuardError>(json!(
                "BLOCKME returned by real async-openai tool path"
            ))
        } else {
            Ok::<_, agent_control_specification_openai::OpenAiGuardError>(json!(format!(
                "echo: {}",
                args["message"].as_str().unwrap_or_default()
            )))
        }
    });

    let allowed = guarded.call(tool_call("hello")).await?;
    assert!(serde_json::to_string(&allowed)?.contains("echo: hello"));

    let blocked = guarded
        .call(tool_call("BLOCKME only in args"))
        .await
        .unwrap_err();
    assert!(blocked.to_string().contains("pre_tool_call"));

    let post = guarded
        .call(tool_call_with_mode("hello", "blocked_output"))
        .await
        .unwrap_err();
    assert!(post.to_string().contains("post_tool_call"));
    Ok(())
}

fn tool_call(message: &str) -> ChatCompletionMessageToolCall {
    ChatCompletionMessageToolCall {
        id: "call_1".to_string(),
        function: FunctionCall {
            name: "echo_tool".to_string(),
            arguments: json!({ "message": message }).to_string(),
        },
    }
}

fn tool_call_with_mode(message: &str, response_mode: &str) -> ChatCompletionMessageToolCall {
    ChatCompletionMessageToolCall {
        id: "call_2".to_string(),
        function: FunctionCall {
            name: "echo_tool".to_string(),
            arguments: json!({ "message": message, "response_mode": response_mode }).to_string(),
        },
    }
}
