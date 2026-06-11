use std::convert::Infallible;

use agent_control_specification::AgentControl;
use agent_control_specification_rig::GuardedRigTool;
use rig::completion::ToolDefinition;
use rig::tool::{Tool, ToolDyn};
use serde::Deserialize;
use serde_json::json;

#[derive(Clone, Copy)]
struct EchoTool;

#[derive(Deserialize)]
struct EchoArgs {
    message: String,
    response_mode: Option<String>,
}

impl Tool for EchoTool {
    const NAME: &'static str = "echo_tool";

    type Error = Infallible;
    type Args = EchoArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Echoes input for the ACS Rig example.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" },
                    "response_mode": { "type": "string" }
                },
                "required": ["message"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if args.response_mode.as_deref() == Some("blocked_output") {
            Ok("BLOCKME returned by real rig tool".to_string())
        } else {
            Ok(format!("echo: {}", args.message))
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let control = AgentControl::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/smoke/manifest.yaml"
    ))?;
    let guarded = GuardedRigTool::new(control, EchoTool);

    let allowed = guarded
        .call(json!({ "message": "hello" }).to_string())
        .await?;
    assert_eq!(allowed, "echo: hello");

    let pre = guarded
        .call(json!({ "message": "BLOCKME only in args" }).to_string())
        .await
        .unwrap_err();
    assert!(pre.to_string().contains("pre_tool_call"));

    let post = guarded
        .call(json!({ "message": "hello", "response_mode": "blocked_output" }).to_string())
        .await
        .unwrap_err();
    assert!(post.to_string().contains("post_tool_call"));

    Ok(())
}
