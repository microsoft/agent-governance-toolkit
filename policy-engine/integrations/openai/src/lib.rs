use std::future::Future;

use agent_control_specification::{
    AgentControl, AgentControlInterruption, JsonValue, ToolRunOptions,
};
use async_openai::types::chat::{
    ChatCompletionMessageToolCall, ChatCompletionMessageToolCalls, ChatCompletionRequestMessage,
    ChatCompletionRequestToolMessage, ChatCompletionRequestToolMessageContent,
};

pub struct GuardedOpenAiToolExecutor<E> {
    control: AgentControl,
    execute: E,
}

impl<E> GuardedOpenAiToolExecutor<E> {
    pub fn new(control: AgentControl, execute: E) -> Self {
        Self { control, execute }
    }

    pub async fn call<Fut>(
        &self,
        tool_call: ChatCompletionMessageToolCall,
    ) -> Result<ChatCompletionRequestMessage, OpenAiGuardError>
    where
        E: Fn(JsonValue) -> Fut,
        Fut: Future<Output = Result<JsonValue, OpenAiGuardError>>,
    {
        let args = parse_arguments(&tool_call.function.arguments)?;
        let options = ToolRunOptions::new().with_tool_call_id(tool_call.id.clone());
        let (effective_args, _) = self
            .control
            .pre_tool_call_with_options(tool_call.function.name.clone(), args, options.clone())
            .map_err(|source| OpenAiGuardError::blocked("pre_tool_call", source))?;
        let raw_output = (self.execute)(effective_args.clone()).await?;
        let (effective_output, _) = self
            .control
            .post_tool_call_with_options(
                tool_call.function.name,
                effective_args,
                raw_output,
                options,
            )
            .map_err(|source| OpenAiGuardError::blocked("post_tool_call", source))?;
        Ok(ChatCompletionRequestMessage::Tool(
            ChatCompletionRequestToolMessage {
                content: ChatCompletionRequestToolMessageContent::Text(tool_output_text(
                    effective_output,
                )),
                tool_call_id: tool_call.id,
            },
        ))
    }
}

pub trait AgentControlOpenAiExt {
    fn guard_openai_tool_executor<E>(&self, execute: E) -> GuardedOpenAiToolExecutor<E>;
}

impl AgentControlOpenAiExt for AgentControl {
    fn guard_openai_tool_executor<E>(&self, execute: E) -> GuardedOpenAiToolExecutor<E> {
        GuardedOpenAiToolExecutor::new(self.clone(), execute)
    }
}

pub fn function_tool_call(
    call: ChatCompletionMessageToolCalls,
) -> Option<ChatCompletionMessageToolCall> {
    match call {
        ChatCompletionMessageToolCalls::Function(call) => Some(call),
        ChatCompletionMessageToolCalls::Custom(_) => None,
    }
}

fn parse_arguments(arguments: &str) -> Result<JsonValue, OpenAiGuardError> {
    serde_json::from_str(arguments).map_err(|source| OpenAiGuardError::MalformedArguments {
        message: source.to_string(),
    })
}

fn tool_output_text(value: JsonValue) -> String {
    match value {
        JsonValue::String(text) => text,
        value => value.to_string(),
    }
}

#[derive(Debug)]
pub enum OpenAiGuardError {
    Blocked {
        point: &'static str,
        source: AgentControlInterruption,
    },
    MalformedArguments {
        message: String,
    },
    Tool {
        message: String,
    },
}

impl OpenAiGuardError {
    fn blocked(point: &'static str, source: AgentControlInterruption) -> Self {
        Self::Blocked { point, source }
    }

    pub fn tool(message: impl Into<String>) -> Self {
        Self::Tool {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for OpenAiGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked { point, source } => write!(f, "{point}: {source}"),
            Self::MalformedArguments { message } => {
                write!(f, "malformed tool arguments: {message}")
            }
            Self::Tool { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for OpenAiGuardError {}
