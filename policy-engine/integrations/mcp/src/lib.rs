use std::future::Future;

use agent_control_specification::{
    AgentControl, AgentControlInterruption, JsonValue, ToolRunOptions,
};
use rmcp::{
    handler::server::ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, IntoContents, JsonObject, ListToolsResult,
        PaginatedRequestParams, ServerInfo, Tool,
    },
    service::{MaybeSendFuture, RequestContext, RoleServer},
    ErrorData as McpError,
};

pub struct GuardedMcpToolExecutor<E> {
    control: AgentControl,
    execute: E,
}

impl<E> GuardedMcpToolExecutor<E> {
    pub fn new(control: AgentControl, execute: E) -> Self {
        Self { control, execute }
    }

    pub async fn call<Fut>(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, McpGuardError>
    where
        E: Fn(JsonValue) -> Fut,
        Fut: Future<Output = Result<JsonValue, McpGuardError>>,
    {
        let args = JsonValue::Object(request.arguments.clone().unwrap_or_default());
        let (effective_args, _) = self
            .control
            .pre_tool_call_with_options(request.name.to_string(), args, ToolRunOptions::new())
            .map_err(|source| McpGuardError::blocked("pre_tool_call", source))?;
        let raw_result = (self.execute)(effective_args.clone()).await?;
        let (effective_output, _) = self
            .control
            .post_tool_call_with_options(
                request.name.to_string(),
                effective_args,
                raw_result,
                ToolRunOptions::new(),
            )
            .map_err(|source| McpGuardError::blocked("post_tool_call", source))?;
        Ok(CallToolResult::success(
            tool_output_text(effective_output).into_contents(),
        ))
    }
}

pub struct GuardedMcpServer<S> {
    control: AgentControl,
    inner: S,
}

impl<S> GuardedMcpServer<S> {
    pub fn new(control: AgentControl, inner: S) -> Self {
        Self { control, inner }
    }

    pub fn control(&self) -> &AgentControl {
        &self.control
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S> ServerHandler for GuardedMcpServer<S>
where
    S: ServerHandler,
{
    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.list_tools(request, context)
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = request.name.to_string();
        let args = JsonValue::Object(request.arguments.clone().unwrap_or_default());
        let options = ToolRunOptions::new();
        let (effective_args, _) = self
            .control
            .pre_tool_call_with_options(tool_name.clone(), args, options.clone())
            .map_err(|err| McpError::invalid_params(format!("pre_tool_call: {err}"), None))?;
        let effective_args_for_post = effective_args.clone();
        request.arguments = match effective_args {
            JsonValue::Object(object) => Some(object),
            value => {
                return Err(McpError::invalid_params(
                    format!("pre_tool_call produced non-object tool arguments: {value}"),
                    None,
                ));
            }
        };

        let result = self.inner.call_tool(request, context).await?;
        let raw_result = serde_json::to_value(&result).map_err(|err| {
            McpError::internal_error(format!("post_tool_call serialization failed: {err}"), None)
        })?;
        let (effective_output, _) = self
            .control
            .post_tool_call_with_options(tool_name, effective_args_for_post, raw_result, options)
            .map_err(|err| McpError::invalid_params(format!("post_tool_call: {err}"), None))?;
        serde_json::from_value(effective_output).map_err(|err| {
            McpError::internal_error(
                format!("post_tool_call deserialization failed: {err}"),
                None,
            )
        })
    }
}
pub trait AgentControlMcpExt {
    fn guard_mcp_tool_executor<E>(&self, execute: E) -> GuardedMcpToolExecutor<E>;

    fn guard_mcp_server<S>(&self, server: S) -> GuardedMcpServer<S>;
}

impl AgentControlMcpExt for AgentControl {
    fn guard_mcp_tool_executor<E>(&self, execute: E) -> GuardedMcpToolExecutor<E> {
        GuardedMcpToolExecutor::new(self.clone(), execute)
    }

    fn guard_mcp_server<S>(&self, server: S) -> GuardedMcpServer<S> {
        GuardedMcpServer::new(self.clone(), server)
    }
}

pub fn params(
    name: impl Into<std::borrow::Cow<'static, str>>,
    arguments: JsonObject,
) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = Some(arguments);
    params
}

fn tool_output_text(value: JsonValue) -> String {
    match value {
        JsonValue::String(text) => text,
        value => value.to_string(),
    }
}

#[derive(Debug)]
pub enum McpGuardError {
    Blocked {
        point: &'static str,
        source: AgentControlInterruption,
    },
    Tool {
        message: String,
    },
}

impl McpGuardError {
    fn blocked(point: &'static str, source: AgentControlInterruption) -> Self {
        Self::Blocked { point, source }
    }

    pub fn tool(message: impl Into<String>) -> Self {
        Self::Tool {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for McpGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked { point, source } => write!(f, "{point}: {source}"),
            Self::Tool { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for McpGuardError {}
