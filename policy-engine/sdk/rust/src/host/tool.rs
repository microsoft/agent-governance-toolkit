use super::{
    AgentControl, AgentControlError, AgentControlInterruption, ToolRunOptions, ToolRunResult,
};
use crate::JsonValue;
use std::{error::Error, fmt};

#[derive(Debug, Clone)]
pub struct ProtectedTool<F> {
    control: AgentControl,
    tool_name: String,
    execute: F,
}

impl<F> ProtectedTool<F> {
    pub(super) fn new(control: AgentControl, tool_name: String, execute: F) -> Self {
        Self {
            control,
            tool_name,
            execute,
        }
    }
}

impl<F> ProtectedTool<F>
where
    F: Fn(JsonValue) -> JsonValue,
{
    pub fn name(&self) -> &str {
        &self.tool_name
    }

    pub fn run(&self, args: JsonValue) -> Result<ToolRunResult, AgentControlInterruption> {
        self.control
            .run_tool(&self.tool_name, args, |effective_args| {
                (self.execute)(effective_args)
            })
    }

    pub fn run_with_options(
        &self,
        args: JsonValue,
        options: ToolRunOptions,
    ) -> Result<ToolRunResult, AgentControlInterruption> {
        self.control
            .run_tool_with_options(&self.tool_name, args, options, |effective_args| {
                (self.execute)(effective_args)
            })
    }
}

pub trait RigLikeTool {
    type Error;

    fn name(&self) -> &str;

    fn call(&self, args: JsonValue) -> Result<JsonValue, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct GuardedRigLikeTool<T> {
    control: AgentControl,
    tool: T,
    options: ToolRunOptions,
}

impl<T> GuardedRigLikeTool<T> {
    pub(super) fn new(control: AgentControl, tool: T, options: ToolRunOptions) -> Self {
        Self {
            control,
            tool,
            options,
        }
    }

    pub fn inner(&self) -> &T {
        &self.tool
    }

    pub fn into_inner(self) -> T {
        self.tool
    }

    pub fn options(&self) -> &ToolRunOptions {
        &self.options
    }
}

impl<T> RigLikeTool for GuardedRigLikeTool<T>
where
    T: RigLikeTool,
{
    type Error = AgentControlError<T::Error>;

    fn name(&self) -> &str {
        self.tool.name()
    }

    fn call(&self, args: JsonValue) -> Result<JsonValue, Self::Error> {
        let tool_name = self.tool.name().to_string();
        self.control
            .try_run_tool_with_options(tool_name, args, self.options.clone(), |effective_args| {
                self.tool.call(effective_args)
            })
            .map(|result| result.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFrameworkAdapter {
    framework: String,
}

impl UnsupportedFrameworkAdapter {
    pub fn framework(&self) -> &str {
        &self.framework
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFrameworkAdapterError {
    framework: String,
    message: String,
}

impl UnsupportedFrameworkAdapterError {
    pub fn framework(&self) -> &str {
        &self.framework
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for UnsupportedFrameworkAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for UnsupportedFrameworkAdapterError {}

pub fn create_unsupported_framework_adapter(
    framework: impl Into<String>,
) -> Result<UnsupportedFrameworkAdapter, UnsupportedFrameworkAdapterError> {
    let framework = framework.into();
    let message = format!(
        "Agent Control framework adapter '{framework}' is intentionally deferred; use generic run_tool/protect_tool helpers for now."
    );
    Err(UnsupportedFrameworkAdapterError { framework, message })
}
