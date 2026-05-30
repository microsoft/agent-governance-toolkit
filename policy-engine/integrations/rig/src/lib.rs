//! Real [Rig](https://docs.rig.rs) integration for Agent Control Specification.
//!
//! Wraps a Rig tool so its arguments and output flow through the
//! `pre_tool_call` / `post_tool_call` intervention points. The wrapper
//! implements [`rig::tool::ToolDyn`] directly, so transformed arguments reach
//! the inner tool before Rig dispatches it — full mutation coverage rather than
//! the advisory-only behaviour of a prompt hook.
//!
//! Enforcement matches the rest of the SDK family. A `deny` verdict blocks the
//! call. An `escalate` verdict consults an approval resolver, either a per-tool
//! override set with [`GuardedRigTool::with_approval_resolver`] or the
//! [`AgentControl`] instance resolver. With no resolver an `escalate` verdict
//! fails closed to a block.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use agent_control_specification::{
    AgentControl, AgentControlInterruption, ApprovalResolver, EnforcementMode, JsonValue,
    ToolRunOptions,
};
use rig::completion::ToolDefinition;
use rig::tool::{ToolDyn, ToolError};

/// A Rig tool whose calls are guarded by Agent Control intervention points.
pub struct GuardedRigTool {
    control: AgentControl,
    inner: Arc<dyn ToolDyn>,
    mode: EnforcementMode,
    approval_resolver: Option<ApprovalResolver>,
}

impl GuardedRigTool {
    /// Guards `inner` in [`EnforcementMode::Enforce`].
    pub fn new<T>(control: AgentControl, inner: T) -> Self
    where
        T: ToolDyn + 'static,
    {
        Self::from_arc(control, Arc::new(inner))
    }

    /// Guards a shared tool instance in [`EnforcementMode::Enforce`].
    pub fn from_arc(control: AgentControl, inner: Arc<dyn ToolDyn>) -> Self {
        Self {
            control,
            inner,
            mode: EnforcementMode::Enforce,
            approval_resolver: None,
        }
    }

    /// Overrides the enforcement mode (defaults to [`EnforcementMode::Enforce`]).
    pub fn with_mode(mut self, mode: EnforcementMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets a per-tool approval resolver consulted for `escalate` verdicts.
    ///
    /// When unset the [`AgentControl`] instance resolver is consulted instead.
    pub fn with_approval_resolver(mut self, approval_resolver: ApprovalResolver) -> Self {
        self.approval_resolver = Some(approval_resolver);
        self
    }
}

/// Adds Rig tool wrapping helpers to [`AgentControl`].
pub trait AgentControlRigExt {
    fn guard_rig_tool(&self, tool: Arc<dyn ToolDyn>) -> GuardedRigTool;

    fn guard_rig_tools(&self, tools: Vec<Arc<dyn ToolDyn>>) -> Vec<Box<dyn ToolDyn>>;
}

impl AgentControlRigExt for AgentControl {
    fn guard_rig_tool(&self, tool: Arc<dyn ToolDyn>) -> GuardedRigTool {
        GuardedRigTool::from_arc(self.clone(), tool)
    }

    fn guard_rig_tools(&self, tools: Vec<Arc<dyn ToolDyn>>) -> Vec<Box<dyn ToolDyn>> {
        tools
            .into_iter()
            .map(|tool| Box::new(GuardedRigTool::from_arc(self.clone(), tool)) as Box<dyn ToolDyn>)
            .collect()
    }
}

impl ToolDyn for GuardedRigTool {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn definition<'a>(
        &'a self,
        prompt: String,
    ) -> Pin<Box<dyn Future<Output = ToolDefinition> + Send + 'a>> {
        self.inner.definition(prompt)
    }

    fn call<'a>(
        &'a self,
        args: String,
    ) -> Pin<Box<dyn Future<Output = Result<String, ToolError>> + Send + 'a>> {
        let control = self.control.clone();
        let inner = self.inner.clone();
        let mode = self.mode;
        let resolver = self.approval_resolver.clone();
        let name = self.inner.name();
        Box::pin(async move {
            let raw_args: JsonValue = serde_json::from_str(&args)?;
            let mut options = ToolRunOptions::new().with_mode(mode);
            if let Some(resolver) = resolver {
                options = options.with_approval_resolver(resolver);
            }

            let (effective_args, _) = control
                .pre_tool_call_with_options(name.clone(), raw_args, options.clone())
                .map_err(|interruption| guardrail_error("pre_tool_call", &name, interruption))?;

            let output = inner.call(serde_json::to_string(&effective_args)?).await?;

            // Rig tool output is an opaque string; expose it as such to policies.
            let raw_output = JsonValue::String(output);
            let (effective_output, _) = control
                .post_tool_call_with_options(name.clone(), effective_args, raw_output, options)
                .map_err(|interruption| guardrail_error("post_tool_call", &name, interruption))?;

            Ok(match effective_output {
                JsonValue::String(text) => text,
                value => value.to_string(),
            })
        })
    }
}

/// Maps a policy interruption onto a Rig [`ToolError`].
///
/// Rig tools may only fail with a [`ToolError`], so both a block and an approval
/// suspension surface as a tool-call error; the message distinguishes them.
fn guardrail_error(point: &str, tool: &str, interruption: AgentControlInterruption) -> ToolError {
    let verdict = &interruption.intervention_point_result().verdict;
    let reason = verdict.message.clone().or_else(|| verdict.reason.clone());
    let detail = match &interruption {
        AgentControlInterruption::Blocked(_) => {
            reason.unwrap_or_else(|| "blocked by policy".to_string())
        }
        AgentControlInterruption::Suspended(_) => {
            reason.unwrap_or_else(|| "suspended pending approval".to_string())
        }
    };
    ToolError::ToolCallError(
        format!("[Agent Control] {point} blocked tool '{tool}': {detail}").into(),
    )
}
