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
//!
//! Use [`GuardedRigTool::with_ambient_snapshot`] when policies need host context
//! beyond Rig's tool name, arguments, and result. Common examples include
//! `snapshot.ifc.source_labels`, tenant metadata, and request metadata.
//! Use [`GuardedRigTool::call_with_result`] when the host needs ACS metadata
//! from the post-tool evaluation, such as `result_labels` for later IFC
//! propagation, before erasing the value behind `dyn ToolDyn`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use agent_control_specification::{
    AgentControl, AgentControlInterruption, ApprovalResolver, EnforcementMode, JsonValue,
    ToolRunOptions, ToolRunResult,
};
use rig::completion::ToolDefinition;
use rig::tool::{ToolDyn, ToolError};
use serde_json::Map;

/// A Rig tool whose calls are guarded by Agent Control intervention points.
pub struct GuardedRigTool {
    control: AgentControl,
    inner: Arc<dyn ToolDyn>,
    options: ToolRunOptions,
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
            options: ToolRunOptions::new(),
        }
    }

    /// Replaces the full set of tool-run options used for every Rig call.
    pub fn with_tool_run_options(mut self, options: ToolRunOptions) -> Self {
        self.options = options;
        self
    }

    /// Overrides the enforcement mode (defaults to [`EnforcementMode::Enforce`]).
    pub fn with_mode(mut self, mode: EnforcementMode) -> Self {
        self.options = self.options.with_mode(mode);
        self
    }

    /// Adds ambient snapshot fields to every `pre_tool_call` and `post_tool_call`.
    ///
    /// Use this for host context such as `snapshot.ifc.source_labels`, tenant
    /// identifiers, or request metadata that policies need in addition to Rig's
    /// tool name, arguments, and result.
    pub fn with_ambient_snapshot(mut self, ambient_snapshot: Map<String, JsonValue>) -> Self {
        self.options = self.options.with_ambient_snapshot(ambient_snapshot);
        self
    }

    /// Sets the optional host tool-call id preserved across pre and post checks.
    pub fn with_tool_call_id(mut self, tool_call_id: impl Into<String>) -> Self {
        self.options = self.options.with_tool_call_id(tool_call_id);
        self
    }

    /// Sets a per-tool approval resolver consulted for `escalate` verdicts.
    ///
    /// When unset the [`AgentControl`] instance resolver is consulted instead.
    pub fn with_approval_resolver(mut self, approval_resolver: ApprovalResolver) -> Self {
        self.options = self.options.with_approval_resolver(approval_resolver);
        self
    }

    /// Calls the wrapped Rig tool and returns the full ACS tool result.
    ///
    /// Rig's [`ToolDyn::call`] trait method can return only a `String`. Hosts
    /// that need metadata such as `post_tool_call` result labels for stateless
    /// IFC propagation should keep the concrete [`GuardedRigTool`] value and
    /// call this method before erasing it behind `dyn ToolDyn`.
    pub async fn call_with_result(&self, args: String) -> Result<ToolRunResult<String>, ToolError> {
        let raw_args: JsonValue = serde_json::from_str(&args)?;
        let name = self.inner.name();

        let (effective_args, pre_tool_call_intervention_point_result) = self
            .control
            .pre_tool_call_with_options(name.clone(), raw_args, self.options.clone())
            .map_err(|interruption| guardrail_error("pre_tool_call", &name, interruption))?;

        let output = self
            .inner
            .call(serde_json::to_string(&effective_args)?)
            .await?;
        let raw_output = JsonValue::String(output);
        let (effective_output, post_tool_call_intervention_point_result) = self
            .control
            .post_tool_call_with_options(
                name.clone(),
                effective_args,
                raw_output,
                self.options.clone(),
            )
            .map_err(|interruption| guardrail_error("post_tool_call", &name, interruption))?;

        let value = match effective_output {
            JsonValue::String(text) => text,
            value => value.to_string(),
        };
        Ok(ToolRunResult {
            value,
            pre_tool_call_intervention_point_result,
            post_tool_call_intervention_point_result,
        })
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
        Box::pin(async move { self.call_with_result(args).await.map(|result| result.value) })
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
