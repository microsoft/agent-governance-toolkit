use crate::{
    AnnotatorDispatcher, EnforcementMode, InterventionPoint, InterventionPointRequest,
    InterventionPointResult, JsonValue, Limits, Manifest, PolicyDispatcher, Runtime, RuntimeError,
};
use std::{convert::Infallible, fmt, path::Path, sync::Arc};

mod approval;
mod error;
mod options;
mod results;
mod snapshot;
mod tool;

pub use approval::{ApprovalOutcome, ApprovalResolution, ApprovalResolver};
pub use error::{
    AgentControlBlocked, AgentControlError, AgentControlInterruption, AgentControlSuspended,
};
pub use options::{RunOptions, ToolRunOptions};
pub use results::{ModelRunResult, RunResult, ToolRunResult};
use snapshot::{
    effective_policy_target, enforce, model_call_snapshot, snapshot_with_value,
    snapshot_with_values, tool_call_snapshot,
};
pub use tool::{
    create_unsupported_framework_adapter, GuardedRigLikeTool, ProtectedTool, RigLikeTool,
    UnsupportedFrameworkAdapter, UnsupportedFrameworkAdapterError,
};

#[derive(Clone)]
pub struct AgentControl {
    runtime: Runtime,
    approval_resolver: Option<ApprovalResolver>,
}

/// Mutable session handle passed to [`AgentControl::guard_session`]. Assign
/// [`summary`](Self::summary) inside the session body to supply the
/// `agent_shutdown` policy target. Defaults to an empty JSON object.
#[derive(Debug, Clone)]
pub struct SessionScope {
    pub summary: JsonValue,
}

impl Default for SessionScope {
    fn default() -> Self {
        Self {
            summary: JsonValue::Object(serde_json::Map::new()),
        }
    }
}

impl fmt::Debug for AgentControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentControl")
            .field("runtime", &"<runtime>")
            .field(
                "approval_resolver",
                &self.approval_resolver.as_ref().map(|_| "<resolver>"),
            )
            .finish()
    }
}

impl AgentControl {
    pub fn new(runtime: Runtime) -> Self {
        Self {
            runtime,
            approval_resolver: None,
        }
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        Self::from_path_with_dispatchers(path, None, None)
    }

    pub fn from_path_with_dispatchers(
        path: impl AsRef<Path>,
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
    ) -> Result<Self, RuntimeError> {
        let manifest = Manifest::from_path(path)?;
        Self::from_manifest_with_dispatchers(manifest, annotations, policy)
    }

    /// Load a top level manifest from an HTTPS URL. The URL MUST be HTTPS. The
    /// `sha256` pin is optional, mirroring URL `extends`, and when supplied MUST
    /// be a 64 character hexadecimal digest over the fetched bytes. See
    /// [`agent_control_specification_core::Manifest::from_url`] for the trust
    /// gate, which fails closed on a non HTTPS URL, a malformed pin, a fetch
    /// error, a body size breach, or a hash mismatch.
    pub fn from_url(url: &str, sha256: Option<&str>) -> Result<Self, RuntimeError> {
        Self::from_url_with_dispatchers(url, sha256, None, None)
    }

    /// Load a top level manifest from an HTTPS URL with explicit URL fetch
    /// `limits`, so a host that tightened `max_manifest_url_bytes`,
    /// `manifest_url_timeout_ms`, or `max_manifest_url_redirects` has those
    /// honored by the bundled default dispatchers for a dispatch time
    /// `system_prompt_url` fetch. `from_url` uses the default limits.
    pub fn from_url_with_limits(
        url: &str,
        sha256: Option<&str>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        let manifest = Manifest::from_url(url, sha256)?;
        Self::from_manifest_with_dispatchers_and_limits(manifest, None, None, limits)
    }

    pub fn from_url_with_dispatchers(
        url: &str,
        sha256: Option<&str>,
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
    ) -> Result<Self, RuntimeError> {
        let manifest = Manifest::from_url(url, sha256)?;
        Self::from_manifest_with_dispatchers(manifest, annotations, policy)
    }

    pub fn from_manifest(manifest: Manifest) -> Result<Self, RuntimeError> {
        Self::from_manifest_with_dispatchers(manifest, None, None)
    }

    pub fn from_manifest_with_dispatchers(
        manifest: Manifest,
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
    ) -> Result<Self, RuntimeError> {
        Self::from_manifest_with_dispatchers_and_limits(
            manifest,
            annotations,
            policy,
            Limits::default(),
        )
    }

    /// Build from a manifest with explicit URL fetch `limits` threaded to the
    /// bundled default dispatchers, so a tightened body size, timeout, or
    /// redirect cap is honored for a dispatch time `system_prompt_url` or file
    /// sourced `bundle_url` fetch. The other constructors pass the default limits.
    pub fn from_manifest_with_dispatchers_and_limits(
        manifest: Manifest,
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        let annotations = annotations.unwrap_or_else(|| {
            agent_control_specification_core::dispatchers::default_annotator_dispatcher_for(
                &manifest, limits,
            )
        });
        let policy = match policy {
            Some(policy) => policy,
            None => {
                agent_control_specification_core::dispatchers::default_policy_dispatcher_with_limits(
                    &manifest, limits,
                )?
            }
        };
        let runtime = Runtime::new(manifest, annotations, policy)?;
        Ok(Self::new(runtime))
    }

    pub fn from_manifest_chain(manifests: &[&str]) -> Result<Self, RuntimeError> {
        Self::from_manifest_chain_with_dispatchers(manifests, None, None)
    }

    pub fn from_manifest_chain_with_dispatchers(
        manifests: &[&str],
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
    ) -> Result<Self, RuntimeError> {
        let manifest = Manifest::from_yaml_chain(manifests)?;
        Self::from_manifest_with_dispatchers(manifest, annotations, policy)
    }

    pub fn with_approval_resolver(mut self, approval_resolver: ApprovalResolver) -> Self {
        self.approval_resolver = Some(approval_resolver);
        self
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn evaluate_intervention_point(
        &self,
        intervention_point: InterventionPoint,
        snapshot: JsonValue,
        mode: EnforcementMode,
    ) -> InterventionPointResult {
        self.runtime
            .evaluate_intervention_point(InterventionPointRequest {
                intervention_point,
                snapshot,
                mode,
            })
    }

    /// Resolves an intervention point result into proceed, block, or suspend.
    ///
    /// Mirrors the `enforce` seam exposed by the other SDKs and is intended for
    /// asynchronous integrations that drive intervention points manually rather
    /// than through [`run_tool`](Self::run_tool) and friends. In enforce mode an
    /// `escalate` verdict consults `approval_resolver` when supplied, otherwise
    /// the instance resolver, and fails closed to a block when neither resolves
    /// it. Other modes never block.
    pub fn enforce(
        &self,
        intervention_point: InterventionPoint,
        intervention_point_result: &InterventionPointResult,
        mode: EnforcementMode,
        approval_resolver: Option<&ApprovalResolver>,
    ) -> Result<(), AgentControlInterruption> {
        let resolver = approval_resolver.or(self.approval_resolver.as_ref());
        enforce(
            intervention_point,
            intervention_point_result,
            mode,
            resolver,
        )
    }

    /// Returns the policy-transformed policy target when effects apply in enforce
    /// mode, otherwise the original `raw` value. Only `allow` and `warn` verdicts
    /// apply effects.
    pub fn effective_policy_target(
        &self,
        raw: JsonValue,
        intervention_point_result: &InterventionPointResult,
        mode: EnforcementMode,
    ) -> JsonValue {
        effective_policy_target(raw, intervention_point_result, mode)
    }

    /// Enforces the `agent_startup` intervention point against `agent`.
    pub fn agent_startup(
        &self,
        agent: JsonValue,
    ) -> Result<InterventionPointResult, AgentControlInterruption> {
        self.agent_startup_with_options(agent, RunOptions::default())
    }

    pub fn agent_startup_with_options(
        &self,
        agent: JsonValue,
        options: RunOptions,
    ) -> Result<InterventionPointResult, AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let result = self.evaluate_intervention_point(
            InterventionPoint::AgentStartup,
            snapshot_with_value(&options.ambient_snapshot, "agent", agent),
            mode,
        );
        enforce(InterventionPoint::AgentStartup, &result, mode, resolver)?;
        Ok(result)
    }

    /// Enforces the `agent_shutdown` intervention point against `summary`.
    pub fn agent_shutdown(
        &self,
        summary: JsonValue,
    ) -> Result<InterventionPointResult, AgentControlInterruption> {
        self.agent_shutdown_with_options(summary, RunOptions::default())
    }

    pub fn agent_shutdown_with_options(
        &self,
        summary: JsonValue,
        options: RunOptions,
    ) -> Result<InterventionPointResult, AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let result = self.evaluate_intervention_point(
            InterventionPoint::AgentShutdown,
            snapshot_with_value(&options.ambient_snapshot, "summary", summary),
            mode,
        );
        enforce(InterventionPoint::AgentShutdown, &result, mode, resolver)?;
        Ok(result)
    }

    /// Framework-agnostic session seam: enforces `agent_startup` before `body`
    /// runs and `agent_shutdown` after it returns. Assign
    /// [`SessionScope::summary`] inside `body` to supply the shutdown target.
    /// If `body` panics, the unwind skips shutdown so an in-session failure is
    /// never masked by the shutdown verdict.
    pub fn guard_session<F, T>(
        &self,
        agent: JsonValue,
        body: F,
    ) -> Result<T, AgentControlInterruption>
    where
        F: FnOnce(&mut SessionScope) -> T,
    {
        self.guard_session_with_options(agent, RunOptions::default(), body)
    }

    pub fn guard_session_with_options<F, T>(
        &self,
        agent: JsonValue,
        options: RunOptions,
        body: F,
    ) -> Result<T, AgentControlInterruption>
    where
        F: FnOnce(&mut SessionScope) -> T,
    {
        self.agent_startup_with_options(agent, options.clone())?;
        let mut scope = SessionScope::default();
        let output = body(&mut scope);
        self.agent_shutdown_with_options(scope.summary, options)?;
        Ok(output)
    }

    /// Fallible variant of [`guard_session`](Self::guard_session): when `body`
    /// returns `Err`, `agent_shutdown` is skipped so the in-session error is
    /// never masked by the shutdown verdict. The body error surfaces as
    /// [`AgentControlError::Execute`].
    pub fn try_guard_session<F, T, E>(
        &self,
        agent: JsonValue,
        body: F,
    ) -> Result<T, AgentControlError<E>>
    where
        F: FnOnce(&mut SessionScope) -> Result<T, E>,
    {
        self.try_guard_session_with_options(agent, RunOptions::default(), body)
    }

    pub fn try_guard_session_with_options<F, T, E>(
        &self,
        agent: JsonValue,
        options: RunOptions,
        body: F,
    ) -> Result<T, AgentControlError<E>>
    where
        F: FnOnce(&mut SessionScope) -> Result<T, E>,
    {
        self.agent_startup_with_options(agent, options.clone())?;
        let mut scope = SessionScope::default();
        let output = body(&mut scope).map_err(AgentControlError::Execute)?;
        self.agent_shutdown_with_options(scope.summary, options)?;
        Ok(output)
    }

    pub fn run<F>(
        &self,
        input: JsonValue,
        execute: F,
    ) -> Result<RunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> JsonValue,
    {
        self.run_with_options(input, RunOptions::default(), execute)
    }

    pub fn run_with_options<F>(
        &self,
        input: JsonValue,
        options: RunOptions,
        execute: F,
    ) -> Result<RunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> JsonValue,
    {
        match self.try_run_with_options(input, options, |effective_input| {
            Ok::<JsonValue, Infallible>(execute(effective_input))
        }) {
            Ok(result) => Ok(result),
            Err(AgentControlError::Blocked(blocked)) => {
                Err(AgentControlInterruption::Blocked(blocked))
            }
            Err(AgentControlError::Suspended(suspended)) => {
                Err(AgentControlInterruption::Suspended(suspended))
            }
            Err(AgentControlError::Execute(infallible)) => match infallible {},
        }
    }

    pub fn try_run<F, E>(
        &self,
        input: JsonValue,
        execute: F,
    ) -> Result<RunResult, AgentControlError<E>>
    where
        F: FnOnce(JsonValue) -> Result<JsonValue, E>,
    {
        self.try_run_with_options(input, RunOptions::default(), execute)
    }

    pub fn try_run_with_options<F, E>(
        &self,
        input: JsonValue,
        options: RunOptions,
        execute: F,
    ) -> Result<RunResult, AgentControlError<E>>
    where
        F: FnOnce(JsonValue) -> Result<JsonValue, E>,
    {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let input_intervention_point_result = self.evaluate_intervention_point(
            InterventionPoint::Input,
            snapshot_with_value(&options.ambient_snapshot, "input", input.clone()),
            mode,
        );
        enforce(
            InterventionPoint::Input,
            &input_intervention_point_result,
            mode,
            resolver,
        )?;

        let effective_input =
            effective_policy_target(input, &input_intervention_point_result, mode);
        let raw_output = execute(effective_input.clone()).map_err(AgentControlError::Execute)?;

        let output_intervention_point_result = self.evaluate_intervention_point(
            InterventionPoint::Output,
            snapshot_with_values(
                &options.ambient_snapshot,
                [
                    ("input", effective_input.clone()),
                    ("output", raw_output.clone()),
                ],
            ),
            mode,
        );
        enforce(
            InterventionPoint::Output,
            &output_intervention_point_result,
            mode,
            resolver,
        )?;

        let value = effective_policy_target(raw_output, &output_intervention_point_result, mode);
        Ok(RunResult {
            value,
            input_intervention_point_result,
            output_intervention_point_result,
        })
    }

    pub fn run_tool<F>(
        &self,
        tool_name: impl Into<String>,
        args: JsonValue,
        execute: F,
    ) -> Result<ToolRunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> JsonValue,
    {
        self.run_tool_with_options(tool_name, args, ToolRunOptions::default(), execute)
    }

    pub fn run_tool_with_options<F>(
        &self,
        tool_name: impl Into<String>,
        args: JsonValue,
        options: ToolRunOptions,
        execute: F,
    ) -> Result<ToolRunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> JsonValue,
    {
        match self.try_run_tool_with_options(tool_name, args, options, |effective_args| {
            Ok::<JsonValue, Infallible>(execute(effective_args))
        }) {
            Ok(result) => Ok(result),
            Err(AgentControlError::Blocked(blocked)) => {
                Err(AgentControlInterruption::Blocked(blocked))
            }
            Err(AgentControlError::Suspended(suspended)) => {
                Err(AgentControlInterruption::Suspended(suspended))
            }
            Err(AgentControlError::Execute(infallible)) => match infallible {},
        }
    }

    pub fn try_run_tool<F, E>(
        &self,
        tool_name: impl Into<String>,
        args: JsonValue,
        execute: F,
    ) -> Result<ToolRunResult, AgentControlError<E>>
    where
        F: FnOnce(JsonValue) -> Result<JsonValue, E>,
    {
        self.try_run_tool_with_options(tool_name, args, ToolRunOptions::default(), execute)
    }

    pub fn try_run_tool_with_options<F, E>(
        &self,
        tool_name: impl Into<String>,
        args: JsonValue,
        options: ToolRunOptions,
        execute: F,
    ) -> Result<ToolRunResult, AgentControlError<E>>
    where
        F: FnOnce(JsonValue) -> Result<JsonValue, E>,
    {
        let tool_name = tool_name.into();
        let (effective_args, pre_tool_call_intervention_point_result) =
            self.pre_tool_call_with_options(tool_name.clone(), args, options.clone())?;
        let raw_result = execute(effective_args.clone()).map_err(AgentControlError::Execute)?;
        let (value, post_tool_call_intervention_point_result) =
            self.post_tool_call_with_options(tool_name, effective_args, raw_result, options)?;
        Ok(ToolRunResult {
            value,
            pre_tool_call_intervention_point_result,
            post_tool_call_intervention_point_result,
        })
    }

    pub fn pre_tool_call_with_options(
        &self,
        tool_name: impl Into<String>,
        args: JsonValue,
        options: ToolRunOptions,
    ) -> Result<(JsonValue, InterventionPointResult), AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let tool_name = tool_name.into();
        let raw_tool_call =
            tool_call_snapshot(&tool_name, args.clone(), options.tool_call_id.as_deref());
        let pre_tool_call_intervention_point_result = self.evaluate_intervention_point(
            InterventionPoint::PreToolCall,
            snapshot_with_value(
                &options.ambient_snapshot,
                "tool_call",
                raw_tool_call.clone(),
            ),
            mode,
        );
        enforce(
            InterventionPoint::PreToolCall,
            &pre_tool_call_intervention_point_result,
            mode,
            resolver,
        )?;

        let effective_args =
            effective_policy_target(args, &pre_tool_call_intervention_point_result, mode);
        Ok((effective_args, pre_tool_call_intervention_point_result))
    }

    pub fn post_tool_call_with_options(
        &self,
        tool_name: impl Into<String>,
        effective_args: JsonValue,
        raw_result: JsonValue,
        options: ToolRunOptions,
    ) -> Result<(JsonValue, InterventionPointResult), AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let tool_name = tool_name.into();

        let effective_tool_call = tool_call_snapshot(
            &tool_name,
            effective_args.clone(),
            options.tool_call_id.as_deref(),
        );
        let post_tool_call_intervention_point_result = self.evaluate_intervention_point(
            InterventionPoint::PostToolCall,
            snapshot_with_values(
                &options.ambient_snapshot,
                [
                    ("tool_call", effective_tool_call),
                    ("tool_result", raw_result.clone()),
                ],
            ),
            mode,
        );
        enforce(
            InterventionPoint::PostToolCall,
            &post_tool_call_intervention_point_result,
            mode,
            resolver,
        )?;

        let value =
            effective_policy_target(raw_result, &post_tool_call_intervention_point_result, mode);
        Ok((value, post_tool_call_intervention_point_result))
    }

    pub fn run_model<F>(
        &self,
        model_request: JsonValue,
        execute: F,
    ) -> Result<ModelRunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> JsonValue,
    {
        self.run_model_with_options(model_request, RunOptions::default(), execute)
    }

    pub fn run_model_with_options<F>(
        &self,
        model_request: JsonValue,
        options: RunOptions,
        execute: F,
    ) -> Result<ModelRunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> JsonValue,
    {
        match self.try_run_model_with_options(model_request, options, |effective_request| {
            Ok::<JsonValue, Infallible>(execute(effective_request))
        }) {
            Ok(result) => Ok(result),
            Err(AgentControlError::Blocked(blocked)) => {
                Err(AgentControlInterruption::Blocked(blocked))
            }
            Err(AgentControlError::Suspended(suspended)) => {
                Err(AgentControlInterruption::Suspended(suspended))
            }
            Err(AgentControlError::Execute(infallible)) => match infallible {},
        }
    }

    pub fn try_run_model<F, E>(
        &self,
        model_request: JsonValue,
        execute: F,
    ) -> Result<ModelRunResult, AgentControlError<E>>
    where
        F: FnOnce(JsonValue) -> Result<JsonValue, E>,
    {
        self.try_run_model_with_options(model_request, RunOptions::default(), execute)
    }

    pub fn try_run_model_with_options<F, E>(
        &self,
        model_request: JsonValue,
        options: RunOptions,
        execute: F,
    ) -> Result<ModelRunResult, AgentControlError<E>>
    where
        F: FnOnce(JsonValue) -> Result<JsonValue, E>,
    {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let pre_model_call_intervention_point_result = self.evaluate_intervention_point(
            InterventionPoint::PreModelCall,
            model_call_snapshot(&options.ambient_snapshot, model_request.clone(), None),
            mode,
        );
        enforce(
            InterventionPoint::PreModelCall,
            &pre_model_call_intervention_point_result,
            mode,
            resolver,
        )?;

        let effective_request = effective_policy_target(
            model_request,
            &pre_model_call_intervention_point_result,
            mode,
        );
        let raw_response =
            execute(effective_request.clone()).map_err(AgentControlError::Execute)?;

        let post_model_call_intervention_point_result = self.evaluate_intervention_point(
            InterventionPoint::PostModelCall,
            model_call_snapshot(
                &options.ambient_snapshot,
                effective_request.clone(),
                Some(raw_response.clone()),
            ),
            mode,
        );
        enforce(
            InterventionPoint::PostModelCall,
            &post_model_call_intervention_point_result,
            mode,
            resolver,
        )?;

        let value = effective_policy_target(
            raw_response,
            &post_model_call_intervention_point_result,
            mode,
        );
        Ok(ModelRunResult {
            value,
            pre_model_call_intervention_point_result,
            post_model_call_intervention_point_result,
        })
    }

    pub fn protect_tool<F>(&self, tool_name: impl Into<String>, execute: F) -> ProtectedTool<F>
    where
        F: Fn(JsonValue) -> JsonValue,
    {
        ProtectedTool::new(self.clone(), tool_name.into(), execute)
    }

    pub fn guard_rig_like_tool<T>(&self, tool: T) -> GuardedRigLikeTool<T>
    where
        T: RigLikeTool,
    {
        self.guard_rig_like_tool_with_options(tool, ToolRunOptions::default())
    }

    pub fn guard_rig_like_tool_with_options<T>(
        &self,
        tool: T,
        options: ToolRunOptions,
    ) -> GuardedRigLikeTool<T>
    where
        T: RigLikeTool,
    {
        GuardedRigLikeTool::new(self.clone(), tool, options)
    }
}

#[cfg(test)]
mod tests;
