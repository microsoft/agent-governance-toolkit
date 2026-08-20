use crate::{
    AnnotatorDispatcher, EnforcementMode, InterceptionPoint, JsonValue, Limits, Manifest,
    PolicyDispatcher, Runtime, RuntimeError,
};
use std::{convert::Infallible, fmt, fs, path::Path, sync::Arc};

mod approval;
mod error;
mod evaluation;
mod options;
mod results;
mod snapshot;
mod tool;

pub use approval::{ApprovalOutcome, ApprovalResolution, ApprovalResolver};
pub use error::{
    AgentControlBlocked, AgentControlError, AgentControlInterruption, AgentControlSuspended,
};
pub use evaluation::{identity, with_transformed_target, HostEvaluation};
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

/// Stands in for an annotator dispatcher when the manifest declares no
/// annotators and the bundled dispatchers are not compiled in. The
/// runtime only dispatches annotators a manifest names, so `dispatch`
/// is unreachable; it fails closed rather than returning a value that
/// would silently satisfy a policy.
#[cfg(not(feature = "bundled-dispatchers"))]
struct NoAnnotatorDispatcher;

#[cfg(not(feature = "bundled-dispatchers"))]
impl AnnotatorDispatcher for NoAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &agent_control_spec::AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Err(RuntimeError::PolicyInvocationFailed(format!(
            "annotator `{annotator_name}` was dispatched but no annotator dispatcher is \
             registered; register one explicitly, or build with the `bundled-dispatchers` \
             feature, which reads host environment credentials"
        )))
    }
}

/// Select the host-safe default annotator dispatcher.
///
/// The credential-reading bundled dispatcher is available only when the
/// `bundled-dispatchers` feature is explicitly enabled. Without it, manifests
/// that declare no annotators receive a fail-closed unreachable fallback, while
/// manifests that declare annotators must supply a host dispatcher.
pub fn default_host_annotator_dispatcher(
    manifest: &Manifest,
) -> Result<Arc<dyn AnnotatorDispatcher>, RuntimeError> {
    #[cfg(feature = "bundled-dispatchers")]
    {
        let _ = manifest;
        Ok(agent_control_spec::dispatchers::default_annotator_dispatcher())
    }
    #[cfg(not(feature = "bundled-dispatchers"))]
    {
        if manifest.annotators.is_empty() {
            Ok(Arc::new(NoAnnotatorDispatcher))
        } else {
            Err(RuntimeError::PolicyInvocationFailed(format!(
                "manifest declares {} annotator(s) but no annotator dispatcher was supplied and \
                 the bundled dispatchers are not enabled; register one explicitly, or build with \
                 the `bundled-dispatchers` feature, which reads host environment credentials",
                manifest.annotators.len()
            )))
        }
    }
}

/// Select the bundled OPA policy dispatcher.
pub fn default_host_policy_dispatcher(
    manifest: &Manifest,
) -> Result<Arc<dyn PolicyDispatcher>, RuntimeError> {
    agent_control_spec::dispatchers::default_policy_dispatcher(manifest)
}

/// Load a top-level manifest URL through ACS's URL `extends` resolver.
///
/// The temporary manifest is created under the current working directory
/// rather than the system temporary directory. ACS performs the HTTPS trust
/// checks, bounded fetch, redirect handling, optional SHA-256 verification,
/// and recursive `extends` resolution.
/// Return true for IP destinations a manifest URL fetch must not target.
///
/// Prevents server side request forgery to the host itself or to a cloud
/// metadata endpoint. Loopback, the unspecified address, the IPv4 broadcast
/// address, and link-local (IPv4 169.254.0.0/16 including 169.254.169.254, and
/// IPv6 fe80::/10) are blocked. RFC1918 and IPv6 unique-local are deliberately
/// allowed so internal HTTPS policy hosting keeps working. IPv4-mapped
/// (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) literals canonicalize
/// to their embedded IPv4 first, so a dual-stack host cannot route past the
/// guard through `[::ffff:169.254.169.254]`.
///
/// Ported from the engine AGT vendored before the retarget;
/// `agent-control-spec` 0.4.0-alpha.1 validates only scheme, credentials and
/// fragment. Filed upstream as agent-control-spec#20.
fn is_blocked_fetch_ip(ip: std::net::IpAddr) -> bool {
    fn blocked_v4(v4: std::net::Ipv4Addr) -> bool {
        v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
    }
    match ip {
        std::net::IpAddr::V4(v4) => blocked_v4(v4),
        std::net::IpAddr::V6(v6) => {
            // Native IPv6 specials first: to_ipv4 would map ::1 to 0.0.0.1
            // and let it through.
            if v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return blocked_v4(v4);
            }
            if let Some(v4) = v6.to_ipv4() {
                return blocked_v4(v4);
            }
            false
        }
    }
}

/// Reject a URL whose host is a literal IP the fetch guard blocks.
///
/// Only literal addresses are checked. A hostname that resolves to a blocked
/// address still passes, which is the same coverage the pre-retarget engine
/// had: closing that needs resolution-time interception in the fetcher.
fn reject_blocked_fetch_host(url: &str) -> Result<(), RuntimeError> {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .map(|authority| authority.rsplit('@').next().unwrap_or(authority))
        .unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) && !h.is_empty() {
            h
        } else {
            host
        }
    });
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        if is_blocked_fetch_ip(ip) {
            return Err(RuntimeError::ManifestInvalid(format!(
                "URL '{url}' targets a loopback or link-local address, which is blocked to \
                 prevent SSRF to a host-local or cloud metadata endpoint"
            )));
        }
    }
    Ok(())
}

pub fn manifest_from_url(
    url: &str,
    sha256: Option<&str>,
    limits: Limits,
) -> Result<Manifest, RuntimeError> {
    reject_blocked_fetch_host(url)?;
    // A URL `extends` never resolves against the base directory, so this
    // synthetic manifest can live in the system temp dir. Writing it into
    // the working directory would fail on a read-only checkout and would
    // leave a stray directory behind if the process died mid-fetch.
    let temp_dir = tempfile::Builder::new()
        .prefix(".acs-url-manifest-")
        .tempdir()
        .map_err(|error| {
            RuntimeError::ManifestInvalid(format!(
                "failed to create a temporary directory for URL manifest loading: {error}"
            ))
        })?;
    let path = temp_dir.path().join("manifest.yaml");
    let mut synthetic = format!(
        "agent_control_specification_version: 0.4.0-alpha.1\nextends:\n  - url: {}\n",
        serde_json::to_string(url).map_err(|error| {
            RuntimeError::ManifestInvalid(format!("failed to encode manifest URL: {error}"))
        })?
    );
    if let Some(sha256) = sha256 {
        synthetic.push_str(&format!(
            "    sha256: {}\n",
            serde_json::to_string(sha256).map_err(|error| {
                RuntimeError::ManifestInvalid(format!(
                    "failed to encode manifest SHA-256 pin: {error}"
                ))
            })?
        ));
    }
    fs::write(&path, synthetic).map_err(|error| {
        RuntimeError::ManifestInvalid(format!(
            "failed to write the temporary URL manifest '{}': {error}",
            path.display()
        ))
    })?;
    Manifest::from_path_with_limits(path, limits)
}

/// Resolved policy identifier and sorted annotator names per interception point.
pub fn policy_labels(manifest: &Manifest) -> JsonValue {
    let mut points = serde_json::Map::new();
    for (interception_point, config) in &manifest.intervention_points {
        let mut annotators: Vec<String> = config.annotations.keys().cloned().collect();
        annotators.sort();
        points.insert(
            interception_point.as_str().to_string(),
            serde_json::json!({
                "policy_id": config.policy.id,
                "annotators": annotators,
            }),
        );
    }
    JsonValue::Object(points)
}

#[derive(Clone)]
pub struct AgentControl {
    runtime: Runtime,
    approval_resolver: Option<ApprovalResolver>,
    /// Retained so [`AgentControl::with_telemetry`] can rebuild the
    /// runtime. `agent_control_spec::Runtime` takes its telemetry sink at
    /// construction and exposes no setter.
    parts: Option<RuntimeParts>,
}

/// The inputs a `Runtime` is built from.
#[derive(Clone)]
struct RuntimeParts {
    manifest: Manifest,
    annotations: Arc<dyn AnnotatorDispatcher>,
    policy: Arc<dyn PolicyDispatcher>,
    /// Retained so rebuilding for telemetry keeps the caller's budget.
    /// Dropping it would silently restore `Limits::default()`, widening
    /// limits the caller deliberately tightened.
    limits: Limits,
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
            parts: None,
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

    /// Build from a manifest with explicit `limits`. The other constructors
    /// pass the default limits.
    ///
    /// `limits` bounds two things: the engine resource budget (snapshot size,
    /// policy input size, annotators per interception point), and the manifest
    /// `extends` URL fetch performed at load time.
    ///
    /// It does **not** bound a dispatch time fetch. `agent-control-spec`
    /// 0.4.0-alpha.1 constructs the bundled dispatchers without limits, so a
    /// `system_prompt_url` or `bundle_url` fetched by an annotator uses that
    /// crate's own defaults regardless of what is set here. Do not rely on
    /// this to cap outbound requests from a dispatcher.
    pub fn from_manifest_with_dispatchers_and_limits(
        manifest: Manifest,
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        // Falling back to the bundled annotator dispatcher would hand a
        // URL sourced manifest a path to host environment credentials,
        // which is the exposure `bundled-dispatchers` gates. A manifest
        // that declares no annotators never reaches a dispatcher, so it
        // keeps working without the feature.
        let annotations = match annotations {
            Some(annotations) => annotations,
            #[cfg(feature = "bundled-dispatchers")]
            None => agent_control_spec::dispatchers::default_annotator_dispatcher(),
            #[cfg(not(feature = "bundled-dispatchers"))]
            None if manifest.annotators.is_empty() => Arc::new(NoAnnotatorDispatcher),
            #[cfg(not(feature = "bundled-dispatchers"))]
            None => {
                return Err(RuntimeError::PolicyInvocationFailed(format!(
                    "manifest declares {} annotator(s) but no annotator dispatcher was \
                     supplied and the bundled dispatchers are not enabled; register one \
                     explicitly, or build with the `bundled-dispatchers` feature, which \
                     reads host environment credentials",
                    manifest.annotators.len()
                )))
            }
        };
        let policy = match policy {
            Some(policy) => policy,
            None => agent_control_spec::dispatchers::default_policy_dispatcher(&manifest)?,
        };
        // `Limits` carries the engine resource budget (snapshot size,
        // policy input size, annotators per point), so it must reach the
        // runtime rather than be dropped. It does not reach the bundled
        // dispatchers, whose URL fetch budget stays at their own
        // defaults; tracked in docs/acs-retarget.md.
        let runtime = Runtime::with_limits(
            manifest.clone(),
            Arc::clone(&annotations),
            Arc::clone(&policy),
            limits,
        )?;
        let mut control = Self::new(runtime);
        control.parts = Some(RuntimeParts {
            manifest,
            annotations,
            policy,
            limits,
        });
        Ok(control)
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

    /// Install a telemetry sink so every evaluation emits a redaction-safe
    /// `TelemetryEvent` to it. The core runtime owns the emission, so installing
    /// a sink built through any constructor is enough. Combine with the built-in
    /// `InMemoryTelemetrySink`, `StdoutJsonTelemetrySink`, or `MultiSink`, or the
    /// `OtelTelemetrySink` from the `agent_control_specification_otel` crate
    /// (added as a dependency) for OpenTelemetry metrics.
    /// Requires an `AgentControl` built from a manifest. `agent_control_spec`
    /// takes the sink at `Runtime` construction and exposes no setter and no
    /// accessors, so a control built through [`AgentControl::new`] from a
    /// pre-built `Runtime` has nothing to rebuild from and keeps the sink the
    /// runtime was constructed with. Tracked in docs/acs-retarget.md.
    pub fn with_telemetry(mut self, telemetry: Arc<dyn crate::TelemetrySink>) -> Self {
        if let Some(parts) = self.parts.clone() {
            if let Ok(runtime) = Runtime::with_telemetry_perf_and_limits(
                parts.manifest,
                parts.annotations,
                parts.policy,
                telemetry,
                crate::PerfTelemetry::default(),
                parts.limits,
            ) {
                self.runtime = runtime;
            }
        }
        self
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn evaluate_intervention_point(
        &self,
        intervention_point: InterceptionPoint,
        snapshot: JsonValue,
        mode: EnforcementMode,
    ) -> HostEvaluation {
        let engine = self.runtime.evaluate_point(intervention_point, snapshot);
        let limits = self
            .parts
            .as_ref()
            .map(|parts| parts.limits)
            .unwrap_or_default();
        HostEvaluation::from_engine_with_limits(intervention_point, engine, mode, limits)
            .unwrap_or_else(|(error, detail)| HostEvaluation {
                verdict: agent_hooks::Verdict::host_error(error, Some(detail)),
                policy_input: None,
                transformed_policy_target: None,
                action_identity: None,
                input_identity: None,
                enforced_identity: None,
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
        intervention_point: InterceptionPoint,
        intervention_point_result: &HostEvaluation,
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
        intervention_point_result: &HostEvaluation,
        mode: EnforcementMode,
    ) -> JsonValue {
        effective_policy_target(raw, intervention_point_result, mode)
    }

    /// Enforces the `agent_startup` intervention point against `agent`.
    pub fn agent_startup(
        &self,
        agent: JsonValue,
    ) -> Result<HostEvaluation, AgentControlInterruption> {
        self.agent_startup_with_options(agent, RunOptions::default())
    }

    pub fn agent_startup_with_options(
        &self,
        agent: JsonValue,
        options: RunOptions,
    ) -> Result<HostEvaluation, AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let result = self.evaluate_intervention_point(
            InterceptionPoint::AgentStartup,
            snapshot_with_value(&options.ambient_snapshot, "agent", agent),
            mode,
        );
        enforce(InterceptionPoint::AgentStartup, &result, mode, resolver)?;
        Ok(result)
    }

    /// Enforces the `agent_shutdown` intervention point against `summary`.
    pub fn agent_shutdown(
        &self,
        summary: JsonValue,
    ) -> Result<HostEvaluation, AgentControlInterruption> {
        self.agent_shutdown_with_options(summary, RunOptions::default())
    }

    pub fn agent_shutdown_with_options(
        &self,
        summary: JsonValue,
        options: RunOptions,
    ) -> Result<HostEvaluation, AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let result = self.evaluate_intervention_point(
            InterceptionPoint::AgentShutdown,
            snapshot_with_value(&options.ambient_snapshot, "summary", summary),
            mode,
        );
        enforce(InterceptionPoint::AgentShutdown, &result, mode, resolver)?;
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
            InterceptionPoint::Input,
            snapshot_with_value(&options.ambient_snapshot, "input", input.clone()),
            mode,
        );
        enforce(
            InterceptionPoint::Input,
            &input_intervention_point_result,
            mode,
            resolver,
        )?;

        let effective_input =
            effective_policy_target(input, &input_intervention_point_result, mode);
        let raw_output = execute(effective_input.clone()).map_err(AgentControlError::Execute)?;

        let output_intervention_point_result = self.evaluate_intervention_point(
            InterceptionPoint::Output,
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
            InterceptionPoint::Output,
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
    ) -> Result<(JsonValue, HostEvaluation), AgentControlInterruption> {
        let mode = options.mode;
        let resolver = options
            .approval_resolver
            .as_ref()
            .or(self.approval_resolver.as_ref());
        let tool_name = tool_name.into();
        let raw_tool_call =
            tool_call_snapshot(&tool_name, args.clone(), options.tool_call_id.as_deref());
        let pre_tool_call_intervention_point_result = self.evaluate_intervention_point(
            InterceptionPoint::PreToolCall,
            snapshot_with_value(
                &options.ambient_snapshot,
                "tool_call",
                raw_tool_call.clone(),
            ),
            mode,
        );
        enforce(
            InterceptionPoint::PreToolCall,
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
    ) -> Result<(JsonValue, HostEvaluation), AgentControlInterruption> {
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
            InterceptionPoint::PostToolCall,
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
            InterceptionPoint::PostToolCall,
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
            InterceptionPoint::PreModelCall,
            model_call_snapshot(&options.ambient_snapshot, model_request.clone(), None),
            mode,
        );
        enforce(
            InterceptionPoint::PreModelCall,
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
            InterceptionPoint::PostModelCall,
            model_call_snapshot(
                &options.ambient_snapshot,
                effective_request.clone(),
                Some(raw_response.clone()),
            ),
            mode,
        );
        enforce(
            InterceptionPoint::PostModelCall,
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
