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

/// Reject a manifest that declares `bundle_url`, `system_prompt_file` or
/// `system_prompt_url`.
///
/// `agent-control-spec` 0.4.0-alpha.3 has no implementation of these
/// pre-retarget fields and its open config maps accept them, so the feature
/// would be silently absent. Every host constructor, the C ABI and the
/// Python and Node bindings run this before building a runtime. See
/// `docs/acs-retarget.md`, "Removed manifest fields".
pub use agent_control_specification_core::reject_removed_manifest_fields;

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

/// Select AGT's OPA policy dispatcher independently of Cargo feature unification.
pub fn default_host_policy_dispatcher(
    manifest: &Manifest,
) -> Result<Arc<dyn PolicyDispatcher>, RuntimeError> {
    for (name, policy) in &manifest.policies {
        let engine = policy.engine_type();
        if engine != "rego" {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "default policy dispatcher supports only Rego policies; policy '{name}' uses engine '{engine}'"
            )));
        }
    }
    // ACS prefers in-process Rego when any consumer enables that feature.
    // AGT's existing API promises OPA executable selection and bundle behavior.
    Ok(Arc::new(
        agent_control_spec::OpaPolicyDispatcher::with_runner(
            agent_control_spec::OpaRegoRunner::from_environment(),
        ),
    ))
}

/// Return true for IP destinations a manifest URL fetch must not target.
///
/// Prevents server side request forgery from the manifest loader to the host
/// itself, to its network, or to a cloud metadata endpoint. Blocked:
///
/// - loopback (`127.0.0.0/8`, `::1`), the unspecified address and the
///   `0.0.0.0/8` "this network" block, and the IPv4 broadcast address;
/// - link-local (`169.254.0.0/16`, which holds the `169.254.169.254`
///   metadata endpoint, and `fe80::/10`);
/// - private ranges (RFC 1918 `10/8`, `172.16/12`, `192.168/16`) and the
///   shared address space `100.64.0.0/10`, which holds the `100.100.100.200`
///   metadata endpoint some clouds use;
/// - IPv6 unique-local `fc00::/7`, which holds the `fd00:ec2::254` metadata
///   endpoint, and the deprecated site-local `fec0::/10`.
///
/// IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`) and NAT64
/// well-known-prefix (`64:ff9b::a.b.c.d`) literals are canonicalized to the
/// embedded IPv4 address first, so a dual-stack host cannot route past the
/// guard through `[::ffff:169.254.169.254]`.
///
/// The pre-retarget engine allowed RFC 1918 and unique-local so a policy
/// could be hosted on an internal HTTPS server by IP literal. That is no
/// longer allowed; use a hostname for internal hosting. Hostnames are not
/// resolved by this guard (see [`is_blocked_fetch_name`]).
fn is_blocked_fetch_ip(ip: std::net::IpAddr) -> bool {
    fn blocked_v4(v4: std::net::Ipv4Addr) -> bool {
        let [a, b, _, _] = v4.octets();
        v4.is_loopback()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_private()
            || a == 0
            || (a == 100 && (b & 0xc0) == 64)
    }
    match ip {
        std::net::IpAddr::V4(v4) => blocked_v4(v4),
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Native IPv6 specials first: to_ipv4 would map ::1 to 0.0.0.1
            // and let it through.
            if v6.is_loopback()
                || v6.is_unspecified()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] & 0xfe00) == 0xfc00
            {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return blocked_v4(v4);
            }
            if let Some(v4) = v6.to_ipv4() {
                return blocked_v4(v4);
            }
            // NAT64 well-known prefix 64:ff9b::/96 embeds IPv4 in the low
            // 32 bits; a NAT64 gateway forwards it to that address.
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [.., a, b, c, d] = v6.octets();
                return blocked_v4(std::net::Ipv4Addr::new(a, b, c, d));
            }
            false
        }
    }
}

/// Return true for host names a manifest URL fetch must not target.
///
/// `localhost`, any `*.localhost` name (reserved for loopback by RFC 6761)
/// and any `*.local` name (mDNS, RFC 6762, link-local scope) are blocked.
/// The `url` crate lowercases ASCII domain labels; a trailing dot is
/// removed before matching so `localhost.` cannot slip through.
///
/// Other names are not resolved here. A name that resolves into a blocked
/// range, and DNS rebinding between this check and the connect, need a
/// resolution-time check inside the fetcher, which `agent-control-spec`
/// 0.4.0-alpha.3 does not expose (upstream issue #20).
fn is_blocked_fetch_name(domain: &str) -> bool {
    let name = domain.trim_end_matches('.').to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost") || name.ends_with(".local")
}

/// Reject a URL whose destination the fetch guard blocks.
///
/// The URL is parsed with the `url` crate, the same parser the upstream
/// loader canonicalizes the fetch target with, and the check runs on the
/// canonical `Url::host()`. Hand-splitting the authority and calling
/// `str::parse::<IpAddr>` accepted only dotted-quad literals, so `127.1`,
/// `2130706433`, `0x7f000001`, `0177.0.0.1` and `127.0.0<TAB>.1` walked past
/// the guard and were then canonicalized to `127.0.0.1` by the fetcher.
///
/// Only the URL a caller passes is checked. Redirect hops are followed by
/// the HTTP client inside `agent-control-spec` without re-running this
/// check, and a nested `extends` URL inside the fetched manifest is not
/// checked at all; see `docs/acs-retarget.md`.
fn reject_blocked_fetch_host(url: &str) -> Result<(), RuntimeError> {
    let parsed = url::Url::parse(url).map_err(|error| {
        RuntimeError::ManifestInvalid(format!("manifest URL '{url}' is invalid: {error}"))
    })?;
    let blocked = match parsed.host() {
        None => Some("no host".to_string()),
        Some(url::Host::Ipv4(ip)) if is_blocked_fetch_ip(std::net::IpAddr::V4(ip)) => {
            Some(format!("IPv4 address {ip}"))
        }
        Some(url::Host::Ipv6(ip)) if is_blocked_fetch_ip(std::net::IpAddr::V6(ip)) => {
            Some(format!("IPv6 address {ip}"))
        }
        Some(url::Host::Domain(domain)) if is_blocked_fetch_name(domain) => {
            Some(format!("host name '{domain}'"))
        }
        Some(_) => None,
    };
    match blocked {
        Some(detail) => Err(RuntimeError::ManifestInvalid(format!(
            "URL '{url}' targets a blocked destination ({detail}); manifest fetches must \
             not reach loopback, link-local, private, unique-local or cloud metadata \
             addresses, or the names localhost, *.localhost and *.local, to prevent SSRF \
             against the host or its network"
        ))),
        None => Ok(()),
    }
}

/// Load a top-level manifest URL through ACS's URL `extends` resolver.
///
/// The URL is first run through the SSRF guard ([`reject_blocked_fetch_host`]).
/// A synthetic one-entry `extends` manifest is then written to a temporary
/// directory and loaded with `Manifest::from_path_with_limits`, so ACS
/// performs the HTTPS trust checks, bounded fetch, redirect handling,
/// optional SHA-256 verification, and recursive `extends` resolution.
///
/// The guard covers the URL passed here and nothing deeper. The upstream
/// fetcher follows up to `limits.max_manifest_url_redirects` redirects
/// inside its HTTP client without re-checking each hop, and exposes no
/// hook to intercept them. A host that needs the guard to hold across
/// redirects must pass `limits` with `max_manifest_url_redirects` set to
/// `0`. A nested `extends` URL inside the fetched manifest is resolved by
/// the upstream loader with no destination check (upstream issue #20).
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
    let version = agent_control_spec::SUPPORTED_VERSIONS
        .first()
        .ok_or_else(|| {
            RuntimeError::ManifestInvalid(
                "engine exports no supported manifest versions".to_string(),
            )
        })?;
    let mut synthetic = format!(
        "agent_control_specification_version: {version}\nextends:\n  - url: {}\n",
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
    let manifest = Manifest::from_path_with_limits(path, limits)?;
    reject_removed_manifest_fields(&manifest)?;
    Ok(manifest)
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

/// Construction inputs that the upstream runtime does not expose.
#[derive(Clone)]
struct RuntimeParts {
    annotations: Arc<dyn AnnotatorDispatcher>,
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
    /// 0.4.0-alpha.3 constructs the bundled dispatchers without limits, so
    /// any request an annotator dispatcher makes (an `llm` or `endpoint`
    /// call) uses that crate's own defaults regardless of what is set here.
    /// Do not rely on this to cap outbound requests from a dispatcher.
    ///
    /// Fails closed with `runtime_error:manifest_invalid` when the manifest
    /// declares a field the pinned engine dropped; see
    /// [`reject_removed_manifest_fields`].
    pub fn from_manifest_with_dispatchers_and_limits(
        manifest: Manifest,
        annotations: Option<Arc<dyn AnnotatorDispatcher>>,
        policy: Option<Arc<dyn PolicyDispatcher>>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        reject_removed_manifest_fields(&manifest)?;
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
            None => default_host_policy_dispatcher(&manifest)?,
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
            annotations,
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
    /// takes the sink at `Runtime` construction and exposes no setter or
    /// annotator/limit accessors, so a control built through
    /// [`AgentControl::new`] keeps the sink the runtime was constructed with.
    /// Tracked in docs/acs-retarget.md.
    pub fn with_telemetry(mut self, telemetry: Arc<dyn crate::TelemetrySink>) -> Self {
        if let Some(parts) = self.parts.clone() {
            if let Ok(runtime) = Runtime::with_telemetry_perf_and_limits(
                self.runtime.manifest().clone(),
                parts.annotations,
                Arc::clone(self.runtime.policy_dispatcher()),
                telemetry,
                self.runtime.perf_telemetry(),
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
