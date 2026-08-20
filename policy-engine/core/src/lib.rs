// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deprecation shim over the Agent Control Specification runtime.
//!
//! The policy decision runtime that used to live in this crate now ships
//! as [`agent_control_spec`] on crates.io, rebased on the agent-hooks
//! control contract. This crate is a compatibility layer for one release
//! cycle. It re-exports the ACS surface under the historical names and
//! keeps the few modules ACS does not carry.
//!
//! # Migrating
//!
//! Depend on `agent-control-spec` directly and import from it. The
//! renames are mechanical.
//!
//! | Was | Now |
//! | --- | --- |
//! | `InterventionPoint` | `agent_hooks::InterceptionPoint` |
//! | `InterventionPointRequest` | `runtime::EvaluationRequest` |
//! | `InterventionPointResult` | `runtime::EvaluationResult` |
//! | `verdict::normalize_policy_output` | `policy_output::normalize_policy_output` |
//! | `verdict::{Decision, Evidence, Transform, Verdict}` | `agent_hooks::{..}` |
//!
//! `Decision` carries three values now rather than five. A `warn` intent
//! becomes `allow` plus `warnings[]`, and an `escalate` intent becomes
//! `deny` plus an `approval` block. `agent_hooks::Verdict::warn` is the
//! constructor sugar for the first. The effects plane is gone and
//! `transform` is the only value changing decision.
//!
//! # Deprecation mechanics
//!
//! Rust ignores `#[deprecated]` on a `pub use` re-export, so the aliases
//! below are declared as deprecated type aliases and wrapper functions,
//! which do warn at the call site. Traits cannot be aliased on stable
//! Rust, so trait re-exports stay plain `pub use` and carry the notice in
//! their documentation only.
//!
//! # Security note
//!
//! AGT gated host environment credential reads on manifest provenance, so
//! a manifest fetched over the network could not reach host credentials.
//! `agent-control-spec` 0.4.0-alpha.1 does not carry that gate while it
//! still supports URL sourced `extends`. Do not enable the bundled
//! dispatcher features until that is restored upstream. See
//! `docs/acs-retarget.md`.

/// Convenience alias for the JSON document type used across the runtime.
pub type JsonValue = serde_json::Value;

#[cfg(feature = "opa")]
pub mod artifact_validation;
pub mod identity;
pub mod manifest_yaml;
pub mod telemetry_sinks;

// ---------------------------------------------------------------------
// Modules re-exported from the Agent Control Specification runtime.
// ---------------------------------------------------------------------

pub use agent_control_spec::{
    annotation, cedar, error, interceptor, limits, manifest, paths, perf_telemetry, point_ext,
    policy, policy_input, policy_output, reserved_reason, runtime, telemetry, tool_projection,
};

#[cfg(feature = "default-dispatchers")]
pub use agent_control_spec::dispatchers;

#[cfg(feature = "opa")]
pub use agent_control_spec::opa;

// ---------------------------------------------------------------------
// The interception contract, by way of ACS.
// ---------------------------------------------------------------------

pub use agent_control_spec::{AgentContext, Interceptor, Warning};

/// Verdict decision. Three values now rather than five.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; import agent_control_spec::Decision"
)]
pub type Decision = agent_control_spec::Decision;

/// Whether the host acts on verdicts.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "owned by agent-hooks; import agent_control_spec::EnforcementMode"
)]
pub type EnforcementMode = agent_control_spec::EnforcementMode;

/// Renamed by the agent-hooks contract.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "renamed InterceptionPoint; import agent_control_spec::InterceptionPoint"
)]
pub type InterventionPoint = agent_control_spec::InterceptionPoint;

/// Supporting evidence attached to a verdict.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; import agent_control_spec::Evidence"
)]
pub type Evidence = agent_control_spec::Evidence;

/// Single target replacement carried by a `transform` verdict.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; import agent_control_spec::Transform"
)]
pub type Transform = agent_control_spec::Transform;

/// Interceptor return value.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; import agent_control_spec::Verdict"
)]
pub type Verdict = agent_control_spec::Verdict;

// ---------------------------------------------------------------------
// Policy plane types.
// ---------------------------------------------------------------------

pub use agent_control_spec::{
    AnnotationConfig, AnnotatorConfig, AnnotatorDispatcher, AnnotatorInvocation, AnnotatorType,
    CedarPolicyDispatcher, PolicyDispatcher, TelemetrySink,
};

pub use agent_control_spec::{
    build_cedar_request, translate_advice, CedarEntity, CedarRequest, CedarTestDispatcher,
};

#[cfg(feature = "cedar")]
pub use agent_control_spec::CedarBuiltinDispatcher;

#[cfg(feature = "default-dispatchers")]
pub use agent_control_spec::{
    ClassifierAnnotator, DefaultAnnotatorDispatcher, EndpointAnnotator, LlmAnnotator,
};

#[cfg(feature = "opa")]
pub use agent_control_spec::{OpaPolicyDispatcher, OpaRegoRunner};

pub use agent_control_spec::{
    CedarPolicyConfig, CedarPolicyInvocation, CustomPolicyConfig, CustomPolicyInvocation,
    PolicyBinding, PolicyConfig, PreparedPolicyInvocation, RegoPolicyConfig, RegoPolicyInvocation,
    TestPolicyConfig, TestPolicyInvocation,
};

pub use agent_control_spec::manifest::{
    ApprovalOnTimeout, ApprovalResolverConfig, ApprovalSection, ManifestExtends, ManifestUrlExtends,
};
pub use agent_control_spec::{InterventionPointConfig, Manifest, ToolConfig};
pub use agent_control_spec::{JsonPath, PathEnv, PathParseError, PathRoot, PathSegment};
pub use agent_control_spec::{Limits, PerfTelemetry, Runtime, RuntimeError};
pub use agent_control_spec::{NoopTelemetrySink, TelemetryEvent, TelemetryEventType};

/// The evaluation request. Renamed by the agent-hooks contract.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "renamed EvaluationRequest; import agent_control_spec::EvaluationRequest"
)]
pub type InterventionPointRequest = agent_control_spec::EvaluationRequest;

/// The evaluation result. Renamed by the agent-hooks contract.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "renamed EvaluationResult; import agent_control_spec::EvaluationResult"
)]
pub type InterventionPointResult = agent_control_spec::EvaluationResult;

// ---------------------------------------------------------------------
// Free functions. Wrappers rather than re-exports so the notice fires.
// ---------------------------------------------------------------------

/// Build the policy input document for an evaluation.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; call agent_control_spec::build_policy_input"
)]
#[allow(clippy::too_many_arguments)]
pub fn build_policy_input(
    intervention_point: agent_control_spec::InterceptionPoint,
    policy_target_path: &str,
    policy_target_kind: Option<&str>,
    policy_target_value: JsonValue,
    snapshot: JsonValue,
    annotations: JsonValue,
    tool: JsonValue,
) -> JsonValue {
    agent_control_spec::build_policy_input(
        intervention_point,
        policy_target_path,
        policy_target_kind,
        policy_target_value,
        snapshot,
        annotations,
        tool,
    )
}

/// Canonical JSON encoding with object keys sorted.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; call agent_control_spec::canonical_json"
)]
pub fn canonical_json(value: &JsonValue) -> Result<String, serde_json::Error> {
    agent_control_spec::canonical_json(value)
}

/// Normalize raw policy output into an agent-hooks verdict.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "moved to agent-control-spec; call agent_control_spec::normalize_policy_output"
)]
pub fn normalize_policy_output(
    output: JsonValue,
) -> Result<agent_control_spec::Verdict, RuntimeError> {
    agent_control_spec::normalize_policy_output(output)
}

// ---------------------------------------------------------------------
// AGT owned surface that the ACS runtime does not carry.
// ---------------------------------------------------------------------

#[allow(deprecated)]
pub use identity::action_identity;

#[cfg(feature = "opa")]
pub use artifact_validation::{
    validate_acs_artifacts, validate_acs_manifest, ArtifactValidationResult, ValidationDiagnostic,
};
pub use manifest_yaml::{
    parse_manifest_yaml_value, validate_manifest_overlay_yaml, validate_manifest_yaml,
};
pub use telemetry_sinks::{
    InMemoryTelemetrySink, MultiSink, StdoutJsonTelemetrySink, TelemetryEventExt,
};
