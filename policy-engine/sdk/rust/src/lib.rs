//! Agent Control Specification — Rust SDK.
//!
//! Thin host-side orchestration over the stateless `agent_control_spec`
//! runtime. Re-exports the full core API plus ergonomic `AgentControl` helpers.
pub use agent_control_spec::*;
pub use agent_hooks::HostError;

// ---------------------------------------------------------------------
// Deprecated aliases for names the agent-hooks contract renamed. Kept for
// one release cycle so downstream code keeps compiling; `agent_control_spec`
// owns the definitions. Type aliases rather than `pub use` because
// `#[deprecated]` on a re-export is silently ignored (rust-lang/rust#30827).
// ---------------------------------------------------------------------

/// Renamed by the agent-hooks contract.
#[deprecated(
    since = "0.4.0-beta.0",
    note = "renamed InterceptionPoint; import agent_control_spec::InterceptionPoint"
)]
pub type InterventionPoint = agent_control_spec::InterceptionPoint;

/// Renamed by the agent-hooks contract.
#[deprecated(
    since = "0.4.0-beta.0",
    note = "renamed EvaluationRequest; import agent_control_spec::EvaluationRequest"
)]
pub type InterventionPointRequest = agent_control_spec::EvaluationRequest;

/// Renamed by the agent-hooks contract.
#[deprecated(
    since = "0.4.0-beta.0",
    note = "renamed EvaluationResult; import agent_control_spec::EvaluationResult"
)]
pub type InterventionPointResult = agent_control_spec::EvaluationResult;

// The C ABI the .NET SDK binds. It lives here rather than in the core shim
// because it discharges the host obligations before crossing the boundary.
pub mod ffi;

mod host;
mod streaming;
pub use host::{
    create_unsupported_framework_adapter, default_host_annotator_dispatcher,
    default_host_policy_dispatcher, identity, manifest_from_url, policy_labels,
    with_transformed_target, AgentControl, AgentControlBlocked, AgentControlError,
    AgentControlInterruption, AgentControlSuspended, ApprovalOutcome, ApprovalResolution,
    ApprovalResolver, GuardedRigLikeTool, HostEvaluation, ModelRunResult, ProtectedTool,
    RigLikeTool, RunOptions, RunResult, SessionScope, ToolRunOptions, ToolRunResult,
    UnsupportedFrameworkAdapter, UnsupportedFrameworkAdapterError,
};
pub use streaming::{
    assemble_sse_stream, assemble_sse_stream_with_limits, synthesize_sse_stream,
    ModelStreamRunResult, StreamingLimits, StreamingUnsupportedError, DEFAULT_MAX_STREAM_BYTES,
    DEFAULT_MAX_STREAM_EVENTS,
};
