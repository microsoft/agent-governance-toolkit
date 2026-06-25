//! Agent Control Specification — Rust SDK.
//!
//! Thin host-side orchestration over the stateless `agent_control_specification_core`
//! runtime. Re-exports the full core API plus ergonomic `AgentControl` helpers.
pub use agent_control_specification_core::*;

mod host;
mod streaming;
pub use host::{
    create_unsupported_framework_adapter, AgentControl, AgentControlBlocked, AgentControlError,
    AgentControlInterruption, AgentControlSuspended, ApprovalOutcome, ApprovalResolution,
    ApprovalResolver, GuardedRigLikeTool, ModelRunResult, ProtectedTool, RigLikeTool, RunOptions,
    RunResult, SessionScope, ToolRunOptions, ToolRunResult, UnsupportedFrameworkAdapter,
    UnsupportedFrameworkAdapterError,
};
pub use streaming::{
    assemble_sse_stream, assemble_sse_stream_with_limits, synthesize_sse_stream,
    ModelStreamRunResult, StreamingLimits, StreamingUnsupportedError, DEFAULT_MAX_STREAM_BYTES,
    DEFAULT_MAX_STREAM_EVENTS,
};
