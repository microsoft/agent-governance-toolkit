use crate::{InterventionPoint, InterventionPointResult, JsonValue};
use std::sync::Arc;

/// Outcome of resolving an `escalate` verdict through an [`ApprovalResolver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Allow,
    Deny,
    Suspend,
}

/// Result returned by an [`ApprovalResolver`].
///
/// `handle` is an opaque, host-owned value carried on
/// [`AgentControlSuspended`](super::AgentControlSuspended) so the host can later
/// resume the suspended interaction. The runtime never stores or interprets it.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalResolution {
    pub outcome: ApprovalOutcome,
    pub handle: Option<JsonValue>,
    pub action_identity: Option<String>,
}

impl ApprovalResolution {
    pub fn allow(action_identity: impl Into<String>) -> Self {
        Self {
            outcome: ApprovalOutcome::Allow,
            handle: None,
            action_identity: Some(action_identity.into()),
        }
    }

    pub fn deny() -> Self {
        Self {
            outcome: ApprovalOutcome::Deny,
            handle: None,
            action_identity: None,
        }
    }

    pub fn suspend(
        handle: impl Into<Option<JsonValue>>,
        action_identity: impl Into<String>,
    ) -> Self {
        Self {
            outcome: ApprovalOutcome::Suspend,
            handle: handle.into(),
            action_identity: Some(action_identity.into()),
        }
    }
}

/// Host-supplied callback invoked for an `escalate` verdict in enforce mode.
///
/// It receives the intervention point and its result and returns an
/// [`ApprovalResolution`]. The runtime is synchronous, so the resolver runs to
/// completion inline. A resolver that wants to signal failure must return
/// [`ApprovalResolution::deny`] (the runtime fails closed).
pub type ApprovalResolver =
    Arc<dyn Fn(InterventionPoint, &InterventionPointResult) -> ApprovalResolution + Send + Sync>;
