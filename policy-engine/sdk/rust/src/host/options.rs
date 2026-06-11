use super::ApprovalResolver;
use crate::{EnforcementMode, JsonValue};
use serde_json::Map;
use std::fmt;

#[derive(Clone)]
pub struct RunOptions {
    pub ambient_snapshot: Map<String, JsonValue>,
    pub mode: EnforcementMode,
    pub approval_resolver: Option<ApprovalResolver>,
}

impl RunOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate_only() -> Self {
        Self {
            mode: EnforcementMode::EvaluateOnly,
            ..Self::default()
        }
    }

    pub fn with_mode(mut self, mode: EnforcementMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_ambient_snapshot(mut self, ambient_snapshot: Map<String, JsonValue>) -> Self {
        self.ambient_snapshot = ambient_snapshot;
        self
    }

    pub fn with_approval_resolver(mut self, approval_resolver: ApprovalResolver) -> Self {
        self.approval_resolver = Some(approval_resolver);
        self
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            ambient_snapshot: Map::new(),
            mode: EnforcementMode::Enforce,
            approval_resolver: None,
        }
    }
}

impl fmt::Debug for RunOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunOptions")
            .field("ambient_snapshot", &self.ambient_snapshot)
            .field("mode", &self.mode)
            .field(
                "approval_resolver",
                &self.approval_resolver.as_ref().map(|_| "<resolver>"),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct ToolRunOptions {
    pub ambient_snapshot: Map<String, JsonValue>,
    pub mode: EnforcementMode,
    pub tool_call_id: Option<String>,
    pub approval_resolver: Option<ApprovalResolver>,
}

impl ToolRunOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate_only() -> Self {
        Self {
            mode: EnforcementMode::EvaluateOnly,
            ..Self::default()
        }
    }

    pub fn with_mode(mut self, mode: EnforcementMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_ambient_snapshot(mut self, ambient_snapshot: Map<String, JsonValue>) -> Self {
        self.ambient_snapshot = ambient_snapshot;
        self
    }

    pub fn with_tool_call_id(mut self, tool_call_id: impl Into<String>) -> Self {
        let tool_call_id = tool_call_id.into();
        assert!(
            !tool_call_id.is_empty(),
            "tool_call_id must be a non-empty string when provided"
        );
        self.tool_call_id = Some(tool_call_id);
        self
    }

    pub fn with_approval_resolver(mut self, approval_resolver: ApprovalResolver) -> Self {
        self.approval_resolver = Some(approval_resolver);
        self
    }
}

impl Default for ToolRunOptions {
    fn default() -> Self {
        Self {
            ambient_snapshot: Map::new(),
            mode: EnforcementMode::Enforce,
            tool_call_id: None,
            approval_resolver: None,
        }
    }
}

impl fmt::Debug for ToolRunOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolRunOptions")
            .field("ambient_snapshot", &self.ambient_snapshot)
            .field("mode", &self.mode)
            .field("tool_call_id", &self.tool_call_id)
            .field(
                "approval_resolver",
                &self.approval_resolver.as_ref().map(|_| "<resolver>"),
            )
            .finish()
    }
}
