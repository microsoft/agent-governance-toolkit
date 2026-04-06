// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Categorical metrics for MCP controls.

use crate::mcp::error::McpError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Decision labels recorded for `mcp_decisions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpDecisionLabel {
    Allowed,
    Denied,
    RateLimited,
    ApprovalRequired,
    Sanitized,
}

impl McpDecisionLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::RateLimited => "rate_limited",
            Self::ApprovalRequired => "approval_required",
            Self::Sanitized => "sanitized",
        }
    }
}

/// Threat labels recorded for `mcp_threats_detected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpThreatLabel {
    ToolPoisoning,
    RugPull,
    CrossServerAttack,
    DescriptionInjection,
    SchemaAbuse,
    HiddenInstruction,
    PromptInjectionTag,
    ImperativePhrasing,
    CredentialLeakage,
    ExfiltrationUrl,
}

impl McpThreatLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolPoisoning => "tool_poisoning",
            Self::RugPull => "rug_pull",
            Self::CrossServerAttack => "cross_server_attack",
            Self::DescriptionInjection => "description_injection",
            Self::SchemaAbuse => "schema_abuse",
            Self::HiddenInstruction => "hidden_instruction",
            Self::PromptInjectionTag => "prompt_injection_tag",
            Self::ImperativePhrasing => "imperative_phrasing",
            Self::CredentialLeakage => "credential_leakage",
            Self::ExfiltrationUrl => "exfiltration_url",
        }
    }
}

/// Scan labels recorded for `mcp_scans`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpScanLabel {
    Response,
    ToolMetadata,
    Gateway,
}

impl McpScanLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::ToolMetadata => "tool_metadata",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Debug, Default)]
struct McpMetricsState {
    decisions: BTreeMap<String, u64>,
    threats_detected: BTreeMap<String, u64>,
    rate_limit_hits: BTreeMap<String, u64>,
    scans: BTreeMap<String, u64>,
}

/// Thread-safe categorical metrics collector.
#[derive(Debug, Clone, Default)]
pub struct McpMetricsCollector {
    state: Arc<Mutex<McpMetricsState>>,
}

/// Snapshot of collected categorical metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpMetricsSnapshot {
    pub mcp_decisions: BTreeMap<String, u64>,
    pub mcp_threats_detected: BTreeMap<String, u64>,
    pub mcp_rate_limit_hits: BTreeMap<String, u64>,
    pub mcp_scans: BTreeMap<String, u64>,
}

impl McpMetricsCollector {
    pub fn record_decision(&self, label: McpDecisionLabel) -> Result<(), McpError> {
        self.increment("metrics", |state| &mut state.decisions, label.as_str())
    }

    pub fn record_threat(&self, label: McpThreatLabel) -> Result<(), McpError> {
        self.increment(
            "metrics",
            |state| &mut state.threats_detected,
            label.as_str(),
        )
    }

    pub fn record_rate_limit_hit(&self, label: &str) -> Result<(), McpError> {
        self.increment("metrics", |state| &mut state.rate_limit_hits, label)
    }

    pub fn record_scan(&self, label: McpScanLabel) -> Result<(), McpError> {
        self.increment("metrics", |state| &mut state.scans, label.as_str())
    }

    pub fn snapshot(&self) -> Result<McpMetricsSnapshot, McpError> {
        let state = self
            .state
            .lock()
            .map_err(|_| McpError::store("metrics", "metrics lock poisoned"))?;
        Ok(McpMetricsSnapshot {
            mcp_decisions: state.decisions.clone(),
            mcp_threats_detected: state.threats_detected.clone(),
            mcp_rate_limit_hits: state.rate_limit_hits.clone(),
            mcp_scans: state.scans.clone(),
        })
    }

    fn increment<F>(&self, store: &'static str, select: F, key: &str) -> Result<(), McpError>
    where
        F: FnOnce(&mut McpMetricsState) -> &mut BTreeMap<String, u64>,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| McpError::store(store, "metrics lock poisoned"))?;
        let entry = select(&mut state).entry(key.to_string()).or_insert(0);
        *entry += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_snapshot_is_categorical() {
        let metrics = McpMetricsCollector::default();
        metrics.record_decision(McpDecisionLabel::Allowed).unwrap();
        metrics.record_threat(McpThreatLabel::SchemaAbuse).unwrap();
        let snapshot = metrics.snapshot().unwrap();
        assert_eq!(snapshot.mcp_decisions["allowed"], 1);
        assert_eq!(snapshot.mcp_threats_detected["schema_abuse"], 1);
    }
}
