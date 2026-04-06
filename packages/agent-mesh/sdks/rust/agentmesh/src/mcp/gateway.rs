// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Gateway pipeline for governed MCP traffic.

use crate::mcp::audit::{McpAuditEntry, McpAuditSink};
use crate::mcp::clock::Clock;
use crate::mcp::error::McpError;
use crate::mcp::metrics::{McpDecisionLabel, McpMetricsCollector, McpScanLabel};
use crate::mcp::rate_limit::McpSlidingRateLimiter;
use crate::mcp::response::{McpResponseFinding, McpResponseScanner, McpSanitizedValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpGatewayConfig {
    pub deny_list: Vec<String>,
    pub allow_list: Vec<String>,
    pub approval_required_tools: Vec<String>,
    pub auto_approve: bool,
    pub block_on_suspicious_payload: bool,
}

impl Default for McpGatewayConfig {
    fn default() -> Self {
        Self {
            deny_list: Vec::new(),
            allow_list: Vec::new(),
            approval_required_tools: Vec::new(),
            auto_approve: false,
            block_on_suspicious_payload: true,
        }
    }
}

/// MCP request evaluated by the gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpGatewayRequest {
    pub agent_id: String,
    pub tool_name: String,
    pub payload: Value,
}

/// Gateway terminal status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpGatewayStatus {
    Allowed,
    Denied,
    RateLimited,
    RequiresApproval,
}

/// Gateway decision with sanitized payload details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpGatewayDecision {
    pub status: McpGatewayStatus,
    pub allowed: bool,
    pub sanitized_payload: Value,
    pub findings: Vec<McpResponseFinding>,
    pub retry_after_secs: u64,
}

/// Enforces deny-list -> allow-list -> sanitization -> rate limiting -> human approval.
#[derive(Clone)]
pub struct McpGateway {
    config: McpGatewayConfig,
    response_scanner: McpResponseScanner,
    rate_limiter: McpSlidingRateLimiter,
    audit_sink: Arc<dyn McpAuditSink>,
    metrics: McpMetricsCollector,
    clock: Arc<dyn Clock>,
}

impl McpGateway {
    pub fn new(
        config: McpGatewayConfig,
        response_scanner: McpResponseScanner,
        rate_limiter: McpSlidingRateLimiter,
        audit_sink: Arc<dyn McpAuditSink>,
        metrics: McpMetricsCollector,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            config,
            response_scanner,
            rate_limiter,
            audit_sink,
            metrics,
            clock,
        }
    }

    pub fn process_request(
        &self,
        request: &McpGatewayRequest,
    ) -> Result<McpGatewayDecision, McpError> {
        self.metrics.record_scan(McpScanLabel::Gateway)?;
        let sanitized = self.response_scanner.scan_value(&request.payload)?;
        if matches_any(&self.config.deny_list, &request.tool_name) {
            return self.finish(
                request,
                sanitized,
                McpGatewayStatus::Denied,
                0,
                McpDecisionLabel::Denied,
            );
        }
        if !self.config.allow_list.is_empty()
            && !matches_any(&self.config.allow_list, &request.tool_name)
        {
            return self.finish(
                request,
                sanitized,
                McpGatewayStatus::Denied,
                0,
                McpDecisionLabel::Denied,
            );
        }
        if self.config.block_on_suspicious_payload && !sanitized.findings.is_empty() {
            return self.finish(
                request,
                sanitized,
                McpGatewayStatus::Denied,
                0,
                McpDecisionLabel::Denied,
            );
        }
        let rate_limit = self.rate_limiter.check(&request.agent_id)?;
        if !rate_limit.allowed {
            self.metrics.record_rate_limit_hit("per_agent")?;
            return self.finish(
                request,
                sanitized,
                McpGatewayStatus::RateLimited,
                rate_limit.retry_after_secs,
                McpDecisionLabel::RateLimited,
            );
        }
        if matches_any(&self.config.approval_required_tools, &request.tool_name)
            && !self.config.auto_approve
        {
            return self.finish(
                request,
                sanitized,
                McpGatewayStatus::RequiresApproval,
                0,
                McpDecisionLabel::ApprovalRequired,
            );
        }
        self.finish(
            request,
            sanitized,
            McpGatewayStatus::Allowed,
            0,
            McpDecisionLabel::Allowed,
        )
    }

    fn finish(
        &self,
        request: &McpGatewayRequest,
        sanitized: McpSanitizedValue,
        status: McpGatewayStatus,
        retry_after_secs: u64,
        label: McpDecisionLabel,
    ) -> Result<McpGatewayDecision, McpError> {
        self.metrics.record_decision(label)?;
        self.audit_sink.record(McpAuditEntry {
            event_type: "gateway_decision".to_string(),
            agent_id: request.agent_id.clone(),
            subject: request.tool_name.clone(),
            outcome: format!("{status:?}").to_lowercase(),
            details: serde_json::json!({
                "finding_types": sanitized.findings.iter().map(|finding| format!("{:?}", finding.threat_type)).collect::<Vec<_>>(),
                "retry_after_secs": retry_after_secs,
            }),
            recorded_at_secs: unix_secs(self.clock.now())?,
        })?;
        Ok(McpGatewayDecision {
            allowed: matches!(status, McpGatewayStatus::Allowed),
            status,
            sanitized_payload: sanitized.sanitized,
            findings: sanitized.findings,
            retry_after_secs,
        })
    }
}

fn matches_any(rules: &[String], value: &str) -> bool {
    rules.iter().any(|rule| matches_rule(rule, value))
}

fn matches_rule(rule: &str, value: &str) -> bool {
    if let Some(prefix) = rule.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    rule == value
}

fn unix_secs(time: SystemTime) -> Result<u64, McpError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::AccessDenied {
            reason: "system clock before unix epoch".to_string(),
        })?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::audit::InMemoryAuditSink;
    use crate::mcp::clock::{FixedClock, SystemClock};
    use crate::mcp::rate_limit::InMemoryRateLimitStore;
    use crate::mcp::redactor::CredentialRedactor;
    use std::time::{Duration, SystemTime};

    fn gateway(config: McpGatewayConfig) -> McpGateway {
        let redactor = CredentialRedactor::new().unwrap();
        let audit = Arc::new(InMemoryAuditSink::new(redactor.clone()));
        let metrics = McpMetricsCollector::default();
        let scanner = McpResponseScanner::new(
            redactor,
            audit.clone(),
            metrics.clone(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let limiter = McpSlidingRateLimiter::new(
            1,
            Duration::from_secs(60),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(InMemoryRateLimitStore::default()),
        )
        .unwrap();
        McpGateway::new(
            config,
            scanner,
            limiter,
            audit,
            metrics,
            Arc::new(SystemClock),
        )
    }

    #[test]
    fn deny_list_blocks_first() {
        let gateway = gateway(McpGatewayConfig {
            deny_list: vec!["shell.*".into(), "shell:*".into()],
            ..Default::default()
        });
        let decision = gateway
            .process_request(&McpGatewayRequest {
                agent_id: "did:agentmesh:test".into(),
                tool_name: "shell:*".into(),
                payload: serde_json::json!({"cmd": "ls"}),
            })
            .unwrap();
        assert_eq!(decision.status, McpGatewayStatus::Denied);
    }

    #[test]
    fn approval_pipeline_triggers_after_rate_limit() {
        let gateway = gateway(McpGatewayConfig {
            approval_required_tools: vec!["db.write".into()],
            ..Default::default()
        });
        let decision = gateway
            .process_request(&McpGatewayRequest {
                agent_id: "did:agentmesh:test".into(),
                tool_name: "db.write".into(),
                payload: serde_json::json!({"query": "insert"}),
            })
            .unwrap();
        assert_eq!(decision.status, McpGatewayStatus::RequiresApproval);
    }
}
