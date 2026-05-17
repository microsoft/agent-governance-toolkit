// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Gateway pipeline for governed MCP traffic.

use crate::mcp::audit::{McpAuditEntry, McpAuditSink};
use crate::mcp::clock::Clock;
use crate::mcp::error::McpError;
use crate::mcp::metrics::{McpDecisionLabel, McpMetricsCollector, McpScanLabel};
use crate::mcp::rate_limit::McpSlidingRateLimiter;
use crate::mcp::response::{McpResponseFinding, McpResponseScanner, McpSanitizedValue};
use crate::mcp::session::McpSessionAuthenticator;
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
    session_authenticator: Option<McpSessionAuthenticator>,
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
            session_authenticator: None,
        }
    }

    #[deprecated(
        note = "unauthenticated requests now fail closed; use process_authenticated_request with McpSessionAuthenticator"
    )]
    pub fn process_request(
        &self,
        _request: &McpGatewayRequest,
    ) -> Result<McpGatewayDecision, McpError> {
        Err(McpError::AccessDenied {
            reason: "session authentication required; call process_authenticated_request with a valid session token".to_string(),
        })
    }

    pub fn with_session_authenticator(
        mut self,
        session_authenticator: McpSessionAuthenticator,
    ) -> Self {
        self.session_authenticator = Some(session_authenticator);
        self
    }

    pub fn process_authenticated_request(
        &self,
        request: &McpGatewayRequest,
        session_token: &str,
    ) -> Result<McpGatewayDecision, McpError> {
        let authenticated_agent_id = self.authenticate_agent(request, session_token)?;
        self.metrics.record_scan(McpScanLabel::Gateway)?;
        let sanitized = self.response_scanner.scan_value(&request.payload)?;
        if matches_any(&self.config.deny_list, &request.tool_name) {
            return self.finish(
                &authenticated_agent_id,
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
                &authenticated_agent_id,
                request,
                sanitized,
                McpGatewayStatus::Denied,
                0,
                McpDecisionLabel::Denied,
            );
        }
        if self.config.block_on_suspicious_payload && !sanitized.findings.is_empty() {
            return self.finish(
                &authenticated_agent_id,
                request,
                sanitized,
                McpGatewayStatus::Denied,
                0,
                McpDecisionLabel::Denied,
            );
        }
        let rate_limit = self.rate_limiter.check(&authenticated_agent_id)?;
        if !rate_limit.allowed {
            self.metrics.record_rate_limit_hit("per_agent")?;
            return self.finish(
                &authenticated_agent_id,
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
                &authenticated_agent_id,
                request,
                sanitized,
                McpGatewayStatus::RequiresApproval,
                0,
                McpDecisionLabel::ApprovalRequired,
            );
        }
        self.finish(
            &authenticated_agent_id,
            request,
            sanitized,
            McpGatewayStatus::Allowed,
            0,
            McpDecisionLabel::Allowed,
        )
    }

    fn authenticate_agent(
        &self,
        request: &McpGatewayRequest,
        session_token: &str,
    ) -> Result<String, McpError> {
        let authenticator =
            self.session_authenticator
                .as_ref()
                .ok_or_else(|| McpError::AccessDenied {
                    reason: "gateway session authenticator is not configured".to_string(),
                })?;
        let session = authenticator.authenticate(session_token, &request.agent_id)?;
        Ok(session.agent_id)
    }

    fn finish(
        &self,
        authenticated_agent_id: &str,
        request: &McpGatewayRequest,
        sanitized: McpSanitizedValue,
        status: McpGatewayStatus,
        retry_after_secs: u64,
        label: McpDecisionLabel,
    ) -> Result<McpGatewayDecision, McpError> {
        self.metrics.record_decision(label)?;
        self.audit_sink.record(McpAuditEntry {
            event_type: "gateway_decision".to_string(),
            agent_id: authenticated_agent_id.to_string(),
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
    use crate::mcp::clock::{DeterministicNonceGenerator, FixedClock, SystemClock};
    use crate::mcp::rate_limit::InMemoryRateLimitStore;
    use crate::mcp::redactor::CredentialRedactor;
    use crate::mcp::session::InMemorySessionStore;
    use std::time::{Duration, SystemTime};

    fn session_authenticator() -> McpSessionAuthenticator {
        McpSessionAuthenticator::new(
            b"0123456789abcdef0123456789abcdef".to_vec(),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(DeterministicNonceGenerator::from_values(vec![
                "session-1".into(),
                "session-2".into(),
            ])),
            Arc::new(InMemorySessionStore::default()),
            Duration::from_secs(60),
            4,
        )
        .unwrap()
    }

    fn gateway(config: McpGatewayConfig) -> (McpGateway, String, Arc<InMemoryAuditSink>) {
        gateway_with_limit(config, 1)
    }

    fn gateway_with_limit(
        config: McpGatewayConfig,
        max_requests: usize,
    ) -> (McpGateway, String, Arc<InMemoryAuditSink>) {
        let redactor = CredentialRedactor::new();
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
            max_requests,
            Duration::from_secs(60),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(InMemoryRateLimitStore::default()),
        )
        .unwrap();
        let session_authenticator = session_authenticator();
        let issued = session_authenticator
            .issue_session("did:agentmesh:test")
            .unwrap();
        (
            McpGateway::new(
                config,
                scanner,
                limiter,
                audit.clone(),
                metrics,
                Arc::new(SystemClock),
            )
            .with_session_authenticator(session_authenticator),
            issued.token,
            audit,
        )
    }

    fn unauthenticated_gateway(config: McpGatewayConfig) -> McpGateway {
        let redactor = CredentialRedactor::new();
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
    #[allow(deprecated)]
    fn unauthenticated_requests_fail_closed() {
        let (gateway, _, _) = gateway(McpGatewayConfig::default());
        let err = gateway
            .process_request(&McpGatewayRequest {
                agent_id: "did:agentmesh:test".into(),
                tool_name: "db.read".into(),
                payload: serde_json::json!({"query": "select 1"}),
            })
            .unwrap_err();
        assert!(matches!(err, McpError::AccessDenied { .. }));
    }

    #[test]
    fn deny_list_blocks_first() {
        let (gateway, session_token, _) = gateway(McpGatewayConfig {
            deny_list: vec!["shell.*".into(), "shell:*".into()],
            ..Default::default()
        });
        let decision = gateway
            .process_authenticated_request(
                &McpGatewayRequest {
                    agent_id: "did:agentmesh:test".into(),
                    tool_name: "shell:*".into(),
                    payload: serde_json::json!({"cmd": "ls"}),
                },
                &session_token,
            )
            .unwrap();
        assert_eq!(decision.status, McpGatewayStatus::Denied);
    }

    #[test]
    fn forged_agent_id_is_rejected() {
        let gateway = unauthenticated_gateway(McpGatewayConfig::default())
            .with_session_authenticator(session_authenticator());
        let attacker_token = gateway
            .session_authenticator
            .as_ref()
            .unwrap()
            .issue_session("did:agentmesh:attacker")
            .unwrap()
            .token;
        let err = gateway
            .process_authenticated_request(
                &McpGatewayRequest {
                    agent_id: "did:agentmesh:victim".into(),
                    tool_name: "db.read".into(),
                    payload: serde_json::json!({"query": "select 1"}),
                },
                &attacker_token,
            )
            .unwrap_err();
        assert!(matches!(err, McpError::AccessDenied { .. }));
    }

    #[test]
    fn authenticated_requests_require_configured_session_authenticator() {
        let gateway = unauthenticated_gateway(McpGatewayConfig::default());
        let err = gateway
            .process_authenticated_request(
                &McpGatewayRequest {
                    agent_id: "did:agentmesh:test".into(),
                    tool_name: "db.read".into(),
                    payload: serde_json::json!({"query": "select 1"}),
                },
                "session-token",
            )
            .unwrap_err();
        assert!(matches!(err, McpError::AccessDenied { .. }));
    }

    #[test]
    fn approval_pipeline_triggers_after_rate_limit() {
        let (gateway, session_token, _) = gateway(McpGatewayConfig {
            approval_required_tools: vec!["db.write".into()],
            ..Default::default()
        });
        let decision = gateway
            .process_authenticated_request(
                &McpGatewayRequest {
                    agent_id: "did:agentmesh:test".into(),
                    tool_name: "db.write".into(),
                    payload: serde_json::json!({"query": "insert"}),
                },
                &session_token,
            )
            .unwrap();
        assert_eq!(decision.status, McpGatewayStatus::RequiresApproval);
    }

    #[test]
    fn invalid_session_token_is_rejected() {
        let (gateway, _, _) = gateway(McpGatewayConfig::default());
        let err = gateway
            .process_authenticated_request(
                &McpGatewayRequest {
                    agent_id: "did:agentmesh:test".into(),
                    tool_name: "db.read".into(),
                    payload: serde_json::json!({"query": "select 1"}),
                },
                "not-a-valid-session-token",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            McpError::InvalidTokenFormat | McpError::InvalidSignature
        ));
    }

    #[test]
    fn authenticated_requests_hit_rate_limit() {
        let (gateway, session_token, _) = gateway(McpGatewayConfig::default());
        let request = McpGatewayRequest {
            agent_id: "did:agentmesh:test".into(),
            tool_name: "db.read".into(),
            payload: serde_json::json!({"query": "select 1"}),
        };

        let first = gateway
            .process_authenticated_request(&request, &session_token)
            .unwrap();
        assert_eq!(first.status, McpGatewayStatus::Allowed);

        let second = gateway
            .process_authenticated_request(&request, &session_token)
            .unwrap();
        assert_eq!(second.status, McpGatewayStatus::RateLimited);
        assert!(second.retry_after_secs > 0);
    }

    #[test]
    fn authenticated_requests_record_audit_entries() {
        let (gateway, session_token, audit) = gateway_with_limit(McpGatewayConfig::default(), 2);
        let request = McpGatewayRequest {
            agent_id: "did:agentmesh:test".into(),
            tool_name: "db.read".into(),
            payload: serde_json::json!({"query": "select 1"}),
        };

        let decision = gateway
            .process_authenticated_request(&request, &session_token)
            .unwrap();
        assert_eq!(decision.status, McpGatewayStatus::Allowed);

        let entries = audit.entries().unwrap();
        let gateway_entry = entries
            .iter()
            .find(|entry| entry.event_type == "gateway_decision")
            .expect("expected gateway_decision audit entry");
        assert_eq!(gateway_entry.agent_id, "did:agentmesh:test");
        assert_eq!(gateway_entry.subject, "db.read");
        assert_eq!(gateway_entry.outcome, "allowed");
    }
}
