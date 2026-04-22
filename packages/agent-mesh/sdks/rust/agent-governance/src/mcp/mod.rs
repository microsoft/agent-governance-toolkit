// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Self-contained MCP governance and security primitives.

pub mod audit;
pub mod clock;
pub mod error;
pub mod gateway;
pub mod metrics;
pub mod rate_limit;
pub mod redactor;
pub mod response;
pub mod security;
pub mod session;
pub mod signing;

pub use audit::{InMemoryAuditSink, McpAuditEntry, McpAuditSink};
pub use clock::{
    Clock, DeterministicNonceGenerator, FixedClock, NonceGenerator, SystemClock,
    SystemNonceGenerator,
};
pub use error::McpError;
pub use gateway::{
    McpGateway, McpGatewayConfig, McpGatewayDecision, McpGatewayRequest, McpGatewayStatus,
};
pub use metrics::{
    McpDecisionLabel, McpMetricsCollector, McpMetricsSnapshot, McpScanLabel, McpThreatLabel,
};
pub use rate_limit::{
    InMemoryRateLimitStore, McpRateLimitStore, McpSlidingRateLimiter, McpSlidingWindowDecision,
};
pub use redactor::{CredentialKind, CredentialRedactor, RedactionResult};
pub use response::{
    McpResponseFinding, McpResponseScanner, McpResponseThreatType, McpSanitizedResponse,
    McpSanitizedValue,
};
pub use security::{
    McpSecurityScanResult, McpSecurityScanner, McpSeverity, McpThreat, McpThreatType,
    McpToolDefinition, McpToolFingerprint,
};
pub use session::{
    InMemorySessionStore, McpIssuedSession, McpSession, McpSessionAuthenticator, McpSessionStore,
};
pub use signing::{InMemoryNonceStore, McpMessageSigner, McpNonceStore, McpSignedMessage};
