// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for the MCP module.

use thiserror::Error;

/// Errors returned by MCP governance and security primitives.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("invalid HMAC key")]
    InvalidHmacKey,

    #[error("invalid token format")]
    InvalidTokenFormat,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("session expired")]
    SessionExpired,

    #[error("session limit exceeded for agent '{agent_id}' (limit: {limit})")]
    SessionLimitExceeded { agent_id: String, limit: usize },

    #[error("message replay detected")]
    ReplayDetected,

    #[error("rate limited; retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    #[error("human approval required for tool '{tool_name}'")]
    ApprovalRequired { tool_name: String },

    #[error("access denied: {reason}")]
    AccessDenied { reason: String },

    #[error("{store} store error: {message}")]
    Store {
        store: &'static str,
        message: String,
    },

    #[error("audit error: {0}")]
    Audit(String),

    #[error("nonce generation error: {0}")]
    NonceGeneration(String),
}

impl McpError {
    /// Create a store error with a concrete store label.
    pub fn store(store: &'static str, message: impl Into<String>) -> Self {
        Self::Store {
            store,
            message: message.into(),
        }
    }
}
