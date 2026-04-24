// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Audit sinks for MCP events.

use crate::mcp::error::McpError;
use crate::mcp::redactor::CredentialRedactor;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Mutex;

/// Auditable MCP event with categorical details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpAuditEntry {
    pub event_type: String,
    pub agent_id: String,
    pub subject: String,
    pub outcome: String,
    pub details: Value,
    pub recorded_at_secs: u64,
}

impl McpAuditEntry {
    /// Return a redacted clone of the entry.
    pub fn redacted(&self, redactor: &CredentialRedactor) -> Self {
        let subject = redactor.redact(&self.subject).sanitized;
        let outcome = redactor.redact(&self.outcome).sanitized;
        let agent_id = redactor.redact(&self.agent_id).sanitized;
        Self {
            event_type: self.event_type.clone(),
            agent_id,
            subject,
            outcome,
            details: redactor.redact_value(&self.details),
            recorded_at_secs: self.recorded_at_secs,
        }
    }
}

/// Sink abstraction for storing audit entries.
pub trait McpAuditSink: Send + Sync {
    fn record(&self, entry: McpAuditEntry) -> Result<(), McpError>;
}

/// In-memory audit sink that stores redacted entries.
#[derive(Debug)]
pub struct InMemoryAuditSink {
    entries: Mutex<Vec<McpAuditEntry>>,
    redactor: CredentialRedactor,
}

impl InMemoryAuditSink {
    pub fn new(redactor: CredentialRedactor) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            redactor,
        }
    }

    pub fn entries(&self) -> Result<Vec<McpAuditEntry>, McpError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| McpError::store("audit", "audit sink lock poisoned"))?;
        Ok(entries.clone())
    }
}

impl McpAuditSink for InMemoryAuditSink {
    fn record(&self, entry: McpAuditEntry) -> Result<(), McpError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| McpError::store("audit", "audit sink lock poisoned"))?;
        entries.push(entry.redacted(&self.redactor));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_audit_sink_redacts_secrets() {
        let redactor = CredentialRedactor::new().unwrap();
        let sink = InMemoryAuditSink::new(redactor);
        sink.record(McpAuditEntry {
            event_type: "test".into(),
            agent_id: "agent-1".into(),
            subject: "Authorization: Bearer abc123secret".into(),
            outcome: "allow".into(),
            details: serde_json::json!({"token": "Bearer abc123secret"}),
            recorded_at_secs: 1,
        })
        .unwrap();
        let entry = sink.entries().unwrap().pop().unwrap();
        assert!(entry.subject.contains("[REDACTED_BEARER_TOKEN]"));
        assert_eq!(entry.details["token"], "[REDACTED_BEARER_TOKEN]");
    }
}
