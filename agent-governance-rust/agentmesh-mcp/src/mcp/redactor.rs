// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Credential redaction for audit-safe storage and display.

use crate::mcp::error::McpError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Categorical credential types that may be redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialKind {
    ApiKey,
    BearerToken,
    ConnectionString,
    SecretAssignment,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::BearerToken => "bearer_token",
            Self::ConnectionString => "connection_string",
            Self::SecretAssignment => "secret_assignment",
        }
    }

    pub(crate) fn placeholder(self) -> &'static str {
        match self {
            Self::ApiKey => "[REDACTED_API_KEY]",
            Self::BearerToken => "[REDACTED_BEARER_TOKEN]",
            Self::ConnectionString => "[REDACTED_CONNECTION_STRING]",
            Self::SecretAssignment => "[REDACTED_SECRET]",
        }
    }
}

/// Result of redacting a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionResult {
    pub sanitized: String,
    pub detected: Vec<CredentialKind>,
}

/// Redacts credentials from strings and nested JSON structures.
#[derive(Debug, Clone)]
pub struct CredentialRedactor {
    patterns: Vec<(CredentialKind, Regex)>,
}

impl CredentialRedactor {
    pub fn new() -> Result<Self, McpError> {
        Ok(Self {
            patterns: vec![
                (
                    CredentialKind::BearerToken,
                    Regex::new(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")?,
                ),
                (
                    CredentialKind::ApiKey,
                    Regex::new(
                        r#"(?i)(?:api[_-]?key|x-api-key)\s*[:=]\s*["']?[a-z0-9_\-]{8,}["']?"#,
                    )?,
                ),
                (
                    CredentialKind::ConnectionString,
                    Regex::new(
                        r"(?i)\b(?:server|host|endpoint)=[^;]+;[^;\n]*(?:password|sharedaccesskey)=[^;\n]+",
                    )?,
                ),
                (
                    CredentialKind::SecretAssignment,
                    Regex::new(
                        r#"(?i)\b(?:password|secret|token)\s*[:=]\s*["']?[^\s"';,]{4,}["']?"#,
                    )?,
                ),
            ],
        })
    }

    pub fn redact(&self, input: &str) -> RedactionResult {
        let mut sanitized = input.to_string();
        let mut detected = Vec::new();
        for (kind, pattern) in &self.patterns {
            if pattern.is_match(&sanitized) && !detected.contains(kind) {
                detected.push(*kind);
            }
            sanitized = pattern
                .replace_all(&sanitized, kind.placeholder())
                .into_owned();
        }
        RedactionResult {
            sanitized,
            detected,
        }
    }

    pub fn redact_value(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.redact(text).sanitized),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.redact_value(item)).collect())
            }
            Value::Object(map) => Value::Object(self.redact_map(map)),
            other => other.clone(),
        }
    }

    fn redact_map(&self, map: &Map<String, Value>) -> Map<String, Value> {
        map.iter()
            .map(|(key, value)| {
                let redacted = match value {
                    Value::String(text) => {
                        let redaction = self.redact(text);
                        if !redaction.detected.is_empty() {
                            Value::String(redaction.sanitized)
                        } else if let Some(kind) = key_hint(key) {
                            Value::String(kind.placeholder().to_string())
                        } else {
                            Value::String(text.clone())
                        }
                    }
                    _ => self.redact_value(value),
                };
                (key.clone(), redacted)
            })
            .collect()
    }
}

pub(crate) fn key_hint(key: &str) -> Option<CredentialKind> {
    let lower = key.to_lowercase();
    if lower.contains("authorization") || lower.contains("bearer") {
        return Some(CredentialKind::BearerToken);
    }
    if lower.contains("api_key") || lower.contains("apikey") || lower.contains("x-api-key") {
        return Some(CredentialKind::ApiKey);
    }
    if lower.contains("connection") && lower.contains("string") {
        return Some(CredentialKind::ConnectionString);
    }
    if ["token", "secret", "password", "credential"]
        .iter()
        .any(|label| lower.contains(label))
    {
        return Some(CredentialKind::SecretAssignment);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_multiple_secret_types() {
        let redactor = CredentialRedactor::new().unwrap();
        let result = redactor
            .redact("Authorization: Bearer abcdefghijklmnop api_key=123456789012 secret=hunter2");
        assert!(result.sanitized.contains("[REDACTED_BEARER_TOKEN]"));
        assert!(result.sanitized.contains("[REDACTED_API_KEY]"));
        assert!(result.sanitized.contains("[REDACTED_SECRET]"));
        assert_eq!(result.detected.len(), 3);
    }

    #[test]
    fn redacts_nested_json_values() {
        let redactor = CredentialRedactor::new().unwrap();
        let value = serde_json::json!({
            "headers": {"authorization": "Bearer abcdefghi"},
            "password": "hunter2"
        });
        let redacted = redactor.redact_value(&value);
        assert_eq!(
            redacted["headers"]["authorization"],
            "[REDACTED_BEARER_TOKEN]"
        );
        assert_eq!(redacted["password"], "[REDACTED_SECRET]");
    }

    #[test]
    fn redacts_x_api_key_fields() {
        let redactor = CredentialRedactor::new().unwrap();
        let value = serde_json::json!({
            "headers": {
                "x-api-key": "abcd1234567890",
                "credential_value": "keep-this-hidden"
            }
        });
        let redacted = redactor.redact_value(&value);
        assert_eq!(redacted["headers"]["x-api-key"], "[REDACTED_API_KEY]");
        assert_eq!(redacted["headers"]["credential_value"], "[REDACTED_SECRET]");
    }
}
