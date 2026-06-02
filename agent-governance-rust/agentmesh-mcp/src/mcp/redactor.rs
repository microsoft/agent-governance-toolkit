// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Credential redaction for audit-safe storage and display.

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
    GitHubToken,
    PemPrivateKey,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::BearerToken => "bearer_token",
            Self::ConnectionString => "connection_string",
            Self::SecretAssignment => "secret_assignment",
            Self::GitHubToken => "github_token",
            Self::PemPrivateKey => "pem_private_key",
        }
    }

    pub(crate) fn placeholder(self) -> &'static str {
        match self {
            Self::ApiKey => "[REDACTED_API_KEY]",
            Self::BearerToken => "[REDACTED_BEARER_TOKEN]",
            Self::ConnectionString => "[REDACTED_CONNECTION_STRING]",
            Self::SecretAssignment => "[REDACTED_SECRET]",
            Self::GitHubToken => "[REDACTED_GITHUB_TOKEN]",
            Self::PemPrivateKey => "[REDACTED_PEM_PRIVATE_KEY]",
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
    /// Build a redactor with the built-in credential patterns.
    ///
    /// All patterns are static string literals compiled at this call site;
    /// any compilation failure is a programmer bug, not a runtime
    /// condition, so this constructor is infallible. The `.expect`
    /// strings name the pattern that would have failed so a regression
    /// points at the offending literal.
    pub fn new() -> Self {
        Self {
            patterns: vec![
                (
                    CredentialKind::BearerToken,
                    Regex::new(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
                        .expect("BearerToken regex literal must compile"),
                ),
                (
                    CredentialKind::ApiKey,
                    Regex::new(
                        r#"(?i)(?:api[_-]?key|x-api-key)\s*[:=]\s*["']?[a-z0-9_\-]{8,}["']?"#,
                    )
                    .expect("ApiKey regex literal must compile"),
                ),
                (
                    CredentialKind::ConnectionString,
                    Regex::new(
                        r"(?i)\b(?:server|host|endpoint)=[^;]+;[^;\n]*(?:password|sharedaccesskey)=[^;\n]+",
                    )
                    .expect("ConnectionString regex literal must compile"),
                ),
                (
                    CredentialKind::SecretAssignment,
                    Regex::new(
                        r#"(?i)\b(?:password|secret|token)\s*[:=]\s*["']?[^\s"';,]{4,}["']?"#,
                    )
                    .expect("SecretAssignment regex literal must compile"),
                ),
                (
                    CredentialKind::GitHubToken,
                    Regex::new(r"\b(?:gh[psour]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})\b")
                        .expect("GitHubToken regex literal must compile"),
                ),
                (
                    CredentialKind::PemPrivateKey,
                    Regex::new(
                        r"-----BEGIN RSA PRIVATE KEY-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END RSA PRIVATE KEY-----",
                    )
                    .expect("PemPrivateKey regex literal must compile"),
                ),
                (
                    CredentialKind::PemPrivateKey,
                    Regex::new(
                        r"-----BEGIN EC PRIVATE KEY-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END EC PRIVATE KEY-----",
                    )
                    .expect("PemPrivateKey regex literal must compile"),
                ),
                (
                    CredentialKind::PemPrivateKey,
                    Regex::new(
                        r"-----BEGIN DSA PRIVATE KEY-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END DSA PRIVATE KEY-----",
                    )
                    .expect("PemPrivateKey regex literal must compile"),
                ),
                (
                    CredentialKind::PemPrivateKey,
                    Regex::new(
                        r"-----BEGIN OPENSSH PRIVATE KEY-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END OPENSSH PRIVATE KEY-----",
                    )
                    .expect("PemPrivateKey regex literal must compile"),
                ),
                (
                    CredentialKind::PemPrivateKey,
                    Regex::new(
                        r"-----BEGIN ENCRYPTED PRIVATE KEY-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END ENCRYPTED PRIVATE KEY-----",
                    )
                    .expect("PemPrivateKey regex literal must compile"),
                ),
                (
                    CredentialKind::PemPrivateKey,
                    Regex::new(
                        r"-----BEGIN PRIVATE KEY-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END PRIVATE KEY-----",
                    )
                    .expect("PemPrivateKey regex literal must compile"),
                ),
            ],
        }
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

impl Default for CredentialRedactor {
    fn default() -> Self {
        Self::new()
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
        let redactor = CredentialRedactor::new();
        let result = redactor
            .redact("Authorization: Bearer abcdefghijklmnop api_key=123456789012 secret=hunter2");
        assert!(result.sanitized.contains("[REDACTED_BEARER_TOKEN]"));
        assert!(result.sanitized.contains("[REDACTED_API_KEY]"));
        assert!(result.sanitized.contains("[REDACTED_SECRET]"));
        assert_eq!(result.detected.len(), 3);
    }

    #[test]
    fn redacts_nested_json_values() {
        let redactor = CredentialRedactor::new();
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
        let redactor = CredentialRedactor::new();
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

    #[test]
    fn redacts_github_token_prefixes() {
        let redactor = CredentialRedactor::new();
        for token in [
            "ghp_FAKEFORTESTING000000000000000000",
            "ghs_FAKEFORTESTING000000000000000000",
            "gho_FAKEFORTESTING000000000000000000",
            "ghu_FAKEFORTESTING000000000000000000",
            "ghr_FAKEFORTESTING000000000000000000",
            "github_pat_FAKE_FOR_TESTING_0000000000000000000000",
        ] {
            let result = redactor.redact(&format!("value {token} end"));
            assert_eq!(result.sanitized, "value [REDACTED_GITHUB_TOKEN] end");
            assert!(result.detected.contains(&CredentialKind::GitHubToken));
        }
    }

    #[test]
    fn redacts_pem_private_key_variants() {
        let redactor = CredentialRedactor::new();
        for label in [
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PRIVATE KEY",
        ] {
            let pem =
                format!("-----BEGIN {label}-----\nZmFrZSBmb3IgdGVzdGluZw==\n-----END {label}-----");
            let result = redactor.redact(&format!("before\n{pem}\nafter"));
            assert_eq!(
                result.sanitized,
                "before\n[REDACTED_PEM_PRIVATE_KEY]\nafter"
            );
            assert!(result.detected.contains(&CredentialKind::PemPrivateKey));
        }
    }

    #[test]
    fn does_not_redact_public_or_malformed_pem_blocks() {
        let redactor = CredentialRedactor::new();
        for text in [
            "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END EC PRIVATE KEY-----",
        ] {
            let result = redactor.redact(text);
            assert_eq!(result.sanitized, text);
            assert!(result.detected.is_empty());
        }
    }
}
