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
    OpenAiToken,
    SlackToken,
    AwsAccessKey,
    GoogleApiKey,
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
            Self::OpenAiToken => "openai_token",
            Self::SlackToken => "slack_token",
            Self::AwsAccessKey => "aws_access_key",
            Self::GoogleApiKey => "google_api_key",
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
            Self::OpenAiToken => "[REDACTED_OPENAI_TOKEN]",
            Self::SlackToken => "[REDACTED_SLACK_TOKEN]",
            Self::AwsAccessKey => "[REDACTED_AWS_ACCESS_KEY]",
            Self::GoogleApiKey => "[REDACTED_GOOGLE_API_KEY]",
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
    bounded_patterns: Vec<(CredentialKind, Regex)>,
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
            bounded_patterns: vec![
                (
                    CredentialKind::GitHubToken,
                    Regex::new(r"(?:gh[psour]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})")
                        .expect("GitHubToken regex literal must compile"),
                ),
                (
                    CredentialKind::OpenAiToken,
                    Regex::new(r"sk-[A-Za-z0-9][A-Za-z0-9_-]{18,}")
                        .expect("OpenAiToken regex literal must compile"),
                ),
                (
                    CredentialKind::SlackToken,
                    Regex::new(r"xox[abprs]-[A-Za-z0-9-]+")
                        .expect("SlackToken regex literal must compile"),
                ),
                (
                    CredentialKind::AwsAccessKey,
                    Regex::new(r"AKIA[A-Z0-9]{16}")
                        .expect("AwsAccessKey regex literal must compile"),
                ),
                (
                    CredentialKind::GoogleApiKey,
                    Regex::new(r"AIza[0-9A-Za-z\-_]{35}")
                        .expect("GoogleApiKey regex literal must compile"),
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
        for (kind, pattern) in &self.bounded_patterns {
            let (redacted, modified) = Self::redact_bounded_token(&sanitized, pattern, *kind);
            if modified && !detected.contains(kind) {
                detected.push(*kind);
            }
            sanitized = redacted;
        }
        RedactionResult {
            sanitized,
            detected,
        }
    }

    fn redact_bounded_token(input: &str, pattern: &Regex, kind: CredentialKind) -> (String, bool) {
        let mut result = String::with_capacity(input.len());
        let mut last = 0;
        let mut modified = false;

        for candidate in pattern.find_iter(input) {
            let previous = input[..candidate.start()].chars().next_back();
            let next = input[candidate.end()..].chars().next();
            let last_consumed = input[..candidate.end()].chars().next_back();
            if previous.is_some_and(|ch| Self::is_left_boundary_char(kind, ch))
                || next.is_some_and(|ch| Self::is_right_boundary_char(kind, ch, last_consumed))
            {
                continue;
            }

            result.push_str(&input[last..candidate.start()]);
            result.push_str(kind.placeholder());
            last = candidate.end();
            modified = true;
        }

        if modified {
            result.push_str(&input[last..]);
            (result, true)
        } else {
            (input.to_string(), false)
        }
    }

    /// Returns true when `ch` means the candidate token is embedded in
    /// a larger alphanumeric word and should be skipped. Only ASCII
    /// letters and digits block a match; `_`, `-`, `.` and other
    /// separators do *not*, because a real secret glued to a preceding
    /// separator (e.g. `session_sk-…`) must still be detected. The
    /// SlackToken prefix (`xox[baprs]-`) can appear inside a dashed
    /// identifier, so `-` is additionally a blocking character for
    /// that kind.
    fn is_left_boundary_char(kind: CredentialKind, ch: char) -> bool {
        match kind {
            CredentialKind::SlackToken => ch.is_ascii_alphanumeric() || ch == '-',
            _ => ch.is_ascii_alphanumeric(),
        }
    }

    /// Returns true when `ch` following the candidate means the match
    /// should be skipped. For most kinds an ASCII alphanumeric follower
    /// means the candidate is embedded in a longer token and should not
    /// match, mirroring the `(?![A-Za-z0-9])` lookahead used by the
    /// TypeScript and Python SDKs. `SlackToken` additionally blocks `-`
    /// (its value class includes `-`). `GoogleApiKey` accepts a trailing
    /// `-` followed by anything (strict superset of the old `\b`
    /// behaviour, mirroring `(?:(?![A-Za-z0-9])|(?<=-))` in the regex
    /// SDKs, see #3934).
    fn is_right_boundary_char(kind: CredentialKind, ch: char, last_consumed: Option<char>) -> bool {
        match kind {
            CredentialKind::SlackToken => ch.is_ascii_alphanumeric() || ch == '-',
            CredentialKind::GoogleApiKey => {
                // Superset rule: if the key's last consumed char is '-',
                // never skip -- mirrors (?<=-)  in the regex SDKs.
                if last_consumed == Some('-') {
                    return false;
                }
                ch.is_ascii_alphanumeric()
            }
            _ => ch.is_ascii_alphanumeric(),
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
    fn redacts_github_tokens_with_non_word_boundaries() {
        let redactor = CredentialRedactor::new();
        let token = "ghp_FAKEFORTESTING000000000000000000";
        let result = redactor.redact(&format!("({token}), {token}."));

        assert_eq!(
            result.sanitized,
            "([REDACTED_GITHUB_TOKEN]), [REDACTED_GITHUB_TOKEN]."
        );
        assert!(result.detected.contains(&CredentialKind::GitHubToken));
    }

    #[test]
    fn redacts_github_token_glued_to_underscore_prefix() {
        // The updated left boundary treats `_` as a valid edge, so a
        // GitHub token preceded by `prefix_` is now detected. This is
        // the correct behaviour: `_` is a separator, not part of the
        // token, and secrets annotated with prefixes like `session_` or
        // `env_` must be caught (issue #3933).
        let redactor = CredentialRedactor::new();
        for text in ["prefix_ghp_FAKEFORTESTING000000000000000000"] {
            let result = redactor.redact(text);
            assert_eq!(result.sanitized, "prefix_[REDACTED_GITHUB_TOKEN]");
            assert!(result.detected.contains(&CredentialKind::GitHubToken));
        }
    }

    #[test]
    fn redacts_recoverable_github_token_before_underscore_suffix() {
        let redactor = CredentialRedactor::new();
        let result = redactor.redact("ghp_FAKEFORTESTING000000000000000000_suffix");

        assert_eq!(result.sanitized, "[REDACTED_GITHUB_TOKEN]_suffix");
        assert!(result.detected.contains(&CredentialKind::GitHubToken));
    }

    #[test]
    fn redacts_modern_provider_token_patterns() {
        let redactor = CredentialRedactor::new();
        let openai_token = format!("sk-FAKEFORTESTING{}", "x".repeat(20));
        let slack_token = "xoxb-FAKE-FOR-TESTING-0000000000";
        let aws_access_key = format!("AKIA{}", "A".repeat(16));
        let google_api_key = format!("AIza{}", "A".repeat(35));

        let result = redactor.redact(&format!(
            "openai {openai_token} slack {slack_token} aws {aws_access_key} google {google_api_key}"
        ));

        assert_eq!(
            result.sanitized,
            "openai [REDACTED_OPENAI_TOKEN] slack [REDACTED_SLACK_TOKEN] aws [REDACTED_AWS_ACCESS_KEY] google [REDACTED_GOOGLE_API_KEY]"
        );
        assert!(result.detected.contains(&CredentialKind::OpenAiToken));
        assert!(result.detected.contains(&CredentialKind::SlackToken));
        assert!(result.detected.contains(&CredentialKind::AwsAccessKey));
        assert!(result.detected.contains(&CredentialKind::GoogleApiKey));
    }

    #[test]
    fn does_not_redact_malformed_provider_token_lookalikes() {
        let redactor = CredentialRedactor::new();
        let embedded_aws_access_key = format!("prefix{}", format!("AKIA{}", "A".repeat(16)));
        for text in [
            "sk-short",
            "xoxq-FAKE-FOR-TESTING-0000000000",
            embedded_aws_access_key.as_str(),
            "AIzaFAKE_FOR_TESTING_000000000000000",
        ] {
            let result = redactor.redact(text);
            assert_eq!(result.sanitized, text);
            assert!(result.detected.is_empty());
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

    // ---------------------------------------------------------------
    // Boundary regression tests for issue #3933
    // A valid credential glued to a preceding or following _
    // must still be detected and redacted.
    // ---------------------------------------------------------------

    #[test]
    fn redacts_github_token_glued_to_underscore_right_edge() {
        let redactor = CredentialRedactor::new();
        let result = redactor.redact("ghp_FAKEFORTESTING000000000000000000_old");
        assert_eq!(result.sanitized, "[REDACTED_GITHUB_TOKEN]_old");
        assert!(result.detected.contains(&CredentialKind::GitHubToken));
    }

    #[test]
    fn redacts_github_token_glued_to_underscore_left_edge() {
        let redactor = CredentialRedactor::new();
        let result = redactor.redact("session_ghp_FAKEFORTESTING000000000000000000");
        assert_eq!(
            result.sanitized,
            "session_[REDACTED_GITHUB_TOKEN]"
        );
        assert!(result.detected.contains(&CredentialKind::GitHubToken));
    }

    #[test]
    fn redacts_aws_key_glued_to_underscore_both_edges() {
        let redactor = CredentialRedactor::new();
        let result = redactor.redact("env_AKIAAAAAAAAAAAAAAAAA_old");
        assert_eq!(result.sanitized, "env_[REDACTED_AWS_ACCESS_KEY]_old");
        assert!(result.detected.contains(&CredentialKind::AwsAccessKey));
    }

    #[test]
    fn redacts_aws_key_glued_to_underscore_left_edge() {
        let redactor = CredentialRedactor::new();
        let result = redactor.redact("session_AKIAAAAAAAAAAAAAAAAA");
        assert_eq!(result.sanitized, "session_[REDACTED_AWS_ACCESS_KEY]");
        assert!(result.detected.contains(&CredentialKind::AwsAccessKey));
    }

    #[test]
    fn redacts_aws_key_glued_to_underscore_right_edge() {
        let redactor = CredentialRedactor::new();
        let result = redactor.redact("AKIAAAAAAAAAAAAAAAAA_deprecated");
        assert_eq!(
            result.sanitized,
            "[REDACTED_AWS_ACCESS_KEY]_deprecated"
        );
        assert!(result.detected.contains(&CredentialKind::AwsAccessKey));
    }

    #[test]
    fn redacts_google_key_glued_to_underscore_left_edge() {
        let redactor = CredentialRedactor::new();
        let key = format!("AIza{}", "A".repeat(35));
        let result = redactor.redact(&format!("svc_{key}"));
        assert!(result.sanitized.contains("[REDACTED_GOOGLE_API_KEY]"));
        assert!(!result.sanitized.contains(&key));
        assert!(result.detected.contains(&CredentialKind::GoogleApiKey));
    }

    #[test]
    fn redacts_google_key_glued_to_underscore_right_edge() {
        let redactor = CredentialRedactor::new();
        let key = format!("AIza{}", "A".repeat(35));
        let result = redactor.redact(&format!("{key}_old"));
        assert!(result.sanitized.contains("[REDACTED_GOOGLE_API_KEY]"));
        assert!(!result.sanitized.contains(&key));
        assert!(result.detected.contains(&CredentialKind::GoogleApiKey));
    }

    #[test]
    fn redacts_openai_token_glued_to_underscore_left_edge() {
        let redactor = CredentialRedactor::new();
        let token = format!("sk-FAKEFORTESTING{}", "x".repeat(20));
        let result = redactor.redact(&format!("session_{token}"));
        assert!(result.sanitized.contains("[REDACTED_OPENAI_TOKEN]"));
        assert!(!result.sanitized.contains(&token));
        assert!(result.detected.contains(&CredentialKind::OpenAiToken));
    }

    #[test]
    fn redacts_openai_token_glued_to_underscore_right_edge() {
        let redactor = CredentialRedactor::new();
        let token = format!("sk-FAKEFORTESTING{}", "x".repeat(20));
        let result = redactor.redact(&format!("{token}_bak"));
        assert!(result.sanitized.contains("[REDACTED_OPENAI_TOKEN]"));
        assert!(!result.sanitized.contains(&token));
        assert!(result.detected.contains(&CredentialKind::OpenAiToken));
    }

    #[test]
    fn redacts_openai_token_preceded_by_hyphen_left_edge_widening() {
        // Pinning test: hyphen-prefixed OpenAI keys ARE redacted, aligning
        // with the Python SDK's (?<![A-Za-z0-9]) anchor.  See audit doc
        // "OpenAI left-edge widening" section.
        let redactor = CredentialRedactor::new();
        let token = format!("sk-FAKEFORTESTING{}", "x".repeat(20));
        let result = redactor.redact(&format!("my-{token}"));
        assert!(result.sanitized.contains("[REDACTED_OPENAI_TOKEN]"));
        assert!(!result.sanitized.contains(&token));
        assert!(result.detected.contains(&CredentialKind::OpenAiToken));
    }

    #[test]
    fn redacts_google_api_key_ending_in_hyphen_when_glued() {
        // Superset rule: a key whose last value char is '-' followed by
        // alnum must still be redacted, mirroring (?:(?![A-Za-z0-9])|(?<=-))
        // in the regex SDKs.
        let redactor = CredentialRedactor::new();
        let key = format!("AIza{}-", "A".repeat(34));
        let input = format!("{key}X");
        let result = redactor.redact(&input);
        assert!(
            result.sanitized.contains("[REDACTED_GOOGLE_API_KEY]"),
            "Google key ending in '-' followed by 'X' should be redacted: got '{}'",
            result.sanitized
        );
    }

    #[test]
    fn still_rejects_alphanumeric_embedded_credentials() {
        // The fix must not create false positives: a token prefix
        // embedded inside a contiguous alphanumeric word is not a
        // real credential.
        let redactor = CredentialRedactor::new();
        for text in [
            "fooghp_FAKEFORTESTING000000000000000000",
            "0AKIAAAAAAAAAAAAAAAAA",
        ] {
            let result = redactor.redact(text);
            assert_eq!(result.sanitized, text);
            assert!(result.detected.is_empty());
        }
    }

    #[test]
    fn redacts_multiple_underscore_glued_credentials_in_one_pass() {
        let redactor = CredentialRedactor::new();
        let aws = format!("AKIA{}", "A".repeat(16));
        let github = "ghp_FAKEFORTESTING000000000000000000";
        let google = format!("AIza{}", "A".repeat(35));
        let openai = format!("sk-FAKEFORTESTING{}", "x".repeat(20));

        let input = format!(
            "env_{aws}_old cfg_{github}_rotated svc_{google}_deprecated session_{openai}_bak"
        );
        let result = redactor.redact(&input);

        assert!(!result.sanitized.contains(&aws));
        assert!(!result.sanitized.contains(github));
        assert!(!result.sanitized.contains(&google));
        assert!(!result.sanitized.contains(&openai));
        assert!(result.detected.contains(&CredentialKind::AwsAccessKey));
        assert!(result.detected.contains(&CredentialKind::GitHubToken));
        assert!(result.detected.contains(&CredentialKind::GoogleApiKey));
        assert!(result.detected.contains(&CredentialKind::OpenAiToken));
    }
}
