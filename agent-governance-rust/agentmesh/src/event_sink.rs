// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pluggable [`GovernanceEventSink`] — provider interface (SPI) for governance event routing.
//!
//! Defines the sink trait and two reference implementations:
//!
//! * [`StdoutEventSink`] — writes JSON to stdout; suitable for development and CI.
//! * [`OtlpEventSink`] — writes OTLP-formatted JSON to a [`std::io::Write`] target
//!   (file, pipe, or stdout) for collection by an OTLP-capable backend.
//!
//! # Architecture
//!
//! AGT emits structured, signed governance events; the *sink* routes them to external
//! observability and enforcement backends. This project does not implement OS-level
//! enforcement — that is the responsibility of the backend (Defender, Falco, Tetragon, etc.).
//!
//! # Event Categories
//!
//! Aligned with CloudEvents + OTEL semantic conventions:
//!
//! | Category            | Description                                              |
//! |---------------------|----------------------------------------------------------|
//! | `policy.decision`   | Policy allow/deny/warn/require-approval outcome          |
//! | `policy.breach`     | Policy violation detected                                |
//! | `identity.assertion`| Agent identity claim or verification result              |
//! | `tool.invocation`   | Tool call intercepted before execution                   |
//! | `sandbox.event`     | Sandbox lifecycle event (create, execute, destroy)       |
//! | `audit.chain`       | Hash-chain audit entry emitted                           |
//!
//! # Example
//!
//! ```rust
//! use agentmesh::event_sink::{GovernanceEventCategory, SignedGovernanceEvent, StdoutEventSink};
//! use agentmesh::event_sink::GovernanceEventSink;
//!
//! let sink = StdoutEventSink;
//! let event = SignedGovernanceEvent::build(
//!     GovernanceEventCategory::PolicyDecision,
//!     "did:agentmesh:agent-1",
//!     "tool:file_write",
//!     serde_json::json!({"decision": "deny", "reason": "path blocked"}),
//!     None,
//! );
//! sink.emit(&event);
//! ```

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Event categories
// ---------------------------------------------------------------------------

/// Categories of governance events emitted through the [`GovernanceEventSink`] SPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceEventCategory {
    /// A policy allow/deny/warn/require-approval outcome was produced.
    PolicyDecision,
    /// A policy violation (breach) was detected.
    PolicyBreach,
    /// An agent identity claim or verification result was produced.
    IdentityAssertion,
    /// A tool call was intercepted before execution.
    ToolInvocation,
    /// A sandbox lifecycle event occurred.
    SandboxEvent,
    /// A hash-chain audit entry was emitted.
    AuditChain,
}

impl GovernanceEventCategory {
    /// Returns the full CloudEvents `type` string for this category.
    pub fn cloud_event_type(&self) -> &'static str {
        match self {
            Self::PolicyDecision => "ai.agentmesh.policy.decision",
            Self::PolicyBreach => "ai.agentmesh.policy.breach",
            Self::IdentityAssertion => "ai.agentmesh.identity.assertion",
            Self::ToolInvocation => "ai.agentmesh.tool.invocation",
            Self::SandboxEvent => "ai.agentmesh.sandbox.event",
            Self::AuditChain => "ai.agentmesh.audit.chain",
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical signed event envelope
// ---------------------------------------------------------------------------

/// CloudEvents 1.0 envelope with HMAC-SHA256 tamper-evidence signature.
///
/// Fields follow the [CloudEvents specification](https://github.com/cloudevents/spec).
/// The `signature` extension field is an HMAC-SHA256 of the canonical form:
/// ```text
/// "{type}\n{source}\n{time}\n{id}\n{data_json}"
/// ```
/// When no signing key is supplied, `signature` is left empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGovernanceEvent {
    /// CloudEvents specification version. Always `"1.0"`.
    pub specversion: String,
    /// Unique event identifier.
    pub id: String,
    /// CloudEvents type string, e.g. `"ai.agentmesh.policy.decision"`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Agent DID or service URI that produced the event.
    pub source: String,
    /// ISO 8601 UTC timestamp.
    pub time: String,
    /// Content type. Always `"application/json"`.
    pub datacontenttype: String,
    /// Tool name, resource path, or context-specific subject.
    pub subject: String,
    /// Event-specific payload.
    pub data: serde_json::Value,
    /// HMAC-SHA256 hex signature of the canonical form. Empty when unsigned.
    pub signature: String,
}

impl SignedGovernanceEvent {
    /// Constructs and optionally signs a [`SignedGovernanceEvent`].
    ///
    /// # Arguments
    ///
    /// * `category`    — The governance event category.
    /// * `source`      — Agent DID or service URI.
    /// * `subject`     — Tool name, resource, or subject string.
    /// * `data`        — Arbitrary JSON event payload.
    /// * `signing_key` — Raw bytes for HMAC-SHA256 signing. `None` = unsigned.
    pub fn build(
        category: GovernanceEventCategory,
        source: &str,
        subject: &str,
        data: serde_json::Value,
        signing_key: Option<&[u8]>,
    ) -> Self {
        let now = iso8601_now();
        let id = generate_id();
        let event_type = category.cloud_event_type().to_owned();
        let data_json = serde_json::to_string(&data).unwrap_or_default();

        let signature = if let Some(key) = signing_key {
            let canonical = format!("{}\n{}\n{}\n{}\n{}", event_type, source, now, id, data_json);
            hmac_sha256_hex(key, &canonical)
        } else {
            String::new()
        };

        Self {
            specversion: "1.0".to_owned(),
            id,
            event_type,
            source: source.to_owned(),
            time: now,
            datacontenttype: "application/json".to_owned(),
            subject: subject.to_owned(),
            data,
            signature,
        }
    }

    /// Verifies the HMAC-SHA256 signature against `signing_key`.
    ///
    /// Returns `true` if valid; `false` if invalid or unsigned.
    pub fn verify_signature(&self, signing_key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let data_json = serde_json::to_string(&self.data).unwrap_or_default();
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.event_type, self.source, self.time, self.id, data_json
        );
        let expected = hmac_sha256_hex(signing_key, &canonical);
        constant_time_eq(&expected, &self.signature)
    }

    /// Serialises the event to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Sink trait
// ---------------------------------------------------------------------------

/// Provider interface (SPI) for governance event routing.
///
/// One method — [`GovernanceEventSink::emit`] — takes a [`SignedGovernanceEvent`]
/// and forwards it to the configured backend. Mirrors the `SandboxProvider` shape.
///
/// Reference implementations:
/// * [`StdoutEventSink`] — JSON to stdout (dev/CI)
/// * [`OtlpEventSink`]   — OTLP JSON to a writer (Defender, Sentinel, Splunk, …)
pub trait GovernanceEventSink: Send + Sync {
    /// Emit a governance event to the configured backend.
    fn emit(&self, event: &SignedGovernanceEvent);
}

// ---------------------------------------------------------------------------
// Reference sink: Stdout
// ---------------------------------------------------------------------------

/// Reference [`GovernanceEventSink`] that writes governance events as JSON lines
/// to `stdout`.
///
/// Suitable for development, CI, and container environments where stdout is
/// collected by a log aggregator (Fluentd, Vector, Logstash, etc.).
pub struct StdoutEventSink;

impl GovernanceEventSink for StdoutEventSink {
    fn emit(&self, event: &SignedGovernanceEvent) {
        println!("{}", event.to_json());
    }
}

// ---------------------------------------------------------------------------
// Reference sink: OTLP (writer-based)
// ---------------------------------------------------------------------------

/// Reference [`GovernanceEventSink`] that writes OTLP-formatted JSON lines to
/// a configurable [`std::io::Write`] target.
///
/// The output format is OTLP JSON (`/v1/logs` compatible) and can be piped to
/// an OpenTelemetry Collector, written to a file for Filebeat/Vector collection,
/// or forwarded to any OTLP-capable backend (Defender, Sentinel, Splunk, etc.).
///
/// # Example
///
/// ```rust
/// use agentmesh::event_sink::{OtlpEventSink, GovernanceEventCategory, SignedGovernanceEvent};
/// use agentmesh::event_sink::GovernanceEventSink;
///
/// // Write to stderr (e.g. for container log collection)
/// let sink = OtlpEventSink::new(std::io::stderr());
/// let event = SignedGovernanceEvent::build(
///     GovernanceEventCategory::PolicyDecision,
///     "did:agentmesh:agent-1",
///     "tool:web_search",
///     serde_json::json!({"decision": "allow"}),
///     None,
/// );
/// sink.emit(&event);
/// ```
pub struct OtlpEventSink<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> OtlpEventSink<W> {
    /// Create a new [`OtlpEventSink`] that writes to the given writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<W: Write + Send + Sync> GovernanceEventSink for OtlpEventSink<W> {
    fn emit(&self, event: &SignedGovernanceEvent) {
        // Wrap as a minimal OTLP LogsData JSON payload.
        let time_unix_nano = system_time_unix_nano();
        let signed = !event.signature.is_empty();

        let attributes = vec![
            otlp_str_attr("event.domain", "agent_governance"),
            otlp_str_attr("event.name", "governance_event"),
            otlp_str_attr("agt.governance.event.type", &event.event_type),
            otlp_str_attr("agt.governance.event.source", &event.source),
            otlp_str_attr("agt.governance.event.subject", &event.subject),
            otlp_str_attr("agt.governance.event.id", &event.id),
            otlp_bool_attr("agt.governance.event.signed", signed),
        ];

        let payload = serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": { "stringValue": "agent-governance-toolkit" }
                    }]
                },
                "scopeLogs": [{
                    "scope": { "name": "agentmesh.event_sink" },
                    "logRecords": [{
                        "timeUnixNano": time_unix_nano.to_string(),
                        "severityNumber": 9,
                        "severityText": "INFO",
                        "body": { "stringValue": event.to_json() },
                        "attributes": attributes,
                    }]
                }]
            }]
        });

        if let Ok(json) = serde_json::to_string(&payload) {
            if let Ok(mut w) = self.writer.lock() {
                let _ = writeln!(w, "{}", json);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hmac_sha256_hex(key: &[u8], input: &str) -> String {
    // HMAC-SHA256 accepts any key length (pads/hashes internally),
    // so new_from_slice only fails for truly invalid sizes (never for SHA-256).
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(input.as_bytes());
    let result = mac.finalize().into_bytes();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_id() -> String {
    // Use timestamp + simple counter as a lightweight UUID substitute.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("evt-{:x}-{:x}", ts, count)
}

fn iso8601_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d_val = doy - (153 * mp + 2) / 5 + 1;
    let m_val = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_val = if m_val <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y_val, m_val, d_val, hours, minutes, seconds
    )
}

fn system_time_unix_nano() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn otlp_str_attr(key: &str, value: &str) -> serde_json::Value {
    serde_json::json!({ "key": key, "value": { "stringValue": value } })
}

fn otlp_bool_attr(key: &str, value: bool) -> serde_json::Value {
    serde_json::json!({ "key": key, "value": { "boolValue": value } })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_creates_required_fields() {
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::PolicyDecision,
            "did:agentmesh:agent-1",
            "tool:file_write",
            serde_json::json!({"decision": "deny"}),
            None,
        );
        assert_eq!(evt.specversion, "1.0");
        assert_eq!(evt.event_type, "ai.agentmesh.policy.decision");
        assert_eq!(evt.source, "did:agentmesh:agent-1");
        assert_eq!(evt.subject, "tool:file_write");
        assert_eq!(evt.datacontenttype, "application/json");
        assert!(!evt.id.is_empty());
        assert!(!evt.time.is_empty());
        assert!(evt.signature.is_empty(), "no key → no signature");
    }

    #[test]
    fn build_with_signing_key_sets_signature() {
        let key = b"test-key-32-bytes-for-hmac-sha256";
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::PolicyBreach,
            "did:agentmesh:agent-2",
            "tool:shell:rm",
            serde_json::json!({"reason": "dangerous command"}),
            Some(key),
        );
        assert!(!evt.signature.is_empty());
        assert_eq!(evt.signature.len(), 64); // 32 bytes HMAC-SHA256 = 64 hex chars
    }

    #[test]
    fn verify_signature_valid() {
        let key = b"test-signing-key-12345678901234";
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::ToolInvocation,
            "did:agentmesh:agent-3",
            "tool:web_search",
            serde_json::json!({"query": "open source"}),
            Some(key),
        );
        assert!(evt.verify_signature(key));
    }

    #[test]
    fn verify_signature_wrong_key_returns_false() {
        let key = b"correct-key-1234567890123456789";
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::ToolInvocation,
            "did:agentmesh:agent-3",
            "tool:web_search",
            serde_json::json!({}),
            Some(key),
        );
        let wrong_key = b"wrong-signing-key-for-test-only";
        assert!(!evt.verify_signature(wrong_key));
    }

    #[test]
    fn verify_signature_unsigned_returns_false() {
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::AuditChain,
            "did:agentmesh:agent-4",
            "",
            serde_json::json!({}),
            None,
        );
        assert!(!evt.verify_signature(b"any-key"));
    }

    #[test]
    fn cloud_event_types_are_correct() {
        assert_eq!(
            GovernanceEventCategory::PolicyDecision.cloud_event_type(),
            "ai.agentmesh.policy.decision"
        );
        assert_eq!(
            GovernanceEventCategory::PolicyBreach.cloud_event_type(),
            "ai.agentmesh.policy.breach"
        );
        assert_eq!(
            GovernanceEventCategory::IdentityAssertion.cloud_event_type(),
            "ai.agentmesh.identity.assertion"
        );
        assert_eq!(
            GovernanceEventCategory::ToolInvocation.cloud_event_type(),
            "ai.agentmesh.tool.invocation"
        );
        assert_eq!(
            GovernanceEventCategory::SandboxEvent.cloud_event_type(),
            "ai.agentmesh.sandbox.event"
        );
        assert_eq!(
            GovernanceEventCategory::AuditChain.cloud_event_type(),
            "ai.agentmesh.audit.chain"
        );
    }

    #[test]
    fn stdout_sink_emits_without_panic() {
        let sink = StdoutEventSink;
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::PolicyDecision,
            "did:agentmesh:agent-1",
            "tool:test",
            serde_json::json!({"ok": true}),
            None,
        );
        // Should not panic
        sink.emit(&evt);
    }

    #[test]
    fn otlp_sink_writes_valid_json() {
        let buf: Vec<u8> = Vec::new();
        let sink = OtlpEventSink::new(std::io::Cursor::new(buf));
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::PolicyDecision,
            "did:agentmesh:agent-1",
            "tool:test",
            serde_json::json!({"decision": "allow"}),
            None,
        );
        sink.emit(&evt);
        // Verify JSON was written
        let written = sink.writer.lock().unwrap();
        let text = std::str::from_utf8(written.get_ref()).unwrap();
        assert!(!text.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert!(parsed["resourceLogs"].is_array());
    }

    #[test]
    fn to_json_roundtrip() {
        let evt = SignedGovernanceEvent::build(
            GovernanceEventCategory::SandboxEvent,
            "did:agentmesh:agent-1",
            "sandbox:create",
            serde_json::json!({"session_id": "s1"}),
            None,
        );
        let json = evt.to_json();
        let parsed: SignedGovernanceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type, evt.event_type);
        assert_eq!(parsed.source, evt.source);
        assert_eq!(parsed.id, evt.id);
    }

    #[test]
    fn iso8601_now_format() {
        let ts = iso8601_now();
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[19..20], "Z");
    }

    #[test]
    fn all_categories_have_distinct_types() {
        let cats = [
            GovernanceEventCategory::PolicyDecision,
            GovernanceEventCategory::PolicyBreach,
            GovernanceEventCategory::IdentityAssertion,
            GovernanceEventCategory::ToolInvocation,
            GovernanceEventCategory::SandboxEvent,
            GovernanceEventCategory::AuditChain,
        ];
        let types: Vec<_> = cats.iter().map(|c| c.cloud_event_type()).collect();
        let deduped: std::collections::HashSet<_> = types.iter().collect();
        assert_eq!(types.len(), deduped.len(), "all categories must have distinct event types");
    }
}
