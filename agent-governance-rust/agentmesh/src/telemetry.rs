// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Feature-gated telemetry hooks for embedding applications.
//!
//! The telemetry surface is intentionally explicit and data-minimizing: callers
//! install a sink, and governance code sends sanitized policy-evaluation events.
//! Raw actions, agent IDs, policy text, prompt text, and rule bodies are not
//! emitted as attributes.

use crate::PolicyDecision;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Sanitized metadata for one policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTelemetryEvent {
    /// Short decision label, such as `allow`, `deny`, or `rate_limited`.
    pub decision_label: &'static str,
    /// Whether the decision permits the action.
    pub allowed: bool,
    /// Policy-evaluation elapsed time.
    pub elapsed: Duration,
    /// SHA-256 hash of the action string.
    pub action_hash: String,
    /// Length of the action string in bytes, retained for coarse debugging.
    pub action_len_bytes: usize,
    /// SHA-256 hash of the agent identity DID.
    pub agent_id_hash: String,
}

impl PolicyTelemetryEvent {
    /// Build a sanitized telemetry event from raw governance inputs.
    pub fn new(agent_id: &str, action: &str, decision: &PolicyDecision, elapsed: Duration) -> Self {
        Self {
            decision_label: decision.label(),
            allowed: decision.is_allowed(),
            elapsed,
            action_hash: hex_sha256(action),
            action_len_bytes: action.len(),
            agent_id_hash: hex_sha256(agent_id),
        }
    }
}

/// Sink for sanitized AgentMesh telemetry events.
///
/// Sinks return `()` so telemetry cannot force a governance decision to fail or
/// succeed. `AgentMeshClient` also guards sink calls against unwinding.
pub trait TelemetrySink: Send + Sync {
    /// Record one policy-evaluation event.
    fn record_policy_evaluation(&self, event: &PolicyTelemetryEvent);
}

/// Default sink used when telemetry is enabled but no sink is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTelemetrySink;

impl TelemetrySink for NoopTelemetrySink {
    fn record_policy_evaluation(&self, _event: &PolicyTelemetryEvent) {}
}

/// OpenTelemetry sink that emits one span per policy evaluation.
///
/// The embedding application remains responsible for configuring the global
/// OpenTelemetry provider/exporter. With the default global no-op provider, this
/// sink is safe and silent.
#[derive(Debug, Clone)]
pub struct OtelTelemetrySink {
    instrumentation_name: &'static str,
}

impl OtelTelemetrySink {
    /// Create a sink using the default `agentmesh` instrumentation name.
    pub fn new() -> Self {
        Self {
            instrumentation_name: "agentmesh",
        }
    }

    /// Create a sink with a caller-supplied instrumentation name.
    pub fn with_instrumentation_name(instrumentation_name: &'static str) -> Self {
        Self {
            instrumentation_name,
        }
    }
}

impl Default for OtelTelemetrySink {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetrySink for OtelTelemetrySink {
    fn record_policy_evaluation(&self, event: &PolicyTelemetryEvent) {
        use opentelemetry::trace::{Span, Tracer};
        use opentelemetry::{global, KeyValue};

        let tracer = global::tracer(self.instrumentation_name);
        let mut span = tracer.start("agentmesh.policy.evaluate");
        span.set_attribute(KeyValue::new(
            "agentmesh.policy.decision",
            event.decision_label,
        ));
        span.set_attribute(KeyValue::new("agentmesh.policy.allowed", event.allowed));
        span.set_attribute(KeyValue::new(
            "agentmesh.policy.elapsed_ms",
            event.elapsed.as_secs_f64() * 1000.0,
        ));
        span.set_attribute(KeyValue::new(
            "agentmesh.policy.action_hash",
            event.action_hash.clone(),
        ));
        span.set_attribute(KeyValue::new(
            "agentmesh.policy.action_len_bytes",
            event.action_len_bytes as i64,
        ));
        span.set_attribute(KeyValue::new(
            "agentmesh.agent.id_hash",
            event.agent_id_hash.clone(),
        ));
        if !event.allowed {
            span.set_status(opentelemetry::trace::Status::error(
                "policy_decision_not_allowed",
            ));
        }
        span.end();
    }
}

/// Return the lowercase hexadecimal SHA-256 digest for a value.
pub fn hex_sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}
