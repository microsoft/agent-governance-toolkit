// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Telemetry sinks retained by AGT.
//!
//! `agent_control_spec` ships the `TelemetrySink` trait and a no-op
//! implementation. The richer sinks below were AGT additions and stay
//! here. They implement the ACS trait, so this is an additive layer rather
//! than a redefinition of the policy plane contract.
//!
//! Two deltas against the embedded engine. The ACS trait has no
//! `force_flush`, so `StdoutJsonTelemetrySink` keeps it as an inherent
//! method and `MultiSink` no longer fans a flush out through
//! `dyn TelemetrySink`. Nothing in AGT called it through the trait.
//! `TelemetryEvent` no longer carries `to_json`, so the JSON projection
//! lives here as [`TelemetryEventExt`].

use agent_control_spec::telemetry::{TelemetryEvent, TelemetrySink};
use agent_control_spec::EnforcementMode;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

/// The redaction safe JSON projection of a telemetry event. Was
/// `TelemetryEvent::to_json` on the embedded engine.
pub trait TelemetryEventExt {
    fn to_json(&self) -> serde_json::Value;
}

impl TelemetryEventExt for TelemetryEvent {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event_type": self.event_type.as_str(),
            "intervention_point": self.intervention_point.as_str(),
            "decision": self.decision.map(|decision| decision.as_str()),
            "reason_code": self.reason_code,
            "error_class": self.error_class,
            "policy_id": self.policy_id,
            "annotators": self.annotators,
            "enforcement_mode": self.enforcement_mode.map(|mode| match mode {
                EnforcementMode::Enforce => "enforce",
                EnforcementMode::EvaluateOnly => "evaluate_only",
            }),
            "duration_ms": self.duration_ms,
            "evidence_artefact": self.evidence_artefact,
            "evidence_verification_pointer_keys": self.evidence_verification_pointer_keys,
            "action_identity": self.action_identity,
            "metadata": self.metadata,
        })
    }
}

/// Records every emitted event in order. For tests and local inspection.
#[derive(Debug, Default)]
pub struct InMemoryTelemetrySink {
    events: Mutex<Vec<TelemetryEvent>>,
}

impl InMemoryTelemetrySink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the events recorded so far, in emission order.
    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.events
            .lock()
            .expect("telemetry mutex poisoned")
            .clone()
    }

    pub fn len(&self) -> usize {
        self.events.lock().expect("telemetry mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.events
            .lock()
            .expect("telemetry mutex poisoned")
            .is_empty()
    }

    pub fn clear(&self) {
        self.events
            .lock()
            .expect("telemetry mutex poisoned")
            .clear();
    }
}

impl TelemetrySink for InMemoryTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        self.events
            .lock()
            .expect("telemetry mutex poisoned")
            .push(event);
    }
}

/// Writes one redaction safe JSON object per line to a `Write` target,
/// defaulting to stdout. Covers the audit.jsonl use case.
pub struct StdoutJsonTelemetrySink {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl StdoutJsonTelemetrySink {
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(Box::new(std::io::stdout())),
        }
    }

    /// Write JSON lines to an arbitrary target, for example a file handle.
    pub fn to_writer(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Mutex::new(Box::new(writer)),
        }
    }

    /// Flush buffered output. Inherent here because the
    /// `agent_control_spec` `TelemetrySink` trait has no `force_flush`.
    pub fn force_flush(&self) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.flush();
        }
    }
}

impl Default for StdoutJsonTelemetrySink {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetrySink for StdoutJsonTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        let line = event.to_json().to_string();
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{line}");
        }
    }

    fn shutdown(&self) {
        self.force_flush();
    }
}

/// Fans one event out to several sinks. A panicking child is isolated so
/// it cannot starve the others or reach the evaluation path. Telemetry is
/// never load bearing.
pub struct MultiSink {
    sinks: Vec<Arc<dyn TelemetrySink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Arc<dyn TelemetrySink>>) -> Self {
        Self { sinks }
    }
}

impl TelemetrySink for MultiSink {
    fn emit(&self, event: TelemetryEvent) {
        for sink in &self.sinks {
            let sink = Arc::clone(sink);
            let event = event.clone();
            let _ = catch_unwind(AssertUnwindSafe(move || sink.emit(event)));
        }
    }

    fn shutdown(&self) {
        for sink in &self.sinks {
            let sink = Arc::clone(sink);
            let _ = catch_unwind(AssertUnwindSafe(move || sink.shutdown()));
        }
    }
}
