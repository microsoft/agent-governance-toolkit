use crate::{Decision, EnforcementMode, InterventionPoint};
use std::collections::BTreeMap;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TelemetryEventType {
    Decision,
    AnnotatorDispatch,
    PolicyEvaluation,
    EvaluationTiming,
    /// AGT D2: the runtime emits this event in addition to `Decision`
    /// whenever the verdict is `Decision::Transform`. Wire name is
    /// `intervention_point.transformed` per AGT-EVIDENCE-1.0 §3.
    InterventionPointTransformed,
    AnnotatorFailed,
    PolicyFailed,
}

impl TelemetryEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::AnnotatorDispatch => "annotator_dispatch",
            Self::PolicyEvaluation => "policy_evaluation",
            Self::EvaluationTiming => "evaluation_timing",
            Self::InterventionPointTransformed => "intervention_point.transformed",
            Self::AnnotatorFailed => "annotator_failed",
            Self::PolicyFailed => "policy_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TelemetryEvent {
    pub event_type: TelemetryEventType,
    pub intervention_point: InterventionPoint,
    pub decision: Option<Decision>,
    pub reason_code: Option<String>,
    pub error_class: Option<String>,
    pub policy_id: Option<String>,
    pub annotators: Vec<String>,
    pub enforcement_mode: Option<EnforcementMode>,
    pub duration_ms: Option<f64>,
    /// AGT D2 / AGT-EVIDENCE-1.0 §3 verbatim `artefact` string from the
    /// originating verdict's `evidence` payload. `None` when the verdict
    /// carried no evidence.
    pub evidence_artefact: Option<String>,
    /// AGT D2 / AGT-EVIDENCE-1.0 §3 sorted keys (not values) of the
    /// originating verdict's `evidence.verification_pointers` map. Empty
    /// when no pointers were attached. The URL values are intentionally
    /// omitted to keep telemetry cardinality bounded; auditors recover
    /// them from the audit record.
    pub evidence_verification_pointer_keys: Vec<String>,
    pub action_identity: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

impl TelemetryEvent {
    pub fn new(event_type: TelemetryEventType, intervention_point: InterventionPoint) -> Self {
        Self {
            event_type,
            intervention_point,
            decision: None,
            reason_code: None,
            error_class: None,
            policy_id: None,
            annotators: Vec::new(),
            enforcement_mode: None,
            duration_ms: None,
            evidence_artefact: None,
            evidence_verification_pointer_keys: Vec::new(),
            action_identity: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.reason_code = Some(reason_code.into());
        self
    }

    pub fn with_optional_reason_code(mut self, reason_code: Option<&str>) -> Self {
        self.reason_code = reason_code.map(str::to_string);
        self
    }

    pub fn with_error_class(mut self, error_class: impl Into<String>) -> Self {
        self.error_class = Some(error_class.into());
        self
    }

    pub fn with_optional_error_class(mut self, error_class: Option<&str>) -> Self {
        self.error_class = error_class.map(str::to_string);
        self
    }

    pub fn with_policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    pub fn with_optional_policy_id(mut self, policy_id: Option<&str>) -> Self {
        self.policy_id = policy_id.map(str::to_string);
        self
    }

    pub fn with_annotator(mut self, annotator: impl Into<String>) -> Self {
        self.annotators.push(annotator.into());
        self
    }

    pub fn with_annotators(mut self, annotators: Vec<String>) -> Self {
        self.annotators = annotators;
        self
    }

    pub fn with_enforcement_mode(mut self, mode: EnforcementMode) -> Self {
        self.enforcement_mode = Some(mode);
        self
    }

    pub fn with_duration_ms(mut self, duration_ms: f64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_action_identity(mut self, action_identity: impl Into<String>) -> Self {
        self.action_identity = Some(action_identity.into());
        self
    }

    pub fn with_optional_action_identity(mut self, action_identity: Option<&str>) -> Self {
        self.action_identity = action_identity.map(str::to_string);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: impl Into<String>) -> Self {
        self.metadata.insert(key.to_string(), value.into());
        self
    }

    /// Attach AGT D2 / AGT-EVIDENCE-1.0 §3 evidence fields from the
    /// originating verdict. `artefact` is forwarded verbatim; the pointer
    /// map is reduced to its sorted keys so the URL values never reach
    /// telemetry sinks.
    pub fn with_evidence(mut self, artefact: Option<&str>, pointer_keys: Vec<String>) -> Self {
        self.evidence_artefact = artefact.map(str::to_string);
        self.evidence_verification_pointer_keys = pointer_keys;
        self
    }

    /// Serialize to a redaction-safe JSON object carrying only the structural
    /// telemetry fields. Every field here is a stable id, name, decision, mode,
    /// reason code, count, duration, evidence artefact, or sorted pointer key.
    /// No policy-target payload, snapshot, annotator output, transform value, or
    /// pointer URL is present, so the serialized form is safe to ship to a sink.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event_type": self.event_type.as_str(),
            "intervention_point": self.intervention_point.as_str(),
            "decision": self.decision.map(|decision| decision.as_str()),
            "reason_code": self.reason_code,
            "error_class": self.error_class,
            "policy_id": self.policy_id,
            "annotators": self.annotators,
            "enforcement_mode": self.enforcement_mode.map(|mode| mode.as_str()),
            "duration_ms": self.duration_ms,
            "evidence_artefact": self.evidence_artefact,
            "evidence_verification_pointer_keys": self.evidence_verification_pointer_keys,
            "action_identity": self.action_identity,
            "metadata": self.metadata,
        })
    }
}

pub trait TelemetrySink: Send + Sync {
    fn emit(&self, event: TelemetryEvent);

    /// Flush any buffered telemetry. A no-op by default; sinks that batch (for
    /// example an OpenTelemetry exporter) override it. Mirrors the host-side
    /// SDK sink shape across languages.
    fn force_flush(&self) {}

    fn shutdown(&self) {}
}

#[derive(Debug, Default)]
pub struct NoopTelemetrySink;

impl TelemetrySink for NoopTelemetrySink {
    fn emit(&self, _event: TelemetryEvent) {}
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

/// Writes one redaction-safe JSON object per line to a `Write` target,
/// defaulting to stdout. The audit.jsonl use case becomes built in.
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

    fn force_flush(&self) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.flush();
        }
    }

    fn shutdown(&self) {
        self.force_flush();
    }
}

/// Fans one event out to several sinks. A panicking child is isolated so it
/// cannot starve the others or reach the evaluation path. Telemetry is never
/// load-bearing.
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

    fn force_flush(&self) {
        for sink in &self.sinks {
            let sink = Arc::clone(sink);
            let _ = catch_unwind(AssertUnwindSafe(move || sink.force_flush()));
        }
    }

    fn shutdown(&self) {
        for sink in &self.sinks {
            let sink = Arc::clone(sink);
            let _ = catch_unwind(AssertUnwindSafe(move || sink.shutdown()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_metadata_carries_artefact_and_sorted_keys() {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_evidence(
                Some("sha256:abcd"),
                vec!["issuer_pubkey".to_string(), "policy_registry".to_string()],
            );
        assert_eq!(event.evidence_artefact.as_deref(), Some("sha256:abcd"));
        assert_eq!(
            event.evidence_verification_pointer_keys,
            vec!["issuer_pubkey", "policy_registry"]
        );
    }

    #[test]
    fn evidence_metadata_is_clean_when_no_evidence_attached() {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input);
        assert!(event.evidence_artefact.is_none());
        assert!(event.evidence_verification_pointer_keys.is_empty());
    }

    #[test]
    fn intervention_point_transformed_event_uses_spec_wire_name() {
        // AGT D2 wire-name contract per AGT-EVIDENCE-1.0 §3.
        let event = TelemetryEvent::new(
            TelemetryEventType::InterventionPointTransformed,
            InterventionPoint::Output,
        );
        assert_eq!(event.event_type.as_str(), "intervention_point.transformed");
    }

    #[test]
    fn in_memory_sink_records_events_in_order() {
        let sink = InMemoryTelemetrySink::new();
        sink.emit(
            TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
                .with_decision(Decision::Allow),
        );
        sink.emit(
            TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Output)
                .with_decision(Decision::Deny),
        );
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision, Some(Decision::Allow));
        assert_eq!(events[1].decision, Some(Decision::Deny));
    }

    #[test]
    fn to_json_emits_only_safe_fields_and_withholds_pointer_urls() {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_decision(Decision::Deny)
            .with_reason_code("policy_reason")
            .with_evidence(
                Some("sha256:proofblob"),
                vec!["issuer_pubkey".to_string(), "policy_registry".to_string()],
            )
            .with_action_identity("sha256:abc");
        let value = event.to_json();
        let object = value.as_object().expect("json object");
        let expected: std::collections::BTreeSet<&str> = [
            "event_type",
            "intervention_point",
            "decision",
            "reason_code",
            "error_class",
            "policy_id",
            "annotators",
            "enforcement_mode",
            "duration_ms",
            "evidence_artefact",
            "evidence_verification_pointer_keys",
            "action_identity",
            "metadata",
        ]
        .into_iter()
        .collect();
        let actual: std::collections::BTreeSet<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(actual, expected);
        // Sorted pointer keys only; no URL value can appear.
        let serialized = value.to_string();
        assert!(serialized.contains("issuer_pubkey"));
        assert!(!serialized.contains("https://"));
    }

    #[test]
    fn stdout_json_sink_writes_one_object_per_line() {
        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = StdoutJsonTelemetrySink::to_writer(SharedWriter(Arc::clone(&buffer)));
        sink.emit(
            TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
                .with_decision(Decision::Allow),
        );
        sink.emit(
            TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Output)
                .with_decision(Decision::Warn),
        );
        let written = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"decision\":\"allow\""));
        assert!(lines[1].contains("\"decision\":\"warn\""));
    }

    #[test]
    fn multi_sink_fans_out_and_isolates_a_panicking_child() {
        struct PanicSink;
        impl TelemetrySink for PanicSink {
            fn emit(&self, _event: TelemetryEvent) {
                panic!("child sink boom");
            }
        }
        let good = Arc::new(InMemoryTelemetrySink::new());
        let multi = MultiSink::new(vec![Arc::new(PanicSink), good.clone()]);
        multi.emit(
            TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
                .with_decision(Decision::Allow),
        );
        assert_eq!(good.len(), 1);
    }
}
