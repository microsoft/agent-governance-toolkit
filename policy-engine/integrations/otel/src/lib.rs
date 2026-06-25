use agent_control_specification_core::{TelemetryEvent, TelemetryEventType, TelemetrySink};
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::{InstrumentationScope, KeyValue};
use std::collections::HashMap;

pub const DEFAULT_OTEL_METER_NAME: &str = "agent_control_specification";

// AGT D1.1: `transform` is the fifth wire decision per
// SPECIFICATION.md §13.1. OtelTelemetrySink builds one
// counter per decision so the transform path is observable alongside
// allow / deny / warn / escalate.
const DECISION_WIRE_STRINGS: &[&str] = &["allow", "deny", "warn", "escalate", "transform"];

pub struct OtelTelemetrySink {
    meter_name: String,
    decision_counters: HashMap<String, Counter<f64>>,
    duration_histogram: Histogram<f64>,
}

impl OtelTelemetrySink {
    pub fn new(meter_name: &str) -> Self {
        let scope = InstrumentationScope::builder(meter_name.to_string()).build();
        let meter = global::meter_with_scope(scope);
        let mut decision_counters = HashMap::with_capacity(DECISION_WIRE_STRINGS.len());
        for decision in DECISION_WIRE_STRINGS {
            let counter = meter
                .f64_counter(format!("acs_intervention_{decision}_total"))
                .build();
            decision_counters.insert((*decision).to_string(), counter);
        }
        let duration_histogram = meter.f64_histogram("acs_intervention_duration_ms").build();
        Self {
            meter_name: meter_name.to_string(),
            decision_counters,
            duration_histogram,
        }
    }

    pub fn meter_name(&self) -> &str {
        &self.meter_name
    }

    pub fn decision_counter_count(&self) -> usize {
        self.decision_counters.len()
    }
}

impl Default for OtelTelemetrySink {
    fn default() -> Self {
        Self::new(DEFAULT_OTEL_METER_NAME)
    }
}

impl TelemetrySink for OtelTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        // Count exactly one increment and one duration sample per evaluation.
        // The core emits two decision-bearing events on a Transform verdict
        // (Decision + intervention_point.transformed) and EvaluationTiming also
        // carries a decision under perf telemetry, so recording metrics only for
        // the base Decision event keeps acs_intervention_*_total at one per
        // evaluation, matching the host SDK sinks and the per-decision contract.
        if !records_metrics(&event) {
            return;
        }
        let attributes = metric_attributes(&event);
        let key_values = to_key_values(&attributes);
        if let Some(decision) = event.decision {
            if let Some(counter) = self.decision_counters.get(decision.as_str()) {
                counter.add(1.0, &key_values);
            }
        }
        if let Some(duration_ms) = event.duration_ms {
            self.duration_histogram.record(duration_ms, &key_values);
        }
    }
}

/// Whether an event should contribute to the per-decision counters and the
/// duration histogram. Only the base `Decision` event does, so each evaluation
/// records exactly one increment and one duration sample even when the core
/// also emits an `intervention_point.transformed` or `evaluation_timing` event.
fn records_metrics(event: &TelemetryEvent) -> bool {
    event.event_type == TelemetryEventType::Decision
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributePair {
    pub key: &'static str,
    pub value: String,
}

pub fn metric_attributes(event: &TelemetryEvent) -> Vec<AttributePair> {
    let mut attributes = Vec::new();
    attributes.push(AttributePair {
        key: "event_type",
        value: event.event_type.as_str().to_string(),
    });
    attributes.push(AttributePair {
        key: "intervention_point",
        value: event.intervention_point.as_str().to_string(),
    });
    if let Some(mode) = event.enforcement_mode {
        attributes.push(AttributePair {
            key: "enforcement_mode",
            value: mode.as_str().to_string(),
        });
    }
    if let Some(decision) = event.decision {
        attributes.push(AttributePair {
            key: "decision",
            value: decision.as_str().to_string(),
        });
    }
    if let Some(reason_code) = &event.reason_code {
        attributes.push(AttributePair {
            key: "reason_code",
            value: reason_code.clone(),
        });
    }
    if let Some(error_class) = &event.error_class {
        attributes.push(AttributePair {
            key: "error_class",
            value: error_class.clone(),
        });
    }
    if let Some(policy_id) = &event.policy_id {
        attributes.push(AttributePair {
            key: "policy_id",
            value: policy_id.clone(),
        });
    }
    if !event.annotators.is_empty() {
        attributes.push(AttributePair {
            key: "annotators",
            value: event.annotators.join(","),
        });
    }
    // AGT D2 / AGT-EVIDENCE-1.0 §3: forward the verbatim `artefact`
    // string and the sorted pointer keys (not the URL values) so
    // telemetry cardinality stays bounded. Auditors recover the full
    // URL map from the audit record per §4.
    if let Some(artefact) = &event.evidence_artefact {
        attributes.push(AttributePair {
            key: "evidence_artefact",
            value: artefact.clone(),
        });
    }
    if !event.evidence_verification_pointer_keys.is_empty() {
        attributes.push(AttributePair {
            key: "evidence_verification_pointer_keys",
            value: event.evidence_verification_pointer_keys.join(","),
        });
    }
    attributes
}

fn to_key_values(attributes: &[AttributePair]) -> Vec<KeyValue> {
    attributes
        .iter()
        .map(|attribute| KeyValue::new(attribute.key, attribute.value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_control_specification_core::{
        Decision, EnforcementMode, InterventionPoint, TelemetryEventType,
    };

    #[test]
    fn default_uses_canonical_meter_name() {
        let sink = OtelTelemetrySink::default();
        assert_eq!(sink.meter_name(), DEFAULT_OTEL_METER_NAME);
        // AGT D1: five decisions (allow, deny, warn, escalate, transform).
        assert_eq!(sink.decision_counter_count(), 5);
    }

    #[test]
    fn mapping_includes_structured_attributes() {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_enforcement_mode(EnforcementMode::Enforce)
            .with_decision(Decision::Deny)
            .with_reason_code("runtime_error:policy_invocation_failed")
            .with_error_class("runtime_error")
            .with_policy_id("content_policy")
            .with_annotator("prompt_classifier")
            .with_duration_ms(4.2);
        let attributes = metric_attributes(&event);
        assert!(attributes.contains(&AttributePair {
            key: "event_type",
            value: "decision".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "decision",
            value: "deny".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "reason_code",
            value: "runtime_error:policy_invocation_failed".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "error_class",
            value: "runtime_error".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "policy_id",
            value: "content_policy".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "annotators",
            value: "prompt_classifier".to_string(),
        }));
    }

    #[test]
    fn mapping_omits_action_identity() {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_decision(Decision::Allow)
            .with_action_identity("sha256:0123456789abcdef");
        let attributes = metric_attributes(&event);
        assert!(!attributes
            .iter()
            .any(|attribute| attribute.key == "action_identity"));
    }

    #[test]
    fn emit_is_panic_free_without_sdk_provider() {
        let sink = OtelTelemetrySink::new("acs_test");
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Output)
            .with_decision(Decision::Allow)
            .with_duration_ms(1.0);
        sink.emit(event);
    }

    #[test]
    fn mapping_omits_evidence_attributes_when_verdict_has_none() {
        // AGT D2 / AGT-EVIDENCE-1.0 §3: events without evidence MUST NOT
        // emit the evidence_artefact or evidence_verification_pointer_keys
        // attributes; their absence keeps the telemetry shape clean for
        // the common no-evidence path.
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_decision(Decision::Allow);
        let attributes = metric_attributes(&event);
        assert!(
            !attributes.iter().any(|attr| attr.key == "evidence_artefact"
                || attr.key == "evidence_verification_pointer_keys")
        );
    }

    #[test]
    fn mapping_includes_evidence_attributes_when_verdict_has_them() {
        // AGT D2 / AGT-EVIDENCE-1.0 §3: the runtime forwards the verbatim
        // artefact and the sorted pointer keys. The URL values MUST NOT
        // appear in telemetry; auditors recover them from the audit
        // record per §4.
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_decision(Decision::Allow)
            .with_evidence(
                Some("sha256:proofblob"),
                vec!["issuer_pubkey".to_string(), "policy_registry".to_string()],
            );
        let attributes = metric_attributes(&event);
        assert!(attributes.contains(&AttributePair {
            key: "evidence_artefact",
            value: "sha256:proofblob".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "evidence_verification_pointer_keys",
            value: "issuer_pubkey,policy_registry".to_string(),
        }));
        // Defense in depth: the URL strings MUST NOT be on any attribute
        // value, per AGT-EVIDENCE-1.0 §3.
        for attr in &attributes {
            assert!(!attr.value.contains("https://"));
        }
    }

    #[test]
    fn transformed_event_maps_attributes_but_does_not_record_metrics() {
        // AGT D1 + D2: the runtime emits a dedicated
        // `intervention_point.transformed` event in addition to the base
        // Decision event when the verdict is Transform. metric_attributes still
        // maps it (redaction-safe), but the OTel sink records metrics only for
        // the base Decision event so the per-decision counter counts a transform
        // once per evaluation, not twice.
        let sink = OtelTelemetrySink::new("acs_transform_test");
        let event = TelemetryEvent::new(
            TelemetryEventType::InterventionPointTransformed,
            InterventionPoint::Output,
        )
        .with_decision(Decision::Transform)
        .with_enforcement_mode(EnforcementMode::Enforce)
        .with_reason_code("redacted")
        .with_evidence(Some("sha256:proofblob"), vec!["issuer_pubkey".to_string()]);
        let attributes = metric_attributes(&event);
        assert!(attributes.contains(&AttributePair {
            key: "event_type",
            value: "intervention_point.transformed".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "decision",
            value: "transform".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "evidence_artefact",
            value: "sha256:proofblob".to_string(),
        }));
        assert!(attributes.contains(&AttributePair {
            key: "evidence_verification_pointer_keys",
            value: "issuer_pubkey".to_string(),
        }));
        // The transform counter exists, but this event MUST NOT record on it.
        assert!(sink.decision_counters.contains_key("transform"));
        assert!(!records_metrics(&event));
        sink.emit(event);
    }

    #[test]
    fn only_the_base_decision_event_records_metrics() {
        // One increment and one duration sample per evaluation: the base
        // Decision event records; the dual intervention_point.transformed event
        // and the perf evaluation_timing event do not, so a transform counts
        // once, matching the host SDK sinks.
        let decision = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_decision(Decision::Transform);
        assert!(records_metrics(&decision));
        for event_type in [
            TelemetryEventType::InterventionPointTransformed,
            TelemetryEventType::EvaluationTiming,
            TelemetryEventType::AnnotatorDispatch,
            TelemetryEventType::PolicyEvaluation,
            TelemetryEventType::AnnotatorFailed,
            TelemetryEventType::PolicyFailed,
        ] {
            let event = TelemetryEvent::new(event_type, InterventionPoint::Input)
                .with_decision(Decision::Transform);
            assert!(
                !records_metrics(&event),
                "{event_type:?} must not record metrics"
            );
        }
    }
}
