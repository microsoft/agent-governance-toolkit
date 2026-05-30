use agent_control_specification_core::{TelemetryEvent, TelemetrySink};
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::{InstrumentationScope, KeyValue};
use std::collections::HashMap;

pub const DEFAULT_OTEL_METER_NAME: &str = "agent_control_specification";

const DECISION_WIRE_STRINGS: &[&str] = &["allow", "deny", "warn", "escalate"];

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
        assert_eq!(sink.decision_counter_count(), 4);
    }

    #[test]
    fn mapping_includes_structured_attributes() {
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_enforcement_mode(EnforcementMode::Enforce)
            .with_decision(Decision::Deny)
            .with_reason_code("policy_denied")
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
            value: "policy_denied".to_string(),
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
    fn emit_is_panic_free_without_sdk_provider() {
        let sink = OtelTelemetrySink::new("acs_test");
        let event = TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Output)
            .with_decision(Decision::Allow)
            .with_duration_ms(1.0);
        sink.emit(event);
    }
}
