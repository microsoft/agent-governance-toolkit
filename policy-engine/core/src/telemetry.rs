use crate::{Decision, EnforcementMode, InterventionPoint};
use std::collections::BTreeMap;

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
}

pub trait TelemetrySink: Send + Sync {
    fn emit(&self, event: TelemetryEvent);

    fn shutdown(&self) {}
}

#[derive(Debug, Default)]
pub struct NoopTelemetrySink;

impl TelemetrySink for NoopTelemetrySink {
    fn emit(&self, _event: TelemetryEvent) {}
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
}
