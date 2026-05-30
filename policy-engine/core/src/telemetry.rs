use crate::{Decision, EnforcementMode, InterventionPoint};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TelemetryEventType {
    Decision,
    AnnotatorDispatch,
    PolicyEvaluation,
    EvaluationTiming,
    EffectApplied,
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
            Self::EffectApplied => "effect_applied",
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
    pub policy_id: Option<String>,
    pub annotators: Vec<String>,
    pub enforcement_mode: Option<EnforcementMode>,
    pub duration_ms: Option<f64>,
    pub metadata: BTreeMap<String, String>,
}

impl TelemetryEvent {
    pub fn new(event_type: TelemetryEventType, intervention_point: InterventionPoint) -> Self {
        Self {
            event_type,
            intervention_point,
            decision: None,
            reason_code: None,
            policy_id: None,
            annotators: Vec::new(),
            enforcement_mode: None,
            duration_ms: None,
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

    pub fn with_metadata(mut self, key: &str, value: impl Into<String>) -> Self {
        self.metadata.insert(key.to_string(), value.into());
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
