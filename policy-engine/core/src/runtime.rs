use crate::{
    annotation::{AnnotatorDispatcher, AnnotatorInvocation},
    constants::policy_input as pi_key,
    effects::validate_and_maybe_apply_effects,
    manifest::Manifest,
    paths::PathRoot,
    policy::{prepare_policy_invocation, PolicyConfig, PreparedPolicyInvocation},
    policy_input::{action_identity, build_policy_input},
    telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetryEventType, TelemetrySink},
    tool_projection::project_tool,
    verdict::{normalize_policy_output, Decision, Transform},
    EnforcementMode, InterventionPoint, JsonPath, JsonValue, Limits, PathEnv, PerfTelemetry,
    RuntimeError, Verdict,
};
use serde_json::Map;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    time::Instant,
};

pub trait PolicyDispatcher: Send + Sync {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError>;
}

#[derive(Clone)]
pub struct Runtime {
    manifest: Manifest,
    annotations: Arc<dyn AnnotatorDispatcher>,
    policy: Arc<dyn PolicyDispatcher>,
    telemetry: Arc<dyn TelemetrySink>,
    perf_telemetry: PerfTelemetry,
    limits: Limits,
}

impl Runtime {
    pub fn new(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
    ) -> Result<Self, RuntimeError> {
        let telemetry: Arc<dyn TelemetrySink> = Arc::new(NoopTelemetrySink);
        Self::with_telemetry_and_perf(
            manifest,
            annotations,
            policy,
            telemetry,
            PerfTelemetry::default(),
        )
    }

    pub fn with_perf_telemetry(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        perf_telemetry: PerfTelemetry,
    ) -> Result<Self, RuntimeError> {
        let telemetry: Arc<dyn TelemetrySink> = Arc::new(NoopTelemetrySink);
        Self::with_telemetry_and_perf(manifest, annotations, policy, telemetry, perf_telemetry)
    }

    pub fn with_limits(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        let telemetry: Arc<dyn TelemetrySink> = Arc::new(NoopTelemetrySink);
        Self::with_telemetry_perf_and_limits(
            manifest,
            annotations,
            policy,
            telemetry,
            PerfTelemetry::default(),
            limits,
        )
    }

    pub fn with_telemetry(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        telemetry: Arc<dyn TelemetrySink>,
    ) -> Result<Self, RuntimeError> {
        Self::with_telemetry_and_perf(
            manifest,
            annotations,
            policy,
            telemetry,
            PerfTelemetry::default(),
        )
    }

    pub fn with_telemetry_and_perf(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        telemetry: Arc<dyn TelemetrySink>,
        perf_telemetry: PerfTelemetry,
    ) -> Result<Self, RuntimeError> {
        Self::with_telemetry_perf_and_limits(
            manifest,
            annotations,
            policy,
            telemetry,
            perf_telemetry,
            Limits::default(),
        )
    }

    pub fn with_telemetry_perf_and_limits(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
        telemetry: Arc<dyn TelemetrySink>,
        perf_telemetry: PerfTelemetry,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        manifest.validate()?;
        if !manifest.extends.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "manifest 'extends' was not resolved; an enforcing runtime requires a fully \
                 composed manifest. Compose with Manifest::from_path, Manifest::from_yaml_chain, \
                 acs_builder_from_path, or acs_builder_from_yaml_chain; single-string loaders \
                 must be given an already-merged manifest"
                    .to_string(),
            ));
        }
        Ok(Self {
            manifest,
            annotations,
            policy,
            telemetry,
            perf_telemetry,
            limits,
        })
    }

    pub fn perf_telemetry(&self) -> PerfTelemetry {
        self.perf_telemetry
    }

    pub fn with_perf_telemetry_level(mut self, perf_telemetry: PerfTelemetry) -> Self {
        self.perf_telemetry = perf_telemetry;
        self
    }

    pub fn evaluate_intervention_point(
        &self,
        request: InterventionPointRequest,
    ) -> InterventionPointResult {
        let started_at = Instant::now();
        let intervention_point = request.intervention_point;
        let mode = request.mode;
        let policy_id = self.policy_id_for(intervention_point).map(str::to_string);
        let annotators = self.annotators_for(intervention_point);
        let result = match self.evaluate_intervention_point_inner(request) {
            Ok(result) => result,
            Err(failure) => InterventionPointResult {
                verdict: Verdict::runtime_error(&failure.error),
                transformed_policy_target: None,
                policy_input: failure.policy_input,
                action_identity: None,
            },
        };
        let duration_ms = started_at.elapsed().as_secs_f64() * 1000.0;
        self.emit_decision_event(
            intervention_point,
            mode,
            &result.verdict,
            policy_id.as_deref(),
            annotators,
            duration_ms,
        );
        if self.perf_telemetry.emit_stage_events() {
            self.emit_event(
                TelemetryEvent::new(TelemetryEventType::EvaluationTiming, intervention_point)
                    .with_decision(result.verdict.decision)
                    .with_optional_reason_code(
                        safe_telemetry_reason_code(result.verdict.reason.as_deref()).as_deref(),
                    )
                    .with_optional_policy_id(policy_id.as_deref())
                    .with_enforcement_mode(mode)
                    .with_duration_ms(duration_ms),
            );
        }
        result
    }

    fn evaluate_intervention_point_inner(
        &self,
        request: InterventionPointRequest,
    ) -> Result<InterventionPointResult, EvaluationFailure> {
        let point_config = self
            .manifest
            .intervention_points
            .get(&request.intervention_point)
            .ok_or_else(|| {
                RuntimeError::InterventionPointUnknown(
                    request.intervention_point.as_str().to_string(),
                )
            })?;

        self.limits.validate_snapshot(&request.snapshot)?;

        let policy_target_path = JsonPath::parse_with_snapshot_alias(&point_config.policy_target)
            .map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "invalid policy_target for intervention point {}: {err}",
                request.intervention_point
            ))
        })?;
        let policy_target = policy_target_path.resolve(&PathEnv::with_snap(&request.snapshot))?;
        let tool = project_tool(
            &self.manifest,
            request.intervention_point,
            point_config,
            &request.snapshot,
        )?;

        let preliminary_policy_input = build_policy_input(
            request.intervention_point,
            &point_config.policy_target,
            point_config.policy_target_kind.as_deref(),
            policy_target.clone(),
            request.snapshot.clone(),
            JsonValue::Object(Map::new()),
            tool.clone(),
        );
        self.limits
            .validate_policy_input(&preliminary_policy_input)?;

        let annotations = self
            .collect_annotations(
                request.intervention_point,
                point_config,
                &preliminary_policy_input,
            )
            .map_err(|error| EvaluationFailure {
                error,
                policy_input: Some(preliminary_policy_input.clone()),
            })?;

        let final_policy_input = build_policy_input(
            request.intervention_point,
            &point_config.policy_target,
            point_config.policy_target_kind.as_deref(),
            policy_target.clone(),
            request.snapshot,
            annotations,
            tool,
        );
        self.limits.validate_policy_input(&final_policy_input)?;

        let policy_config = self
            .manifest
            .policies
            .get(&point_config.policy.id)
            .ok_or_else(|| {
                RuntimeError::ManifestInvalid(format!(
                    "intervention point {} references unknown policy '{}'",
                    request.intervention_point, point_config.policy.id
                ))
            })?;

        let invocation =
            prepare_policy_invocation(policy_config, &point_config.policy, &final_policy_input)
                .map_err(|error| {
                    self.emit_policy_failed(
                        request.intervention_point,
                        &point_config.policy.id,
                        policy_config,
                        &error,
                    );
                    EvaluationFailure {
                        error,
                        policy_input: Some(final_policy_input.clone()),
                    }
                })?;

        let policy_start = Instant::now();
        let policy_output = self.policy.evaluate(&invocation).map_err(|err| {
            let error = RuntimeError::PolicyInvocationFailed(err.to_string());
            self.emit_policy_external_event(
                request.intervention_point,
                &point_config.policy.id,
                policy_config,
                Some(error.reason()),
                policy_start.elapsed().as_secs_f64() * 1000.0,
            );
            self.emit_policy_failed(
                request.intervention_point,
                &point_config.policy.id,
                policy_config,
                &error,
            );
            EvaluationFailure {
                error,
                policy_input: Some(final_policy_input.clone()),
            }
        })?;
        self.emit_policy_external_event(
            request.intervention_point,
            &point_config.policy.id,
            policy_config,
            None,
            policy_start.elapsed().as_secs_f64() * 1000.0,
        );

        let verdict = normalize_policy_output(policy_output).map_err(|error| {
            self.emit_policy_failed(
                request.intervention_point,
                &point_config.policy.id,
                policy_config,
                &error,
            );
            EvaluationFailure {
                error,
                policy_input: Some(final_policy_input.clone()),
            }
        })?;

        let transformed_policy_target = match verdict.decision {
            Decision::Transform => {
                let transform = verdict
                    .transform
                    .as_ref()
                    .ok_or_else(|| EvaluationFailure {
                        error: RuntimeError::PolicyOutputInvalid(
                            "transform decision missing transform body after normalization"
                                .to_string(),
                        ),
                        policy_input: Some(final_policy_input.clone()),
                    })?;
                let applied = apply_transform(&policy_target, transform).map_err(|error| {
                    EvaluationFailure {
                        error,
                        policy_input: Some(final_policy_input.clone()),
                    }
                })?;
                if request.mode == EnforcementMode::Enforce {
                    Some(applied)
                } else {
                    None
                }
            }
            _ => {
                let should_apply =
                    request.mode == EnforcementMode::Enforce && verdict.decision.applies_effects();
                let transformed = validate_and_maybe_apply_effects(
                    &policy_target,
                    &verdict.effects,
                    should_apply,
                )
                .map_err(|error| EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                })?;
                if should_apply && !verdict.effects.is_empty() {
                    self.emit_intervention_point_effect_applied(
                        request.intervention_point,
                        request.mode,
                        &point_config.policy.id,
                        verdict.effects.len(),
                    );
                }
                transformed
            }
        };

        let action_identity =
            action_identity(&final_policy_input).map_err(|error| EvaluationFailure {
                error: RuntimeError::PolicyOutputInvalid(format!(
                    "failed to derive action identity: {error}"
                )),
                policy_input: Some(final_policy_input.clone()),
            })?;

        Ok(InterventionPointResult {
            verdict,
            transformed_policy_target,
            policy_input: Some(final_policy_input),
            action_identity: Some(action_identity),
        })
    }

    fn collect_annotations(
        &self,
        intervention_point: InterventionPoint,
        point_config: &crate::manifest::InterventionPointConfig,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        if point_config.annotations.len() > self.limits.max_annotators_per_point {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "intervention point {intervention_point} invokes {} annotators, limit {}",
                point_config.annotations.len(),
                self.limits.max_annotators_per_point
            )));
        }

        let mut annotations_map = Map::new();
        for annotator_name in point_config.annotations.keys() {
            let annotation_config = point_config
                .annotations
                .get(annotator_name)
                .ok_or_else(|| RuntimeError::ManifestInvalid(annotator_name.clone()))
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            let annotator_config = self
                .manifest
                .annotators
                .get(annotator_name)
                .ok_or_else(|| RuntimeError::ManifestInvalid(annotator_name.clone()))
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            let annotator =
                AnnotatorInvocation::from_annotation(annotator_config, annotation_config);

            if let Some(input_from) = annotator.input_from() {
                let path = JsonPath::parse_with_snapshot_alias(input_from)
                    .map_err(|err| {
                        RuntimeError::ManifestInvalid(format!(
                            "invalid from path for annotator '{annotator_name}': {err}"
                        ))
                    })
                    .inspect_err(|error| {
                        self.emit_annotator_failed(intervention_point, annotator_name, error);
                    })?;
                let snapshot = preliminary_policy_input
                    .get(pi_key::SNAPSHOT)
                    .ok_or_else(|| {
                        RuntimeError::ManifestInvalid(
                            "preliminary policy input missing snapshot".to_string(),
                        )
                    })?;
                path.resolve(&PathEnv::with_pi_and_snap(
                    preliminary_policy_input,
                    snapshot,
                ))
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            }

            let dispatch_start = Instant::now();
            let output = self
                .annotations
                .dispatch(annotator_name, &annotator, preliminary_policy_input)
                .map_err(|err| normalize_annotator_error(annotator_name, err))
                .inspect_err(|error| {
                    self.emit_annotator_external_event(
                        intervention_point,
                        annotator_name,
                        Some(error.reason()),
                        dispatch_start.elapsed().as_secs_f64() * 1000.0,
                    );
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            self.limits
                .validate_annotator_output(annotator_name, &output)
                .inspect_err(|error| {
                    self.emit_annotator_failed(intervention_point, annotator_name, error);
                })?;
            self.emit_annotator_external_event(
                intervention_point,
                annotator_name,
                None,
                dispatch_start.elapsed().as_secs_f64() * 1000.0,
            );
            annotations_map.insert(annotator_name.clone(), output);
        }
        Ok(JsonValue::Object(annotations_map))
    }

    fn emit_decision_event(
        &self,
        intervention_point: InterventionPoint,
        mode: EnforcementMode,
        verdict: &Verdict,
        policy_id: Option<&str>,
        annotators: Vec<String>,
        duration_ms: f64,
    ) {
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::Decision, intervention_point)
                .with_decision(verdict.decision)
                .with_optional_reason_code(
                    safe_telemetry_reason_code(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_policy_id(policy_id)
                .with_annotators(annotators)
                .with_enforcement_mode(mode)
                .with_duration_ms(duration_ms),
        );
    }

    fn emit_intervention_point_effect_applied(
        &self,
        intervention_point: InterventionPoint,
        mode: EnforcementMode,
        policy_id: &str,
        effect_count: usize,
    ) {
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::EffectApplied, intervention_point)
                .with_policy_id(policy_id)
                .with_enforcement_mode(mode)
                .with_metadata("effect_count", effect_count.to_string()),
        );
    }

    fn emit_annotator_failed(
        &self,
        intervention_point: InterventionPoint,
        annotator_name: &str,
        error: &RuntimeError,
    ) {
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::AnnotatorFailed, intervention_point)
                .with_annotator(annotator_name)
                .with_reason_code(error.reason()),
        );
    }

    fn emit_policy_failed(
        &self,
        intervention_point: InterventionPoint,
        policy_id: &str,
        policy_config: &PolicyConfig,
        error: &RuntimeError,
    ) {
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::PolicyFailed, intervention_point)
                .with_policy_id(policy_id)
                .with_reason_code(error.reason())
                .with_metadata("policy_type", policy_config.engine_type()),
        );
    }

    fn emit_annotator_external_event(
        &self,
        intervention_point: InterventionPoint,
        annotator_name: &str,
        reason: Option<&str>,
        duration_ms: f64,
    ) {
        if !self.perf_telemetry.emit_external_events() {
            return;
        }
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::AnnotatorDispatch, intervention_point)
                .with_annotator(annotator_name)
                .with_optional_reason_code(safe_telemetry_reason_code(reason).as_deref())
                .with_duration_ms(duration_ms),
        );
    }

    fn emit_policy_external_event(
        &self,
        intervention_point: InterventionPoint,
        policy_id: &str,
        policy_config: &PolicyConfig,
        reason: Option<&str>,
        duration_ms: f64,
    ) {
        if !self.perf_telemetry.emit_external_events() {
            return;
        }
        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::PolicyEvaluation, intervention_point)
                .with_policy_id(policy_id)
                .with_optional_reason_code(safe_telemetry_reason_code(reason).as_deref())
                .with_duration_ms(duration_ms)
                .with_metadata("policy_type", policy_config.engine_type()),
        );
    }

    fn emit_event(&self, event: TelemetryEvent) {
        let _ = catch_unwind(AssertUnwindSafe(|| self.telemetry.emit(event)));
    }

    fn policy_id_for(&self, intervention_point: InterventionPoint) -> Option<&str> {
        self.manifest
            .intervention_points
            .get(&intervention_point)
            .map(|config| config.policy.id.as_str())
    }

    fn annotators_for(&self, intervention_point: InterventionPoint) -> Vec<String> {
        self.manifest
            .intervention_points
            .get(&intervention_point)
            .map(|config| config.annotations.keys().cloned().collect())
            .unwrap_or_default()
    }
}

fn safe_telemetry_reason_code(reason: Option<&str>) -> Option<String> {
    let reason = reason?;
    if is_identifier_reason_code(reason) {
        Some(reason.to_string())
    } else {
        Some("policy_reason".to_string())
    }
}

fn is_identifier_reason_code(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 96
        && reason.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

/// Validate and apply an AGT D1.1 `transform` verdict body against the current
/// policy target. The returned value is the rewritten policy target. The caller
/// decides whether to surface the rewrite per the enforcement mode.
///
/// Per `SPECIFICATION-AGT-DELTA.md` D1.1 a transform whose path is outside
/// `$policy_target` fails closed with `runtime_error:transform_target_forbidden`;
/// a transform whose path does not resolve or whose value cannot be set fails
/// closed with `runtime_error:transform_invalid`.
fn apply_transform(
    policy_target: &JsonValue,
    transform: &Transform,
) -> Result<JsonValue, RuntimeError> {
    let path = JsonPath::parse(&transform.path)
        .map_err(|err| RuntimeError::TransformInvalid(format!("invalid transform path: {err}")))?;
    if path.root() != PathRoot::PolicyTarget {
        return Err(RuntimeError::TransformTargetForbidden(
            transform.path.clone(),
        ));
    }

    let mut working = policy_target.clone();
    match path.resolve_policy_target_mut(&mut working) {
        Ok(slot) => {
            *slot = transform.value.clone();
            Ok(working)
        }
        Err(RuntimeError::EffectTargetForbidden(detail)) => {
            Err(RuntimeError::TransformTargetForbidden(detail))
        }
        Err(error) => Err(RuntimeError::TransformInvalid(format!(
            "transform could not be applied: {error}"
        ))),
    }
}

#[derive(Debug, Clone)]
pub struct InterventionPointRequest {
    pub intervention_point: InterventionPoint,
    pub snapshot: JsonValue,
    pub mode: EnforcementMode,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InterventionPointResult {
    pub verdict: Verdict,
    pub transformed_policy_target: Option<JsonValue>,
    pub policy_input: Option<JsonValue>,
    pub action_identity: Option<String>,
}

fn normalize_annotator_error(annotator_name: &str, error: RuntimeError) -> RuntimeError {
    match error {
        RuntimeError::AnnotationTimeout(detail) => {
            RuntimeError::AnnotationTimeout(annotator_error_detail(annotator_name, detail))
        }
        RuntimeError::AnnotationFailed(detail) => {
            RuntimeError::AnnotationFailed(annotator_error_detail(annotator_name, detail))
        }
        other => RuntimeError::AnnotationFailed(format!("{annotator_name}: {other}")),
    }
}

fn annotator_error_detail(annotator_name: &str, detail: String) -> String {
    if detail.is_empty() || detail == annotator_name {
        annotator_name.to_string()
    } else if detail.starts_with(&format!("{annotator_name}:")) {
        detail
    } else {
        format!("{annotator_name}: {detail}")
    }
}

#[derive(Debug)]
struct EvaluationFailure {
    error: RuntimeError,
    policy_input: Option<JsonValue>,
}

impl From<RuntimeError> for EvaluationFailure {
    fn from(error: RuntimeError) -> Self {
        Self {
            error,
            policy_input: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decision, Manifest, RuntimeError};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct StaticAnnotator;
    impl AnnotatorDispatcher for StaticAnnotator {
        fn dispatch(
            &self,
            _annotator_name: &str,
            _annotator: &AnnotatorInvocation,
            _preliminary_policy_input: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            Ok(JsonValue::Null)
        }
    }

    struct StaticPolicy {
        output: JsonValue,
        seen: Mutex<Vec<JsonValue>>,
    }

    impl StaticPolicy {
        fn new(output: JsonValue) -> Self {
            Self {
                output,
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl PolicyDispatcher for StaticPolicy {
        fn evaluate(
            &self,
            invocation: &PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            self.seen
                .lock()
                .unwrap()
                .push(invocation.policy_input().unwrap().clone());
            Ok(self.output.clone())
        }
    }

    fn output_manifest() -> Manifest {
        Manifest::from_yaml_str(
            r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output"#,
        )
        .unwrap()
    }

    fn runtime(policy_output: JsonValue) -> Runtime {
        Runtime::new(
            output_manifest(),
            Arc::new(StaticAnnotator),
            Arc::new(StaticPolicy::new(policy_output)),
        )
        .unwrap()
    }

    fn evaluate(
        runtime: &Runtime,
        mode: EnforcementMode,
        snapshot: JsonValue,
    ) -> InterventionPointResult {
        runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Output,
            snapshot,
            mode,
        })
    }

    // ── AGT D1 transform application in evaluate_intervention_point ───────

    #[test]
    fn transform_decision_applied_in_enforce_mode() {
        let runtime = runtime(json!({
            "decision": "transform",
            "reason": "pii_redacted",
            "transform": {"path": "$policy_target.body", "value": "[REDACTED]"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "secret data"}}),
        );

        assert_eq!(result.verdict.decision, Decision::Transform);
        assert_eq!(
            result.transformed_policy_target,
            Some(json!({"body": "[REDACTED]"})),
            "enforce mode must surface the transformed policy target"
        );
    }

    #[test]
    fn transform_decision_validated_only_in_evaluate_only_mode() {
        let runtime = runtime(json!({
            "decision": "transform",
            "reason": "pii_redacted",
            "transform": {"path": "$policy_target.body", "value": "[REDACTED]"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::EvaluateOnly,
            json!({"output": {"body": "secret data"}}),
        );

        assert_eq!(result.verdict.decision, Decision::Transform);
        assert!(
            result.transformed_policy_target.is_none(),
            "evaluate_only mode must validate without applying transform"
        );
    }

    #[test]
    fn transform_with_invalid_path_fails_closed_with_transform_invalid() {
        let runtime = runtime(json!({
            "decision": "transform",
            "transform": {"path": "$policy_target.missing_field", "value": "x"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "data"}}),
        );

        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:transform_invalid")
        );
        assert!(result.transformed_policy_target.is_none());
    }

    #[test]
    fn transform_with_path_outside_policy_target_fails_closed_with_target_forbidden() {
        // The exclusivity rule is enforced in verdict::normalize_policy_output;
        // we still verify the runtime surface returns the reserved reason on
        // the produced verdict.
        let runtime = runtime(json!({
            "decision": "transform",
            "transform": {"path": "$snap.output.body", "value": "x"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "data"}}),
        );

        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:transform_target_forbidden")
        );
    }

    #[test]
    fn transform_with_type_mismatch_fails_closed_with_transform_invalid() {
        // Target body is a string but transform tries to write to a nested key.
        // resolve_policy_target_mut returns PathTypeMismatch which the runtime
        // remaps to TransformInvalid.
        let runtime = runtime(json!({
            "decision": "transform",
            "transform": {"path": "$policy_target.body.nested", "value": "x"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "string value"}}),
        );

        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:transform_invalid")
        );
    }
}
