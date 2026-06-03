use crate::{
    annotation::{AnnotatorDispatcher, AnnotatorInvocation},
    constants::policy_input as pi_key,
    manifest::Manifest,
    paths::PathRoot,
    policy::{prepare_policy_invocation, PolicyConfig, PreparedPolicyInvocation},
    policy_input::{action_identity, build_policy_input},
    telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetryEventType, TelemetrySink},
    tool_projection::project_tool,
    verdict::{normalize_policy_output, Decision, Transform},
    EnforcementMode, InterventionPoint, JsonPath, JsonValue, Limits, PathEnv, PathSegment,
    PerfTelemetry, RuntimeError, Verdict,
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
                input_identity: None,
                enforced_identity: None,
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
            result.action_identity.as_deref(),
        );
        if self.perf_telemetry.emit_stage_events() {
            self.emit_event(
                TelemetryEvent::new(TelemetryEventType::EvaluationTiming, intervention_point)
                    .with_decision(result.verdict.decision)
                    .with_optional_reason_code(
                        safe_telemetry_reason_code(result.verdict.reason.as_deref()).as_deref(),
                    )
                    .with_optional_policy_id(policy_id.as_deref())
                    .with_optional_error_class(
                        telemetry_error_class(result.verdict.reason.as_deref()).as_deref(),
                    )
                    .with_enforcement_mode(mode)
                    .with_duration_ms(duration_ms)
                    .with_optional_action_identity(result.action_identity.as_deref()),
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

        let policy_target_field = point_config.policy_target.as_str();
        let policy = &point_config.policy;

        let policy_target_path =
            JsonPath::parse_with_snapshot_alias(policy_target_field).map_err(|err| {
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
            policy_target_field,
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
            policy_target_field,
            point_config.policy_target_kind.as_deref(),
            policy_target.clone(),
            request.snapshot.clone(),
            annotations,
            tool,
        );
        self.limits.validate_policy_input(&final_policy_input)?;

        let policy_config = self.manifest.policies.get(&policy.id).ok_or_else(|| {
            RuntimeError::ManifestInvalid(format!(
                "intervention point {} references unknown policy '{}'",
                request.intervention_point, policy.id
            ))
        })?;

        let invocation = prepare_policy_invocation(policy_config, policy, &final_policy_input)
            .map_err(|error| {
                self.emit_policy_failed(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    &error,
                );
                EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                }
            })?;

        let policy_start = Instant::now();
        let policy_output = catch_unwind(AssertUnwindSafe(|| self.policy.evaluate(&invocation)))
            .map_err(|payload| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "policy dispatcher panicked: {}",
                    panic_detail(payload.as_ref())
                ))
            })
            .and_then(|result| {
                result.map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))
            })
            .map_err(|error| {
                self.emit_policy_external_event(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    Some(error.reason()),
                    policy_start.elapsed().as_secs_f64() * 1000.0,
                );
                self.emit_policy_failed(
                    request.intervention_point,
                    &policy.id,
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
            &policy.id,
            policy_config,
            None,
            policy_start.elapsed().as_secs_f64() * 1000.0,
        );

        self.limits
            .validate_policy_output(&policy_output)
            .map_err(|error| {
                self.emit_policy_failed(
                    request.intervention_point,
                    &policy.id,
                    policy_config,
                    &error,
                );
                EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                }
            })?;

        let verdict = normalize_policy_output(policy_output).map_err(|error| {
            self.emit_policy_failed(
                request.intervention_point,
                &policy.id,
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
            _ => None,
        };

        // AGT D1.1 hardening ported from upstream ACS. When a transform
        // rewrites the policy target, rebuild the snapshot with the rewritten
        // value and re-validate it against resource limits before the rewrite
        // is surfaced to the host.
        if let Some(transformed) = &transformed_policy_target {
            let transformed_snapshot = snapshot_with_transformed_policy_target(
                &request.snapshot,
                &policy_target_path,
                transformed.clone(),
            )
            .map_err(|error| EvaluationFailure {
                error,
                policy_input: Some(final_policy_input.clone()),
            })?;
            self.limits
                .validate_snapshot(&transformed_snapshot)
                .map_err(|error| EvaluationFailure {
                    error,
                    policy_input: Some(final_policy_input.clone()),
                })?;
        }

        let input_identity =
            action_identity(&final_policy_input).map_err(|error| EvaluationFailure {
                error: RuntimeError::PolicyOutputInvalid(format!(
                    "failed to derive input_identity: {error}"
                )),
                policy_input: Some(final_policy_input.clone()),
            })?;

        // AGT D1.4: enforced_identity is computed over the policy input
        // with `policy_target.value` replaced by the transformed value when
        // a Transform decision rewrites it. Non-transform decisions and
        // evaluate-only mode (where `transformed_policy_target` is None by
        // design) keep enforced_identity equal to input_identity, so audit
        // consumers always see a stable two-field schema.
        let enforced_identity = match &transformed_policy_target {
            Some(transformed) => {
                let mut enforced_policy_input = final_policy_input.clone();
                if let Some(value_slot) = enforced_policy_input
                    .get_mut(pi_key::POLICY_TARGET)
                    .and_then(JsonValue::as_object_mut)
                    .and_then(|object| object.get_mut(pi_key::VALUE))
                {
                    *value_slot = transformed.clone();
                }
                action_identity(&enforced_policy_input).map_err(|error| EvaluationFailure {
                    error: RuntimeError::PolicyOutputInvalid(format!(
                        "failed to derive enforced_identity: {error}"
                    )),
                    policy_input: Some(final_policy_input.clone()),
                })?
            }
            None => input_identity.clone(),
        };

        Ok(InterventionPointResult {
            verdict,
            transformed_policy_target,
            policy_input: Some(final_policy_input),
            action_identity: Some(enforced_identity.clone()),
            input_identity: Some(input_identity),
            enforced_identity: Some(enforced_identity),
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
            let output = catch_unwind(AssertUnwindSafe(|| {
                self.annotations
                    .dispatch(annotator_name, &annotator, preliminary_policy_input)
            }))
            .map_err(|payload| {
                RuntimeError::AnnotationFailed(format!(
                    "annotator dispatcher panicked: {}",
                    panic_detail(payload.as_ref())
                ))
            })
            .and_then(|result| result)
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

    // AGT integration passes decision evidence/identity fields explicitly; keep
    // the signature stable to minimize divergence and risk in the vendored
    // runtime hot path rather than refactoring to a params struct.
    #[allow(clippy::too_many_arguments)]
    fn emit_decision_event(
        &self,
        intervention_point: InterventionPoint,
        mode: EnforcementMode,
        verdict: &Verdict,
        policy_id: Option<&str>,
        annotators: Vec<String>,
        duration_ms: f64,
        action_identity: Option<&str>,
    ) {
        // AGT D2 / AGT-EVIDENCE-1.0 §3: propagate the verbatim artefact
        // string and the sorted pointer keys (not URL values) when the
        // verdict carries `evidence`.
        let (evidence_artefact, evidence_keys): (Option<String>, Vec<String>) =
            match verdict.evidence.as_ref() {
                Some(evidence) => (evidence.artefact.clone(), evidence.pointer_keys()),
                None => (None, Vec::new()),
            };

        self.emit_event(
            TelemetryEvent::new(TelemetryEventType::Decision, intervention_point)
                .with_decision(verdict.decision)
                .with_optional_reason_code(
                    safe_telemetry_reason_code(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_error_class(
                    telemetry_error_class(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_policy_id(policy_id)
                .with_annotators(annotators.clone())
                .with_enforcement_mode(mode)
                .with_duration_ms(duration_ms)
                .with_optional_action_identity(action_identity)
                .with_evidence(evidence_artefact.as_deref(), evidence_keys.clone()),
        );

        // AGT D2: when the decision is `Transform`, emit the dedicated
        // `intervention_point.transformed` event in addition to the
        // base Decision event so that single-event consumers and
        // multi-event consumers both see the transformation.
        if verdict.decision == Decision::Transform {
            self.emit_event(
                TelemetryEvent::new(
                    TelemetryEventType::InterventionPointTransformed,
                    intervention_point,
                )
                .with_decision(verdict.decision)
                .with_optional_reason_code(
                    safe_telemetry_reason_code(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_error_class(
                    telemetry_error_class(verdict.reason.as_deref()).as_deref(),
                )
                .with_optional_policy_id(policy_id)
                .with_annotators(annotators)
                .with_enforcement_mode(mode)
                .with_duration_ms(duration_ms)
                .with_optional_action_identity(action_identity)
                .with_evidence(evidence_artefact.as_deref(), evidence_keys),
            );
        }
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
                .with_reason_code(error.reason())
                .with_optional_error_class(telemetry_error_class(Some(error.reason())).as_deref()),
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
                .with_optional_error_class(telemetry_error_class(Some(error.reason())).as_deref())
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
                .with_optional_error_class(telemetry_error_class(reason).as_deref())
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
                .with_optional_error_class(telemetry_error_class(reason).as_deref())
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

fn telemetry_error_class(reason: Option<&str>) -> Option<String> {
    reason
        .filter(|reason| reason.starts_with("runtime_error:"))
        .map(|_| "runtime_error".to_string())
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
/// Per `SPECIFICATION.md` §14 a transform whose path is outside
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

fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[derive(Debug, Clone)]
pub struct InterventionPointRequest {
    pub intervention_point: InterventionPoint,
    pub snapshot: JsonValue,
    pub mode: EnforcementMode,
}

/// Result of evaluating a single intervention point.
///
/// Per AGT D1.4 the engine produces two SHA-256 identities for every
/// successful evaluation:
///
/// - `input_identity` pins what the policy actually saw.
/// - `enforced_identity` pins what the host will carry out. It differs
///   from `input_identity` only when the verdict is `Decision::Transform`
///   in `EnforcementMode::Enforce`; in every other case the two are equal.
///
/// `action_identity` is retained as a backwards-compatible alias that
/// always equals `enforced_identity`, satisfying the AGT-EVIDENCE-1.0
/// note that single-identity telemetry consumers MAY default to
/// `enforced_identity`. New callers should reach for the bisected fields
/// directly.
#[derive(Debug, Clone, PartialEq)]
pub struct InterventionPointResult {
    pub verdict: Verdict,
    pub transformed_policy_target: Option<JsonValue>,
    pub policy_input: Option<JsonValue>,
    /// Backwards-compatible alias for `enforced_identity` per AGT D1.4.
    pub action_identity: Option<String>,
    /// AGT D1.4 SHA-256 of the canonical policy input as evaluated.
    pub input_identity: Option<String>,
    /// AGT D1.4 SHA-256 of the canonical policy input with the
    /// transformed policy target applied. Equal to `input_identity` for
    /// non-transform decisions and evaluate-only transforms.
    pub enforced_identity: Option<String>,
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

fn snapshot_with_transformed_policy_target(
    snapshot: &JsonValue,
    policy_target_path: &JsonPath,
    transformed: JsonValue,
) -> Result<JsonValue, RuntimeError> {
    if policy_target_path.root() != PathRoot::Snap {
        return Err(RuntimeError::ManifestInvalid(
            "policy_target must resolve from snapshot".to_string(),
        ));
    }

    let mut snapshot = snapshot.clone();
    let mut current = &mut snapshot;
    for segment in policy_target_path.segments() {
        match segment {
            PathSegment::Field(field) => match current {
                JsonValue::Object(map) => {
                    current = map.get_mut(field).ok_or_else(|| {
                        RuntimeError::PathMissing(policy_target_path.original().to_string())
                    })?;
                }
                _ => {
                    return Err(RuntimeError::PathTypeMismatch(
                        policy_target_path.original().to_string(),
                    ))
                }
            },
            PathSegment::Index(index) => match current {
                JsonValue::Array(values) => {
                    current = values.get_mut(*index).ok_or_else(|| {
                        RuntimeError::PathMissing(policy_target_path.original().to_string())
                    })?;
                }
                _ => {
                    return Err(RuntimeError::PathTypeMismatch(
                        policy_target_path.original().to_string(),
                    ))
                }
            },
        }
    }
    *current = transformed;
    Ok(snapshot)
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

    // ── AGT D2 evidence propagation + Transformed event ───────────────

    #[derive(Default)]
    struct RecordingTelemetry {
        events: Mutex<Vec<TelemetryEvent>>,
    }

    impl TelemetrySink for RecordingTelemetry {
        fn emit(&self, event: TelemetryEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn runtime_with_recording_sink(policy_output: JsonValue) -> (Runtime, Arc<RecordingTelemetry>) {
        let telemetry = Arc::new(RecordingTelemetry::default());
        let runtime = Runtime::with_telemetry(
            output_manifest(),
            Arc::new(StaticAnnotator),
            Arc::new(StaticPolicy::new(policy_output)),
            telemetry.clone(),
        )
        .unwrap();
        (runtime, telemetry)
    }

    #[test]
    fn decision_event_carries_evidence_artefact_and_sorted_pointer_keys() {
        let (runtime, telemetry) = runtime_with_recording_sink(json!({
            "decision": "allow",
            "evidence": {
                "artefact": "sha256:abcd",
                "verification_pointers": {
                    "policy_registry": "https://x/policies",
                    "issuer_pubkey": "https://x/keys"
                }
            }
        }));
        let _ = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "data"}}),
        );

        let events = telemetry.events.lock().unwrap();
        let decision = events
            .iter()
            .find(|event| event.event_type == TelemetryEventType::Decision)
            .expect("decision event emitted");
        assert_eq!(decision.evidence_artefact.as_deref(), Some("sha256:abcd"));
        // Sorted keys per AGT-EVIDENCE-1.0 §3 (BTreeMap iteration order).
        assert_eq!(
            decision.evidence_verification_pointer_keys,
            vec!["issuer_pubkey", "policy_registry"]
        );
    }

    #[test]
    fn decision_event_evidence_metadata_is_clean_when_verdict_has_no_evidence() {
        let (runtime, telemetry) = runtime_with_recording_sink(json!({"decision": "allow"}));
        let _ = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "data"}}),
        );

        let events = telemetry.events.lock().unwrap();
        let decision = events
            .iter()
            .find(|event| event.event_type == TelemetryEventType::Decision)
            .expect("decision event emitted");
        assert!(decision.evidence_artefact.is_none());
        assert!(decision.evidence_verification_pointer_keys.is_empty());
    }

    #[test]
    fn transform_decision_emits_dedicated_intervention_point_transformed_event() {
        let (runtime, telemetry) = runtime_with_recording_sink(json!({
            "decision": "transform",
            "reason": "redacted",
            "transform": {"path": "$policy_target.body", "value": "[REDACTED]"},
            "evidence": {
                "artefact": "sha256:cafe",
                "verification_pointers": {"attestation": "https://x/att"}
            }
        }));
        let _ = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "secret"}}),
        );

        let events = telemetry.events.lock().unwrap();
        let event_types: Vec<_> = events.iter().map(|event| event.event_type).collect();
        assert!(
            event_types.contains(&TelemetryEventType::Decision),
            "Decision event still emitted alongside Transformed event: {event_types:?}"
        );
        let transformed = events
            .iter()
            .find(|event| event.event_type == TelemetryEventType::InterventionPointTransformed)
            .expect("AGT D2 intervention_point.transformed event must fire on Transform decision");
        assert_eq!(transformed.decision, Some(Decision::Transform));
        assert_eq!(transformed.reason_code.as_deref(), Some("redacted"));
        assert_eq!(
            transformed.evidence_artefact.as_deref(),
            Some("sha256:cafe")
        );
        assert_eq!(
            transformed.evidence_verification_pointer_keys,
            vec!["attestation"]
        );
    }

    // ── AGT D1.4 bisected action identity ─────────────────────────────

    #[test]
    fn non_transform_verdict_yields_equal_input_and_enforced_identities() {
        let runtime = runtime(json!({"decision": "allow"}));
        let result = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "data"}}),
        );
        assert!(result.input_identity.is_some());
        assert!(result.enforced_identity.is_some());
        assert_eq!(
            result.input_identity, result.enforced_identity,
            "non-transform decisions keep enforced_identity == input_identity"
        );
        assert_eq!(
            result.action_identity, result.enforced_identity,
            "action_identity is the back-compat alias for enforced_identity"
        );
    }

    #[test]
    fn transform_decision_diverges_input_and_enforced_identities() {
        let runtime = runtime(json!({
            "decision": "transform",
            "transform": {"path": "$policy_target.body", "value": "[REDACTED]"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::Enforce,
            json!({"output": {"body": "secret"}}),
        );
        let input = result.input_identity.expect("input_identity present");
        let enforced = result.enforced_identity.expect("enforced_identity present");
        assert_ne!(
            input, enforced,
            "transform that rewrites the policy target must shift enforced_identity"
        );
        assert_eq!(
            result.action_identity.as_deref(),
            Some(enforced.as_str()),
            "action_identity stays aligned to enforced_identity"
        );
    }

    #[test]
    fn evaluate_only_transform_keeps_enforced_identity_equal_to_input() {
        // Per AGT D1.1 §5 + D1.4: in evaluate_only mode the transform is
        // validated but not applied; transformed_policy_target stays None,
        // so enforced_identity must equal input_identity even though the
        // verdict is Transform.
        let runtime = runtime(json!({
            "decision": "transform",
            "transform": {"path": "$policy_target.body", "value": "[REDACTED]"}
        }));
        let result = evaluate(
            &runtime,
            EnforcementMode::EvaluateOnly,
            json!({"output": {"body": "secret"}}),
        );
        assert_eq!(result.verdict.decision, Decision::Transform);
        assert!(result.transformed_policy_target.is_none());
        assert_eq!(
            result.input_identity, result.enforced_identity,
            "evaluate_only transforms must not shift enforced_identity"
        );
    }

    #[test]
    fn runtime_error_clears_both_identities() {
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
        assert!(result.input_identity.is_none());
        assert!(result.enforced_identity.is_none());
        assert!(result.action_identity.is_none());
    }
}
