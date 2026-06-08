use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, PolicyDispatcher, PreparedPolicyInvocation,
    Runtime, RuntimeError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

const REQUIRED_COVERAGE: &[&str] = &[
    "manifest_validation",
    "unknown_intervention_point_rejection",
    "invalid_root_rejection",
    "per_intervention_point_snapshot_envelope",
    "policy_target_extraction",
    "tool_metadata_projection",
    "preliminary_policy_input_before_annotations",
    "policy_input_canonicalization",
    "rego_prepared_invocation",
    "verdict_normalization",
    "reserved_runtime_error_reasons",
    "policy_target_only_effect_validation_application",
    "parallel_tool_call_per_invocation_semantics",
    "aggregated_streaming_semantics",
    "fail_closed_errors",
];

const FORBIDDEN_VALID_MANIFEST_TOKENS: &[&str] = &[
    "state:",
    "endpoint:",
    "hooks:",
    "variables:",
    "lifetimes:",
    "event_bus:",
    "resolvers:",
    "guard_policies:",
    "allowed_when:",
    "evaluate_when:",
    "auto_resolution:",
    "durable_state:",
    "fail_open:",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    schema_version: u32,
    id: String,
    description: String,
    covers: Vec<String>,
    case_kind: String,
    manifest_yaml: String,
    #[serde(default)]
    expect_valid: Option<bool>,
    #[serde(default)]
    expected_error_reason: Option<String>,
    #[serde(default)]
    expected_intervention_point_names: Option<Vec<String>>,
    #[serde(default)]
    annotation_responses: BTreeMap<String, DispatcherResponse>,
    #[serde(default)]
    intentionally_absent: Vec<String>,
    #[serde(default)]
    evaluations: Vec<FixtureEvaluation>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherResponse {
    #[serde(default)]
    ok: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvaluation {
    name: String,
    intervention_point: String,
    mode: String,
    snapshot: Value,
    #[serde(default)]
    policy_response: Option<DispatcherResponse>,
    expected: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
struct AnnotationCall {
    annotator_name: String,
    preliminary_policy_input: Value,
}

struct FixtureAnnotator {
    responses: BTreeMap<String, Result<Value, RuntimeError>>,
    seen: Mutex<Vec<AnnotationCall>>,
}

impl FixtureAnnotator {
    fn new(responses: BTreeMap<String, Result<Value, RuntimeError>>) -> Self {
        Self {
            responses,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen_len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn seen_since(&self, index: usize) -> Vec<AnnotationCall> {
        self.seen.lock().unwrap()[index..].to_vec()
    }
}

impl AnnotatorDispatcher for FixtureAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        self.seen.lock().unwrap().push(AnnotationCall {
            annotator_name: annotator_name.to_string(),
            preliminary_policy_input: preliminary_policy_input.clone(),
        });
        self.responses
            .get(annotator_name)
            .unwrap_or_else(|| {
                panic!("no fixture annotations response configured for {annotator_name}")
            })
            .clone()
    }
}

struct FixturePolicy {
    responses: Mutex<VecDeque<Result<Value, RuntimeError>>>,
    seen: Mutex<Vec<PreparedPolicyInvocation>>,
}

impl FixturePolicy {
    fn new() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn push_response(&self, response: Result<Value, RuntimeError>) {
        self.responses.lock().unwrap().push_back(response);
    }

    fn seen_len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn seen_since(&self, index: usize) -> Vec<PreparedPolicyInvocation> {
        self.seen.lock().unwrap()[index..].to_vec()
    }

    fn assert_no_pending_responses(&self, case_id: &str) {
        let pending = self.responses.lock().unwrap().len();
        assert_eq!(
            pending, 0,
            "{case_id}: fixture configured {pending} policy responses that were not consumed"
        );
    }
}

impl PolicyDispatcher for FixturePolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        self.seen.lock().unwrap().push(invocation.clone());
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("policy invoked without a configured fixture response"))
    }
}

#[test]
fn fixture_cases_match_current_core_contract() {
    let cases = load_cases();
    assert!(!cases.is_empty(), "expected fixture cases to be present");

    let mut covered = BTreeSet::new();
    for case in &cases {
        assert_eq!(case.schema_version, 1, "{}: unsupported schema", case.id);
        assert!(
            !case.description.trim().is_empty(),
            "{}: missing description",
            case.id
        );
        assert!(
            !case.covers.is_empty(),
            "{}: missing coverage tags",
            case.id
        );
        covered.extend(case.covers.iter().cloned());

        match case.case_kind.as_str() {
            "manifest" => run_manifest_case(case),
            "runtime" => run_runtime_case(case),
            other => panic!("{}: unsupported case_kind {other}", case.id),
        }
    }

    let missing: Vec<_> = REQUIRED_COVERAGE
        .iter()
        .filter(|coverage| !covered.contains(**coverage))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "fixture corpus missing required coverage tags: {missing:?}"
    );
}

fn load_cases() -> Vec<FixtureCase> {
    let cases_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cases");
    let mut paths: Vec<PathBuf> = fs::read_dir(&cases_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", cases_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            serde_json::from_str(&content)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
        })
        .collect()
}

fn run_manifest_case(case: &FixtureCase) {
    let expect_valid = case.expect_valid.unwrap_or(true);
    let result = Manifest::from_yaml_str(&case.manifest_yaml);
    if expect_valid {
        assert_valid_manifest_has_no_removed_concepts(case);
        let manifest = result.unwrap_or_else(|err| panic!("{}: manifest invalid: {err}", case.id));
        if let Some(expected_intervention_point_names) = &case.expected_intervention_point_names {
            let actual: Vec<_> = manifest
                .intervention_points
                .keys()
                .map(|intervention_point| intervention_point.as_str().to_string())
                .collect();
            assert_eq!(
                &actual, expected_intervention_point_names,
                "{}: intervention_point names",
                case.id
            );
        }
    } else {
        let error = result.expect_err("manifest fixture should be invalid");
        assert_eq!(
            Some(error.reason()),
            case.expected_error_reason.as_deref(),
            "{}: manifest error reason",
            case.id
        );
    }
}

fn run_runtime_case(case: &FixtureCase) {
    assert_valid_manifest_has_no_removed_concepts(case);
    assert_intentionally_absent_markers(case);

    let manifest = Manifest::from_yaml_str(&case.manifest_yaml)
        .unwrap_or_else(|err| panic!("{}: manifest invalid: {err}", case.id));
    let annotations = Arc::new(FixtureAnnotator::new(
        case.annotation_responses
            .iter()
            .map(|(name, response)| (name.clone(), dispatcher_result(response)))
            .collect(),
    ));
    let policy = Arc::new(FixturePolicy::new());
    let runtime = Runtime::new(manifest, annotations.clone(), policy.clone())
        .unwrap_or_else(|err| panic!("{}: runtime construction failed: {err}", case.id));

    for evaluation in &case.evaluations {
        run_runtime_evaluation(case, evaluation, &runtime, &annotations, &policy);
    }

    policy.assert_no_pending_responses(&case.id);
}

fn run_runtime_evaluation(
    case: &FixtureCase,
    evaluation: &FixtureEvaluation,
    runtime: &Runtime,
    annotations: &FixtureAnnotator,
    policy: &FixturePolicy,
) {
    if let Some(response) = &evaluation.policy_response {
        policy.push_response(dispatcher_result(response));
    }

    let intervention_point = InterventionPoint::from_str(&evaluation.intervention_point)
        .unwrap_or_else(|err| panic!("{}:{}: {err}", case.id, evaluation.name));
    let mode = EnforcementMode::from_str(&evaluation.mode)
        .unwrap_or_else(|err| panic!("{}:{}: {err}", case.id, evaluation.name));
    let annotation_before = annotations.seen_len();
    let policy_before = policy.seen_len();

    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point,
        snapshot: evaluation.snapshot.clone(),
        mode,
    });

    let actual_verdict = serde_json::to_value(&result.verdict).unwrap();
    assert_eq!(
        &actual_verdict,
        evaluation
            .expected
            .get("verdict")
            .unwrap_or_else(|| panic!("{}:{}: missing expected verdict", case.id, evaluation.name)),
        "{}:{}: verdict",
        case.id,
        evaluation.name
    );

    if let Some(expected_policy_input) = evaluation.expected.get("policy_input") {
        let actual_policy_input = result.policy_input.clone().unwrap_or(Value::Null);
        assert_eq!(
            &actual_policy_input, expected_policy_input,
            "{}:{}: policy_input",
            case.id, evaluation.name
        );
        assert_policy_input_omits_removed_roots(&actual_policy_input, case, evaluation);
    }

    if let Some(expected_transformed_policy_target) =
        evaluation.expected.get("transformed_policy_target")
    {
        let actual_transformed_policy_target = result
            .transformed_policy_target
            .clone()
            .unwrap_or(Value::Null);
        assert_eq!(
            &actual_transformed_policy_target, expected_transformed_policy_target,
            "{}:{}: transformed_policy_target",
            case.id, evaluation.name
        );
    }

    let annotation_delta = annotations.seen_since(annotation_before);
    if let Some(expected_annotation_calls) = evaluation.expected.get("annotation_calls") {
        let actual = serde_json::to_value(annotation_delta).unwrap();
        assert_eq!(
            &actual, expected_annotation_calls,
            "{}:{}: annotation_calls",
            case.id, evaluation.name
        );
    }

    let policy_delta = policy.seen_since(policy_before);
    if let Some(expected_policy_invoked) = evaluation.expected.get("policy_invoked") {
        let expected = expected_policy_invoked.as_bool().unwrap_or_else(|| {
            panic!(
                "{}:{}: expected policy_invoked must be boolean",
                case.id, evaluation.name
            )
        });
        assert_eq!(
            !policy_delta.is_empty(),
            expected,
            "{}:{}: policy_invoked",
            case.id,
            evaluation.name
        );
    }

    if let Some(expected_policy_invocation) = evaluation.expected.get("policy_invocation") {
        assert_eq!(
            policy_delta.len(),
            1,
            "{}:{}: expected exactly one policy invocation",
            case.id,
            evaluation.name
        );
        let actual_invocation = serde_json::to_value(&policy_delta[0]).unwrap();
        assert_eq!(
            &actual_invocation, expected_policy_invocation,
            "{}:{}: policy_invocation",
            case.id, evaluation.name
        );
    }
}

fn dispatcher_result(response: &DispatcherResponse) -> Result<Value, RuntimeError> {
    if let Some(reason) = &response.error {
        Err(runtime_error_for_reason(reason))
    } else if let Some(value) = &response.ok {
        Ok(value.clone())
    } else {
        panic!("dispatcher response must contain ok or error")
    }
}

fn runtime_error_for_reason(reason: &str) -> RuntimeError {
    match reason {
        "runtime_error:manifest_invalid" => RuntimeError::ManifestInvalid("fixture".to_string()),
        "runtime_error:intervention_point_unknown" => {
            RuntimeError::InterventionPointUnknown("fixture".to_string())
        }
        "runtime_error:path_missing" => RuntimeError::PathMissing("fixture".to_string()),
        "runtime_error:path_type_mismatch" => RuntimeError::PathTypeMismatch("fixture".to_string()),
        "runtime_error:tool_unknown" => RuntimeError::ToolUnknown("fixture".to_string()),
        "runtime_error:annotation_failed" => RuntimeError::AnnotationFailed("fixture".to_string()),
        "runtime_error:annotation_timeout" => {
            RuntimeError::AnnotationTimeout("fixture".to_string())
        }
        "runtime_error:policy_invocation_failed" => {
            RuntimeError::PolicyInvocationFailed("fixture".to_string())
        }
        "runtime_error:policy_output_invalid" => {
            RuntimeError::PolicyOutputInvalid("fixture".to_string())
        }
        "runtime_error:effect_invalid" => RuntimeError::EffectInvalid("fixture".to_string()),
        "runtime_error:effect_target_forbidden" => {
            RuntimeError::EffectTargetForbidden("fixture".to_string())
        }
        other => panic!("unsupported fixture runtime error reason: {other}"),
    }
}

fn assert_valid_manifest_has_no_removed_concepts(case: &FixtureCase) {
    for token in FORBIDDEN_VALID_MANIFEST_TOKENS {
        assert!(
            !case.manifest_yaml.contains(token),
            "{}: valid fixture manifest contains removed concept token {token}",
            case.id
        );
    }
}

fn assert_intentionally_absent_markers(case: &FixtureCase) {
    for marker in &case.intentionally_absent {
        match marker.as_str() {
            "stream_chunk_intervention_point" => {
                assert!(InterventionPoint::from_str("stream_chunk").is_err())
            }
            "token_level_enforcement" | "chunk_level_verdicts" => {}
            other => panic!("{}: unknown intentionally_absent marker {other}", case.id),
        }
    }
}

fn assert_policy_input_omits_removed_roots(
    policy_input: &Value,
    case: &FixtureCase,
    evaluation: &FixtureEvaluation,
) {
    if policy_input.is_null() {
        return;
    }
    let root = policy_input.as_object().unwrap_or_else(|| {
        panic!(
            "{}:{}: expected policy_input to be object or null",
            case.id, evaluation.name
        )
    });
    for forbidden in ["request", "resource", "tools"] {
        assert!(
            !root.contains_key(forbidden),
            "{}:{}: policy_input must not contain top-level {forbidden}",
            case.id,
            evaluation.name
        );
    }
}
