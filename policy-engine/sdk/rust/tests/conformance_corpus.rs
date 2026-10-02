//! Executes the shared conformance corpus in `tests/conformance/cases`.
//!
//! Lives in the SDK rather than the core shim because applying a transform and
//! deriving identities are host obligations now, so the expected results are
//! only observable through `HostEvaluation`.

use agent_control_specification::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, HostEvaluation,
    InterceptionPoint, JsonValue, Limits, Manifest, PolicyDispatcher, PreparedPolicyInvocation,
    Runtime, RuntimeError,
};
use jsonschema::JSONSchema;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

struct FixtureAnnotator {
    behavior: Option<String>,
    outputs: BTreeMap<String, JsonValue>,
    order: Arc<Mutex<Vec<String>>>,
}

impl AnnotatorDispatcher for FixtureAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        self.order.lock().unwrap().push(annotator_name.to_string());
        match self.behavior.as_deref() {
            Some("error") => Err(RuntimeError::AnnotationFailed("fixture".to_string())),
            Some("timeout") => Err(RuntimeError::AnnotationTimeout("fixture".to_string())),
            _ => Ok(self
                .outputs
                .get(annotator_name)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"ok": true}))),
        }
    }
}

struct FixturePolicy {
    response: JsonValue,
}

impl PolicyDispatcher for FixturePolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match self
            .response
            .get("__policy_behavior")
            .and_then(Value::as_str)
        {
            Some("error") => Err(RuntimeError::PolicyInvocationFailed("fixture".to_string())),
            _ => Ok(self.response.clone()),
        }
    }
}

fn conformance_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is policy-engine/sdk/rust; the corpus lives at
    // policy-engine/tests/conformance.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap()
        .join("tests/conformance")
}

fn case_paths() -> Vec<PathBuf> {
    let mut paths = fs::read_dir(conformance_dir().join("cases"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn limits_from_case(case: &Value) -> Limits {
    let mut limits = Limits::default();
    if let Some(value) = case
        .pointer("/limits/max_snapshot_bytes")
        .and_then(Value::as_u64)
    {
        limits.max_snapshot_bytes = value as usize;
    }
    if let Some(value) = case
        .pointer("/limits/max_policy_input_depth")
        .and_then(Value::as_u64)
    {
        limits.max_policy_input_depth = value as usize;
    }
    if let Some(value) = case
        .pointer("/limits/max_annotators_per_point")
        .and_then(Value::as_u64)
    {
        limits.max_annotators_per_point = value as usize;
    }
    if let Some(value) = case
        .pointer("/limits/max_annotator_output_bytes")
        .and_then(Value::as_u64)
    {
        limits.max_annotator_output_bytes = value as usize;
    }
    if let Some(value) = case
        .pointer("/limits/max_policy_output_bytes")
        .and_then(Value::as_u64)
    {
        limits.max_policy_output_bytes = value as usize;
    }
    if let Some(value) = case
        .pointer("/limits/max_extends_depth")
        .and_then(Value::as_u64)
    {
        limits.max_extends_depth = value as usize;
    }
    if let Some(value) = case
        .pointer("/limits/max_merged_manifest_bytes")
        .and_then(Value::as_u64)
    {
        limits.max_merged_manifest_bytes = value as usize;
    }
    limits
}

#[test]
fn conformance_cases_validate_against_schema() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(conformance_dir().join("cases.schema.json")).unwrap(),
    )
    .unwrap();
    let compiled = JSONSchema::compile(&schema).unwrap();
    let paths = case_paths();
    assert!(paths.len() >= 16, "expanded corpus should not shrink");

    for path in paths {
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        if let Err(errors) = compiled.validate(&case) {
            let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
            panic!("{} failed schema validation: {messages:?}", path.display());
        }
        assert_eq!(
            path.file_stem().unwrap().to_str().unwrap(),
            case["id"].as_str().unwrap(),
            "case id must match file name"
        );
    }
}

#[test]
fn coverage_claims_reference_existing_cases() {
    let case_ids = case_paths()
        .into_iter()
        .map(|path| path.file_stem().unwrap().to_str().unwrap().to_string())
        .collect::<std::collections::BTreeSet<_>>();
    let coverage = fs::read_to_string(conformance_dir().join("coverage.md")).unwrap();
    let mut sections = 0usize;
    for line in coverage.lines() {
        if !line.starts_with('|') || line.starts_with("| ---") || line.contains("Spec section") {
            continue;
        }
        let cells = line
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        if cells.len() != 4
            || !cells[0]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_digit())
        {
            continue;
        }
        sections += 1;
        assert!(!cells[1].is_empty(), "section {} has no status", cells[0]);
        assert!(!cells[2].is_empty(), "section {} has no claim", cells[0]);
        assert!(!cells[3].is_empty(), "section {} has no anchors", cells[0]);
    }
    assert!(sections >= 23, "expected expanded section coverage");
    let missing = case_ids
        .into_iter()
        .filter(|case| !coverage.contains(case))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "every case must be mapped in coverage.md: {missing:?}"
    );
}

#[test]
fn executable_conformance_corpus_matches_expected_results() {
    for path in case_paths() {
        let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let id = case["id"].as_str().unwrap();
        match case["operation"].as_str().unwrap() {
            "evaluate" => run_evaluate_case(id, &case),
            "approval_action_mismatch" => run_approval_mismatch_case(id, &case),
            other => panic!("{id}: unsupported operation {other}"),
        }
    }
}

fn run_evaluate_case(id: &str, case: &Value) {
    let manifest = Manifest::from_yaml_str(case["manifest_yaml"].as_str().unwrap())
        .unwrap_or_else(|error| panic!("{id}: manifest failed: {error}"));
    let annotator_order = Arc::new(Mutex::new(Vec::new()));
    let annotator_outputs = case
        .get("annotator_outputs")
        .and_then(Value::as_object)
        .map(|outputs| {
            outputs
                .iter()
                .map(|(name, output)| (name.clone(), output.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut policy_response = case["policy_response"].clone();
    if let Some(policy_behavior) = case.get("policy_behavior").and_then(Value::as_str) {
        policy_response["__policy_behavior"] = Value::String(policy_behavior.to_string());
    }
    let runtime = Runtime::with_limits(
        manifest,
        Arc::new(FixtureAnnotator {
            behavior: case
                .get("annotator_behavior")
                .and_then(Value::as_str)
                .map(str::to_string),
            outputs: annotator_outputs,
            order: annotator_order.clone(),
        }),
        Arc::new(FixturePolicy {
            response: policy_response,
        }),
        limits_from_case(case),
    )
    .unwrap_or_else(|error| panic!("{id}: runtime build failed: {error}"));
    let point = InterceptionPoint::from_str(case["intervention_point"].as_str().unwrap()).unwrap();
    let mode = match case.get("mode").and_then(Value::as_str) {
        Some("evaluate_only") => EnforcementMode::EvaluateOnly,
        _ => EnforcementMode::Enforce,
    };
    let engine = runtime.evaluate_point(point, case["snapshot"].clone());
    let result =
        HostEvaluation::from_engine(point, engine, mode).unwrap_or_else(|(error, detail)| {
            HostEvaluation {
                verdict: agent_hooks::Verdict::host_error(error, Some(detail)),
                policy_input: None,
                transformed_policy_target: None,
                action_identity: None,
                input_identity: None,
                enforced_identity: None,
            }
        });
    assert_expected(id, case, &result, &annotator_order.lock().unwrap());
}

fn run_approval_mismatch_case(id: &str, case: &Value) {
    // Approval resolution is a host obligation, so an identity mismatch is a
    // reserved host_error the host synthesizes rather than an engine error.
    let mismatch = agent_hooks::Verdict::host_error(
        agent_hooks::HostError::ApprovalIdentityMismatch,
        Some("approved action identity differed".to_string()),
    );
    assert_eq!(mismatch.decision, Decision::Deny, "{id}");
    assert_eq!(
        mismatch.reason.as_deref(),
        case.pointer("/expected/reason").and_then(Value::as_str),
        "{id}"
    );
}

fn assert_expected(id: &str, case: &Value, result: &HostEvaluation, annotator_order: &[String]) {
    let expected = &case["expected"];
    assert_eq!(
        result.verdict.decision,
        match expected["decision"].as_str().unwrap() {
            "allow" => Decision::Allow,
            "deny" => Decision::Deny,
            "transform" => Decision::Transform,
            other => panic!("{id}: {other} is not one of the three normalized decisions"),
        },
        "{id}: decision"
    );
    if expected.get("reason").is_some() {
        assert_eq!(
            result.verdict.reason.as_deref(),
            expected["reason"].as_str(),
            "{id}: reason"
        );
    }
    if let Some(expected_transformed) = expected.get("transformed_policy_target") {
        match expected_transformed {
            Value::Null => assert!(
                result.transformed_policy_target.is_none(),
                "{id}: transformed target should be absent"
            ),
            value => assert_eq!(
                result.transformed_policy_target.as_ref(),
                Some(value),
                "{id}: transformed target"
            ),
        }
    }
    if let Some(expected_target) = expected.get("policy_target") {
        assert_eq!(
            result.policy_input.as_ref().unwrap()["policy_target"]["value"],
            *expected_target,
            "{id}: policy target"
        );
    }
    if let Some(tool_name) = expected.get("tool_name").and_then(Value::as_str) {
        assert_eq!(
            result.policy_input.as_ref().unwrap()["tool"]["name"],
            tool_name,
            "{id}: tool name"
        );
    }
    if let Some(annotations) = expected.get("annotations") {
        assert_eq!(
            &result.policy_input.as_ref().unwrap()["annotations"],
            annotations,
            "{id}: annotations"
        );
    }
    if let Some(expected_order) = expected.get("annotator_order").and_then(Value::as_array) {
        let expected_order = expected_order
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(annotator_order, expected_order, "{id}: annotator order");
    }
    // warnings[] and approval carry what the retired warn and escalate
    // decisions used to express, so a normalized verdict is only fully pinned
    // when both are asserted.
    if let Some(warnings) = expected.get("warnings").and_then(Value::as_str) {
        let present = !result.verdict.warnings.is_empty();
        assert_eq!(present, warnings == "present", "{id}: warnings");
    }
    if let Some(approval) = expected.get("approval").and_then(Value::as_str) {
        let present = result.verdict.approval.is_some();
        assert_eq!(present, approval == "present", "{id}: approval");
    }
    if let Some(action_identity) = expected.get("action_identity").and_then(Value::as_str) {
        match action_identity {
            "present" => assert!(result.action_identity.is_some(), "{id}: action identity"),
            "absent" => assert!(result.action_identity.is_none(), "{id}: action identity"),
            other => panic!("{id}: unsupported action_identity expectation {other}"),
        }
    }
}
