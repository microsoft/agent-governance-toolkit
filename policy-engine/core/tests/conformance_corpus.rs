use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Limits, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError, Verdict,
};
use jsonschema::JSONSchema;
use serde_json::Value;
use std::{fs, path::PathBuf, str::FromStr, sync::Arc};

struct FixtureAnnotator;

impl AnnotatorDispatcher for FixtureAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(serde_json::json!({"ok": true}))
    }
}

struct FixturePolicy {
    response: JsonValue,
}

impl PolicyDispatcher for FixturePolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(self.response.clone())
    }
}

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
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
    let mut covered = std::collections::BTreeSet::new();
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
        if cells.len() != 3 {
            continue;
        }
        sections += 1;
        let cases = cells[2]
            .split(',')
            .map(str::trim)
            .filter(|case| !case.is_empty())
            .collect::<Vec<_>>();
        assert!(!cases.is_empty(), "section {} has no cases", cells[0]);
        for case in cases {
            assert!(
                case_ids.contains(case),
                "coverage references missing case {case}"
            );
            covered.insert(case.to_string());
        }
    }
    assert!(sections >= 7, "expected expanded section coverage");
    assert_eq!(
        covered, case_ids,
        "every case must be mapped in coverage.md"
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
    let runtime = Runtime::with_limits(
        manifest,
        Arc::new(FixtureAnnotator),
        Arc::new(FixturePolicy {
            response: case["policy_response"].clone(),
        }),
        limits_from_case(case),
    )
    .unwrap_or_else(|error| panic!("{id}: runtime build failed: {error}"));
    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::from_str(
            case["intervention_point"].as_str().unwrap(),
        )
        .unwrap(),
        snapshot: case["snapshot"].clone(),
        mode: EnforcementMode::Enforce,
    });
    assert_expected(id, case, &result);
}

fn run_approval_mismatch_case(id: &str, case: &Value) {
    let mismatch = Verdict::runtime_error(&RuntimeError::ApprovalActionMismatch(
        "approved action identity differed".to_string(),
    ));
    assert_eq!(mismatch.decision, Decision::Deny, "{id}");
    assert_eq!(
        mismatch.reason.as_deref(),
        case.pointer("/expected/reason").and_then(Value::as_str),
        "{id}"
    );
}

fn assert_expected(
    id: &str,
    case: &Value,
    result: &agent_control_specification_core::InterventionPointResult,
) {
    let expected = &case["expected"];
    assert_eq!(
        result.verdict.decision,
        Decision::from_str(expected["decision"].as_str().unwrap()).unwrap(),
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
    if let Some(action_identity) = expected.get("action_identity").and_then(Value::as_str) {
        match action_identity {
            "present" => assert!(result.action_identity.is_some(), "{id}: action identity"),
            "absent" => assert!(result.action_identity.is_none(), "{id}: action identity"),
            other => panic!("{id}: unsupported action_identity expectation {other}"),
        }
    }
}
