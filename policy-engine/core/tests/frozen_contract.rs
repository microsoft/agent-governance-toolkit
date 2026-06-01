use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, AnnotatorType, Decision, EnforcementMode,
    InterventionPoint, InterventionPointRequest, JsonValue, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load_manifest_fixture(name: &str) -> Manifest {
    let path = fixture_root().join("manifests").join(name);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    Manifest::from_yaml_str(&source)
        .unwrap_or_else(|err| panic!("{} did not load: {err}", path.display()))
}

fn load_policy_input_fixture(name: &str) -> Value {
    let path = fixture_root().join("policy-inputs").join(name);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn assert_manifest_invalid(manifest_yaml: &str) {
    let error = Manifest::from_yaml_str(manifest_yaml).expect_err("manifest should be invalid");
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
}

#[test]
fn canonical_manifest_fixtures_load_successfully() {
    let manifests_dir = fixture_root().join("manifests");
    let mut paths: Vec<_> = fs::read_dir(&manifests_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifests_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("yaml"))
        .collect();
    paths.sort();

    let names: BTreeSet<_> = paths
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(names.contains("canonical-all-interventions.yaml"));
    assert!(names.contains("minimal-all-interventions.yaml"));

    let expected_intervention_points = [
        InterventionPoint::AgentStartup,
        InterventionPoint::Input,
        InterventionPoint::PreModelCall,
        InterventionPoint::PostModelCall,
        InterventionPoint::PreToolCall,
        InterventionPoint::PostToolCall,
        InterventionPoint::Output,
        InterventionPoint::AgentShutdown,
    ];

    for path in paths {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let manifest = Manifest::from_yaml_str(&source)
            .unwrap_or_else(|err| panic!("{} did not load: {err}", path.display()));
        assert!(
            !manifest.policies.is_empty(),
            "{} must use top-level policies",
            path.display()
        );
        for intervention_point in expected_intervention_points {
            assert!(
                manifest
                    .intervention_points
                    .contains_key(&intervention_point),
                "{} missing {intervention_point}",
                path.display()
            );
        }
    }

    let canonical = load_manifest_fixture("canonical-all-interventions.yaml");
    assert_eq!(canonical.extends, vec!["./base-controls.yaml"]);
    assert!(canonical
        .intervention_points
        .values()
        .all(|config| !config.annotations.is_empty()));

    let annotator_types: BTreeSet<_> = canonical
        .annotators
        .values()
        .map(|annotator| annotator.annotator_type.as_str().to_string())
        .collect();
    assert_eq!(
        annotator_types,
        BTreeSet::from([
            AnnotatorType::Classifier.as_str().to_string(),
            AnnotatorType::Llm.as_str().to_string(),
            AnnotatorType::Endpoint.as_str().to_string(),
        ])
    );
}

#[test]
fn manifest_invariants_are_frozen() {
    for intervention_point in ["agent_startup", "output", "agent_shutdown"] {
        assert_eq!(
            InterventionPoint::from_str(intervention_point)
                .unwrap()
                .as_str(),
            intervention_point
        );
    }
    for removed_or_alias in ["startup", "shutdown", "final_output", "state", "endpoint"] {
        assert!(InterventionPoint::from_str(removed_or_alias).is_err());
    }

    let valid = Manifest::from_yaml_str(
        r#"agent_control_specification_version: "0.3.1-beta"
extends:
  - ./base.yaml
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy_target_kind: user_input
    annotations:
      classifier:
        from: "$policy_target.text"
    policy:
      id: test_policy
annotators:
  classifier:
    type: classifier
  judge:
    type: llm
  actor_lookup:
    type: endpoint
"#,
    )
    .unwrap();
    assert_eq!(valid.extends, vec!["./base.yaml"]);
    assert!(valid.policies.contains_key("test_policy"));
    assert!(valid.intervention_points[&InterventionPoint::Input]
        .annotations
        .contains_key("classifier"));

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
extends: ./base.yaml
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: test_policy
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
intervention_points:
  startup:
    policy_target: "$snap.agent"
    policy:
      id: test_policy
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target: "$pi.input"
    policy:
      id: test_policy
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: test_policy
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      type: test
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: test_policy
annotators:
  classifier:
    type: regex
"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
annotations:
  classifier:
    from: "$snap.input.text"
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: test_policy
annotators:
  classifier:
    type: classifier
"#,
    );
}

struct GoldenAnnotator {
    responses: BTreeMap<String, JsonValue>,
}

impl AnnotatorDispatcher for GoldenAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(self
            .responses
            .get(annotator_name)
            .cloned()
            .unwrap_or(JsonValue::Null))
    }
}

struct AllowPolicy;

impl PolicyDispatcher for AllowPolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(json!({"decision": "allow"}))
    }
}

#[test]
fn golden_policy_input_fixtures_match_runtime_contract() {
    let mut manifest = load_manifest_fixture("canonical-all-interventions.yaml");
    // The fixture carries `extends` purely to prove the field round-trips as data
    // (see canonical_manifest_fixtures_load_successfully); it is otherwise
    // self-contained, so clear the unresolved reference before building a runtime,
    // matching what a file-based loader does after composing the bases.
    manifest.extends.clear();
    let mut responses = BTreeMap::new();
    responses.insert("actor_context".to_string(), json!({"tier": "gold"}));
    responses.insert(
        "output_safety".to_string(),
        json!({"contains_pii": false, "risk": "low"}),
    );
    responses.insert(
        "prompt_classifier".to_string(),
        json!({"categories": [], "risk": "low"}),
    );
    responses.insert(
        "startup_context".to_string(),
        json!({"deployment": "prod", "region": "us-east"}),
    );
    responses.insert(
        "shutdown_context".to_string(),
        json!({"reason_seen": "completed"}),
    );
    responses.insert(
        "tool_risk".to_string(),
        json!({"data_labels": ["public"], "risk": "low"}),
    );

    let runtime = Runtime::new(
        manifest,
        Arc::new(GoldenAnnotator { responses }),
        Arc::new(AllowPolicy),
    )
    .unwrap();

    let cases = [
        (
            InterventionPoint::AgentStartup,
            json!({
                "agent": {"id": "agent-007", "version": "1.0.0"},
                "metadata": {"deployment": "prod"}
            }),
            "agent-startup.json",
        ),
        (
            InterventionPoint::PreModelCall,
            json!({
                "conversation": {"id": "conv-123"},
                "model_request": {
                    "messages": [
                        {"content": "Be helpful.", "role": "system"},
                        {"content": "Summarize account policy.", "role": "user"}
                    ],
                    "params": {"temperature": 0},
                    "tools": [{"name": "search"}]
                }
            }),
            "pre-model-call.json",
        ),
        (
            InterventionPoint::AgentShutdown,
            json!({
                "agent": {"id": "agent-007", "version": "1.0.0"},
                "metadata": {"deployment": "prod"},
                "reason": "completed"
            }),
            "agent-shutdown.json",
        ),
        (
            InterventionPoint::PreToolCall,
            json!({
                "action": "invokeTool",
                "actor": {"id": "user-123", "type": "User"},
                "tool_call": {
                    "args": {"limit": 5, "query": "account policy"},
                    "id": "tool-call-1",
                    "name": "search"
                }
            }),
            "pre-tool-call.json",
        ),
        (
            InterventionPoint::Output,
            json!({
                "output": {
                    "citations": ["policy-doc-1"],
                    "content": "Your account policy summary is ready."
                }
            }),
            "output.json",
        ),
    ];

    for (intervention_point, snapshot, fixture_name) in cases {
        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point,
            snapshot,
            mode: EnforcementMode::Enforce,
        });
        assert_eq!(result.verdict.decision, Decision::Allow, "{fixture_name}");
        let actual = result
            .policy_input
            .expect("policy input should be available");
        let expected = load_policy_input_fixture(fixture_name);
        assert_eq!(actual, expected, "{fixture_name}");

        let root = actual
            .as_object()
            .expect("policy input root should be an object");
        assert!(root.contains_key("annotations"));
        assert!(root.contains_key("snapshot"));
        assert!(root.contains_key("policy_target"));
        assert!(root.contains_key("tool"));
        assert!(!root.contains_key("request"));
        assert!(!root.contains_key("resource"));
        assert!(!root.contains_key("tools"));
    }
}
