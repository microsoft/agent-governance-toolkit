use agent_control_specification_core::{
    action_identity, canonical_json, AnnotatorDispatcher, AnnotatorInvocation, Decision,
    EnforcementMode, InterventionPoint, InterventionPointRequest, JsonPath, JsonValue, Manifest,
    PathEnv, PerfTelemetry, PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
    TelemetryEvent, TelemetryEventType, TelemetrySink,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct AnnotationCall {
    annotator_name: String,
    preliminary_policy_input: JsonValue,
}

struct RecordingAnnotator {
    outputs: Mutex<BTreeMap<String, Result<JsonValue, RuntimeError>>>,
    seen: Mutex<Vec<AnnotationCall>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingAnnotator {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Self {
            outputs: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(Vec::new()),
            events,
        })
    }

    fn set_output(&self, annotator_name: &str, output: JsonValue) {
        self.outputs
            .lock()
            .unwrap()
            .insert(annotator_name.to_string(), Ok(output));
    }

    fn set_error(&self, annotator_name: &str, error: RuntimeError) {
        self.outputs
            .lock()
            .unwrap()
            .insert(annotator_name.to_string(), Err(error));
    }

    fn seen(&self) -> Vec<AnnotationCall> {
        self.seen.lock().unwrap().clone()
    }
}

impl AnnotatorDispatcher for RecordingAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("annotations:{annotator_name}"));
        self.seen.lock().unwrap().push(AnnotationCall {
            annotator_name: annotator_name.to_string(),
            preliminary_policy_input: preliminary_policy_input.clone(),
        });
        self.outputs
            .lock()
            .unwrap()
            .get(annotator_name)
            .cloned()
            .unwrap_or(Ok(JsonValue::Null))
    }
}

#[derive(Clone, Debug)]
struct PolicyCall {
    invocation: PreparedPolicyInvocation,
}

impl PolicyCall {
    fn final_policy_input(&self) -> &JsonValue {
        self.invocation
            .policy_input()
            .expect("test policy invocation should include final policy input")
    }
}

struct RecordingPolicy {
    result: Mutex<Result<JsonValue, RuntimeError>>,
    seen: Mutex<Vec<PolicyCall>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingPolicy {
    fn allow(events: Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Self::with_output(json!({"decision": "allow"}), events)
    }

    fn with_output(output: JsonValue, events: Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(Ok(output)),
            seen: Mutex::new(Vec::new()),
            events,
        })
    }

    fn with_error(error: RuntimeError, events: Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(Err(error)),
            seen: Mutex::new(Vec::new()),
            events,
        })
    }

    fn seen(&self) -> Vec<PolicyCall> {
        self.seen.lock().unwrap().clone()
    }
}

impl PolicyDispatcher for RecordingPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        self.events.lock().unwrap().push("policy".to_string());
        self.seen.lock().unwrap().push(PolicyCall {
            invocation: invocation.clone(),
        });
        self.result.lock().unwrap().clone()
    }
}

struct RecordingTelemetry {
    events: Arc<Mutex<Vec<TelemetryEvent>>>,
}

impl RecordingTelemetry {
    fn new() -> (Arc<Self>, Arc<Mutex<Vec<TelemetryEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(Self {
                events: events.clone(),
            }),
            events,
        )
    }
}

impl TelemetrySink for RecordingTelemetry {
    fn emit(&self, event: TelemetryEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn runtime(
    manifest_yaml: &str,
    annotations: Arc<RecordingAnnotator>,
    policy: Arc<RecordingPolicy>,
) -> Runtime {
    let manifest = Manifest::from_yaml_str(manifest_yaml).unwrap();
    Runtime::new(manifest, annotations, policy).unwrap()
}

fn no_events() -> Arc<Mutex<Vec<String>>> {
    Arc::new(Mutex::new(Vec::new()))
}

#[test]
fn action_identity_is_stable_for_repeated_escalations() {
    let manifest_yaml = r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
"#;
    let events = no_events();
    let policy = RecordingPolicy::with_output(json!({"decision": "escalate"}), events.clone());
    let runtime = runtime(manifest_yaml, RecordingAnnotator::new(events), policy);
    let snapshot = json!({"input": {"text": "approve me", "nested": {"b": 2, "a": 1}}});

    let first = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: snapshot.clone(),
        mode: EnforcementMode::Enforce,
    });
    let second = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot,
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(first.verdict.decision, Decision::Escalate);
    assert_eq!(first.action_identity, second.action_identity);
    let policy_input = first.policy_input.as_ref().expect("policy input");
    assert_eq!(
        first.action_identity.as_deref(),
        Some(action_identity(policy_input).unwrap().as_str())
    );
}

fn assert_manifest_invalid(manifest_yaml: &str) {
    let error = Manifest::from_yaml_str(manifest_yaml).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
}

#[test]
fn runtime_is_send_sync_for_reentrant_intervention_point_evaluation() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Runtime>();
}

#[test]
fn manifest_accepts_only_the_design_intervention_point_enum() {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  agent_startup:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $snap.agent
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: test_policy
    policy_target: $snap.model_request
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: test_policy
    policy_target: $snap.model_response
  pre_tool_call:
    policy_target_kind: tool_args
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args
  post_tool_call:
    policy_target_kind: tool_result
    policy:
      id: test_policy
    policy_target: $snap.tool_result
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output
  agent_shutdown:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $snap.agent"#,
    )
    .unwrap();

    assert_eq!(manifest.intervention_points.len(), 8);
    for intervention_point in [
        InterventionPoint::AgentStartup,
        InterventionPoint::Input,
        InterventionPoint::PreModelCall,
        InterventionPoint::PostModelCall,
        InterventionPoint::PreToolCall,
        InterventionPoint::PostToolCall,
        InterventionPoint::Output,
        InterventionPoint::AgentShutdown,
    ] {
        assert!(manifest
            .intervention_points
            .contains_key(&intervention_point));
        assert_eq!(
            InterventionPoint::from_str(intervention_point.as_str()).unwrap(),
            intervention_point
        );
    }

    for removed_or_unknown in [
        "state",
        "endpoint",
        "final_output",
        "startup",
        "shutdown",
        "hooks",
    ] {
        assert!(InterventionPoint::from_str(removed_or_unknown).is_err());
        let manifest_yaml = format!(
            r#"
agent_control_specification_version: "0.3.1-beta"
policies:
  test_policy:
    type: test
intervention_points:
  {removed_or_unknown}:
    policy_target: "$snap.value"
    policy:
      id: test_policy
"#
        );
        assert_manifest_invalid(&manifest_yaml);
    }
}

#[test]
fn manifest_enforces_explicit_roots_for_each_field_context() {
    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  agent_startup:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $snap.agent
  input:
    policy:
      id: test_policy
    policy_target: input"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  agent_startup:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $snap.agent
  input:
    policy:
      id: test_policy
    policy_target: $pi.input"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  agent_startup:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $snap.agent
  input:
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.input"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  pre_tool_call:
    tool_name_from: $pi.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: input
annotators:
  classifier:
    type: classifier"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      missing_classifier:
        from: $policy_target.text"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
annotators:
  classifier:
    type: heuristic"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
        annotator: classifier
annotators:
  classifier:
    type: classifier"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: missing_policy
    policy_target: $snap.input"#,
    );

    assert_manifest_invalid(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $pi.annotations.classifier
annotators:
  classifier:
    type: classifier"#,
    );
}

#[test]
fn explicit_path_roots_resolve_against_their_intended_envelopes() {
    let snap = json!({
        "tool_call": {
            "name": "wire_transfer",
            "args": {"amount": 100, "notes": ["first"]}
        }
    });
    let pi = json!({
        "intervention_point": "pre_tool_call",
        "policy_target": {
            "kind": "tool_args",
            "path": "$snap.tool_call.args",
            "value": {"amount": 100, "notes": ["first"]}
        },
        "snapshot": snap,
        "annotations": {"risk": {"score": 0.2}},
        "tool": {"name": "wire_transfer", "clearance": ["banking", "payments"]}
    });

    assert_eq!(
        JsonPath::parse("$snap.tool_call.args.amount")
            .unwrap()
            .resolve(&PathEnv::with_snap(&pi["snapshot"]))
            .unwrap(),
        json!(100)
    );
    assert_eq!(
        JsonPath::parse_with_snapshot_alias("$.tool_call.args.amount")
            .unwrap()
            .resolve(&PathEnv::with_snap(&pi["snapshot"]))
            .unwrap(),
        json!(100)
    );
    assert_eq!(
        JsonPath::parse_with_snapshot_alias("$")
            .unwrap()
            .resolve(&PathEnv::with_snap(&pi["snapshot"]))
            .unwrap(),
        pi["snapshot"]
    );
    assert_eq!(
        JsonPath::parse("$pi.snapshot.tool_call.name")
            .unwrap()
            .resolve(&PathEnv::with_pi(&pi))
            .unwrap(),
        json!("wire_transfer")
    );
    assert_eq!(
        JsonPath::parse("$policy_target.notes[0]")
            .unwrap()
            .resolve(&PathEnv::with_pi(&pi))
            .unwrap(),
        json!("first")
    );
    assert_eq!(
        JsonPath::parse("$tool.clearance[1]")
            .unwrap()
            .resolve(&PathEnv::with_pi(&pi))
            .unwrap(),
        json!("payments")
    );
    assert_eq!(
        JsonPath::parse("tool_call.args").unwrap_err().to_string(),
        "path must start with an explicit root"
    );
    assert_eq!(
        JsonPath::parse("$snap.tool_call.name")
            .unwrap()
            .resolve(&PathEnv::with_pi(&pi))
            .unwrap_err()
            .reason(),
        "runtime_error:path_missing"
    );
}

#[test]
fn manifest_validates_typed_policy_configs_and_supported_engines() {
    let valid = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  input_rego_policy:
    type: rego
    bundle: ./policy/bundle.tar.gz
  pre_tool_call_test_policy:
    type: test
  output_custom_policy:
    type: custom
    adapter: my_adapter
intervention_points:
  input:
    policy:
      id: input_rego_policy
      query: data.agent_control_specification.input.verdict
    policy_target: $snap.input
  pre_tool_call:
    tool_name_from: $snap.tool_call.name
    policy:
      id: pre_tool_call_test_policy
    policy_target: $snap.tool_call.args
  output:
    policy:
      id: output_custom_policy
    policy_target: $snap.output"#,
    )
    .unwrap();
    assert!(valid
        .intervention_points
        .contains_key(&InterventionPoint::Input));
    assert!(valid
        .intervention_points
        .contains_key(&InterventionPoint::PreToolCall));
    assert!(valid
        .intervention_points
        .contains_key(&InterventionPoint::Output));

    for invalid_policy in [r#"type: mock"#, r#"type: rego"#, r#"type: custom"#] {
        let manifest_yaml = format!(
            r#"
agent_control_specification_version: "0.3.1-beta"
policies:
  bad_policy:
    {invalid_policy}
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: bad_policy
"#
        );
        assert_manifest_invalid(&manifest_yaml);
    }

    let empty_rego_binding_query = r#"
agent_control_specification_version: "0.3.1-beta"
policies:
  bad_policy:
    type: rego
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: bad_policy
      query: ""
"#;
    assert_manifest_invalid(empty_rego_binding_query);
}

#[test]
fn policy_target_extraction_and_policy_input_shape_cover_all_runtime_intervention_points() {
    let events = no_events();
    let annotations = RecordingAnnotator::new(events.clone());
    let policy = RecordingPolicy::allow(events);
    let tool_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  agent_startup:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $snap.agent
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: test_policy
    policy_target: $snap.model_request
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: test_policy
    policy_target: $snap.model_response
  pre_tool_call:
    policy_target_kind: tool_args
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args
  post_tool_call:
    policy_target_kind: tool_result
    policy:
      id: test_policy
    policy_target: $snap.tool_result
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output
  agent_shutdown:
    policy_target_kind: agent_metadata
    policy:
      id: test_policy
    policy_target: $"#,
        annotations,
        policy.clone(),
    );

    let cases = vec![
        (
            InterventionPoint::AgentStartup,
            json!({"agent": {"id": "agent-1", "status": "starting"}}),
            json!({"id": "agent-1", "status": "starting"}),
            "agent_metadata",
        ),
        (
            InterventionPoint::Input,
            json!({"input": {"text": "hello"}}),
            json!({"text": "hello"}),
            "user_input",
        ),
        (
            InterventionPoint::PreModelCall,
            json!({"model_request": {"messages": [{"role": "user", "content": "hi"}]}}),
            json!({"messages": [{"role": "user", "content": "hi"}]}),
            "model_request",
        ),
        (
            InterventionPoint::PostModelCall,
            json!({"model_response": {"content": "ok", "tool_calls": []}}),
            json!({"content": "ok", "tool_calls": []}),
            "model_response",
        ),
        (
            InterventionPoint::PreToolCall,
            json!({"tool_call": {"id": "call-1", "name": "search", "args": {"q": "bob"}}}),
            json!({"q": "bob"}),
            "tool_args",
        ),
        (
            InterventionPoint::PostToolCall,
            json!({"tool_call": {"id": "call-1", "name": "search"}, "tool_result": {"rows": []}}),
            json!({"rows": []}),
            "tool_result",
        ),
        (
            InterventionPoint::Output,
            json!({"output": {"content": "done"}}),
            json!({"content": "done"}),
            "assistant_output",
        ),
        (
            InterventionPoint::AgentShutdown,
            json!({"agent": {"id": "agent-1"}, "reason": "complete"}),
            json!({"agent": {"id": "agent-1"}, "reason": "complete"}),
            "agent_metadata",
        ),
    ];

    for (intervention_point, snapshot, expected_policy_target, expected_kind) in cases {
        let result = tool_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point,
            snapshot,
            mode: EnforcementMode::Enforce,
        });
        assert_eq!(result.verdict.decision, Decision::Allow);
        let policy_input = result.policy_input.unwrap();
        assert_eq!(
            policy_input["intervention_point"],
            json!(intervention_point.as_str())
        );
        assert_eq!(policy_input["policy_target"]["kind"], json!(expected_kind));
        assert_eq!(
            policy_input["policy_target"]["value"],
            expected_policy_target
        );
        assert_eq!(policy_input["annotations"], json!({}));
        assert!(policy_input["tool"].is_null());
        let root = policy_input.as_object().unwrap();
        assert!(!root.contains_key("request"));
        assert!(!root.contains_key("resource"));
        assert!(!root.contains_key("tools"));
    }

    assert_eq!(policy.seen().len(), 8);
}

#[test]
fn policy_dispatcher_receives_prepared_rego_and_test_invocations() {
    let events = no_events();
    let policy = RecordingPolicy::allow(events.clone());
    let runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  input_rego_policy:
    type: rego
    bundle: ./policy/input.tar.gz
  output_test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_rego_policy
      query: data.agent_control_specification.input.verdict
    policy_target: $snap.input
  output:
    policy_target_kind: assistant_output
    policy:
      id: output_test_policy
    policy_target: $snap.output"#,
        RecordingAnnotator::new(events),
        policy.clone(),
    );

    let input_result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": "hello"}}),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(input_result.verdict.decision, Decision::Allow);

    let output_result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Output,
        snapshot: json!({"output": {"safe": true}}),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(output_result.verdict.decision, Decision::Allow);

    let calls = policy.seen();
    assert_eq!(calls.len(), 2);
    match &calls[0].invocation {
        PreparedPolicyInvocation::Rego(invocation) => {
            assert_eq!(
                invocation.query,
                "data.agent_control_specification.input.verdict"
            );
            assert_eq!(invocation.bundle.as_deref(), Some("./policy/input.tar.gz"));
            assert_eq!(invocation.input, input_result.policy_input.unwrap());
            assert_eq!(
                invocation.canonical_input,
                canonical_json(&invocation.input).unwrap()
            );
        }
        other => panic!("expected Rego invocation, got {other:?}"),
    }
    match &calls[1].invocation {
        PreparedPolicyInvocation::Test(invocation) => {
            assert_eq!(invocation.input, output_result.policy_input.unwrap());
            assert_eq!(
                invocation.canonical_input,
                canonical_json(&invocation.input).unwrap()
            );
        }
        other => panic!("expected Test invocation, got {other:?}"),
    }
}

#[test]
fn runtime_flow_uses_preliminary_annotations_final_policy_input_and_transform_in_order() {
    let events = no_events();
    let annotations = RecordingAnnotator::new(events.clone());
    annotations.set_output("tool_context", json!({"saw_tool": true}));
    annotations.set_output("actor_context", json!({"tier": "gold"}));
    annotations.set_output(
        "classifier",
        json!({"score": 0.05, "data_labels": ["public"]}),
    );
    let policy = RecordingPolicy::with_output(
        json!({
            "decision": "transform",
            "reason": "sanitized",
            "transform": {
                "path": "$policy_target.query",
                "value": "find [redacted]"
            }
        }),
        events.clone(),
    );
    let tool_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  pre_tool_call_policy:
    type: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $snap.tool_call.name
    policy:
      id: pre_tool_call_policy
    policy_target: $snap.tool_call.args
    annotations:
      tool_context:
        from: $tool.name
      actor_context:
        from: $pi.snapshot.actor.id
      classifier:
        from: $policy_target.query
tools:
  search:
    type: Tool
    id: search
    clearance:
    - public
    - customer_profile
    security_labels:
    - customer_profile
annotators:
  tool_context:
    type: classifier
  actor_context:
    type: classifier
  classifier:
    type: classifier"#,
        annotations.clone(),
        policy.clone(),
    );

    let result = tool_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::PreToolCall,
        snapshot: json!({
            "actor": {"type": "User", "id": "user-123"},
            "tool_call": {
                "id": "tool-call-1",
                "name": "search",
                "args": {"query": "find alice", "limit": 5}
            }
        }),
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(result.verdict.decision, Decision::Transform);
    assert_eq!(result.verdict.reason.as_deref(), Some("sanitized"));
    assert_eq!(
        result.transformed_policy_target.unwrap(),
        json!({"query": "find [redacted]", "limit": 5})
    );
    assert_eq!(
        events.lock().unwrap().clone(),
        vec![
            "annotations:actor_context".to_string(),
            "annotations:classifier".to_string(),
            "annotations:tool_context".to_string(),
            "policy".to_string(),
        ]
    );

    let annotation_calls = annotations.seen();
    assert_eq!(annotation_calls.len(), 3);
    assert_eq!(annotation_calls[0].annotator_name, "actor_context");
    let preliminary = &annotation_calls[0].preliminary_policy_input;
    assert_eq!(preliminary["intervention_point"], json!("pre_tool_call"));
    assert_eq!(
        preliminary["policy_target"]["value"]["query"],
        json!("find alice")
    );
    assert_eq!(preliminary["annotations"], json!({}));
    assert_eq!(preliminary["tool"]["name"], json!("search"));
    assert_eq!(
        preliminary["tool"]["clearance"],
        json!(["public", "customer_profile"])
    );

    let policy_calls = policy.seen();
    assert_eq!(policy_calls.len(), 1);
    let final_input = result.policy_input.as_ref().unwrap();
    assert_eq!(final_input, result.policy_input.as_ref().unwrap());
    assert_eq!(
        final_input["annotations"]["tool_context"],
        json!({"saw_tool": true})
    );
    assert_eq!(
        final_input["annotations"]["actor_context"],
        json!({"tier": "gold"})
    );
    assert_eq!(
        final_input["annotations"]["classifier"],
        json!({"score": 0.05, "data_labels": ["public"]})
    );
    assert_eq!(
        final_input["tool"]["security_labels"],
        json!(["customer_profile"])
    );
    assert_eq!(
        canonical_json(final_input).unwrap(),
        canonical_json(result.policy_input.as_ref().unwrap()).unwrap()
    );

    match &policy_calls[0].invocation {
        PreparedPolicyInvocation::Test(invocation) => {
            assert_eq!(invocation.input, *final_input);
        }
        other => panic!("expected Test invocation, got {other:?}"),
    }
}

#[test]
fn runtime_failures_normalize_to_deny_with_reserved_reasons() {
    let missing_path_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input"#,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::allow(no_events()),
    );
    let missing_path = missing_path_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({}),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(missing_path.verdict.decision, Decision::Deny);
    assert_eq!(
        missing_path.verdict.reason.as_deref(),
        Some("runtime_error:path_missing")
    );
    assert_eq!(
        missing_path.verdict.message.as_deref(),
        Some("Request blocked by Agent Control Specification.")
    );
    assert!(missing_path.policy_input.is_none());

    let events = no_events();
    let annotations = RecordingAnnotator::new(events.clone());
    annotations.set_error(
        "classifier",
        RuntimeError::AnnotationTimeout("slow".to_string()),
    );
    let policy = RecordingPolicy::allow(events.clone());
    let annotation_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
annotators:
  classifier:
    type: classifier"#,
        annotations,
        policy.clone(),
    );
    let timeout = annotation_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": "hello"}}),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(timeout.verdict.decision, Decision::Deny);
    assert_eq!(
        timeout.verdict.reason.as_deref(),
        Some("runtime_error:annotation_timeout")
    );
    assert!(policy.seen().is_empty());
    assert_eq!(timeout.policy_input.unwrap()["annotations"], json!({}));

    let policy_error_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input"#,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_error(
            RuntimeError::PolicyInvocationFailed("engine down".to_string()),
            no_events(),
        ),
    );
    let policy_error = policy_error_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": "hello"}),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(policy_error.verdict.decision, Decision::Deny);
    assert_eq!(
        policy_error.verdict.reason.as_deref(),
        Some("runtime_error:policy_invocation_failed")
    );

    for invalid_policy_output in [
        json!({"decision": "error"}),
        json!({"decision": "allow", "reason": "runtime_error:path_missing"}),
    ] {
        let invalid_runtime = runtime(
            r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input"#,
            RecordingAnnotator::new(no_events()),
            RecordingPolicy::with_output(invalid_policy_output, no_events()),
        );
        let result = invalid_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Input,
            snapshot: json!({"input": "hello"}),
            mode: EnforcementMode::Enforce,
        });
        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:policy_output_invalid")
        );
    }
}

#[test]
fn telemetry_sink_receives_structured_low_cardinality_events() {
    // AGT D1 migration: the warn-with-effects scenario is now a single
    // transform decision. Effects are no longer emitted on the verdict;
    // the runtime exposes the rewritten policy target through
    // `transformed_policy_target` and the dedicated Transformed event is
    // added by AGT D2 in a follow-up commit.
    let callback_events = no_events();
    let annotations = RecordingAnnotator::new(callback_events.clone());
    annotations.set_output("classifier", json!({"risk": "low"}));
    let policy = RecordingPolicy::with_output(
        json!({
            "decision": "transform",
            "reason": "sanitized",
            "transform": {"path": "$policy_target.text", "value": "safe"}
        }),
        callback_events,
    );
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
annotators:
  classifier:
    type: classifier"#,
    )
    .unwrap();
    let (telemetry, emitted) = RecordingTelemetry::new();
    let runtime = Runtime::with_telemetry(manifest, annotations, policy, telemetry).unwrap();

    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": "unsafe account 1234"}}),
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(result.verdict.decision, Decision::Transform);
    assert_eq!(
        result.transformed_policy_target,
        Some(json!({"text": "safe"}))
    );

    let events = emitted.lock().unwrap().clone();
    let event_types: Vec<_> = events.iter().map(|event| event.event_type).collect();
    // AGT D2: a transform decision emits both the base Decision event
    // and the dedicated InterventionPointTransformed event.
    assert_eq!(
        event_types,
        vec![
            TelemetryEventType::Decision,
            TelemetryEventType::InterventionPointTransformed
        ]
    );

    let decision_event = &events[0];
    assert_eq!(decision_event.decision, Some(Decision::Transform));
    assert_eq!(decision_event.reason_code.as_deref(), Some("sanitized"));
    assert_eq!(decision_event.policy_id.as_deref(), Some("test_policy"));
    assert_eq!(decision_event.annotators, vec!["classifier".to_string()]);
    assert_eq!(
        decision_event.enforcement_mode,
        Some(EnforcementMode::Enforce)
    );
    assert!(decision_event.duration_ms.unwrap() >= 0.0);

    let transformed_event = &events[1];
    assert_eq!(transformed_event.decision, Some(Decision::Transform));
    assert_eq!(transformed_event.reason_code.as_deref(), Some("sanitized"));
    assert_eq!(transformed_event.policy_id.as_deref(), Some("test_policy"));
    assert_eq!(
        transformed_event.enforcement_mode,
        Some(EnforcementMode::Enforce)
    );
    assert!(transformed_event.duration_ms.unwrap() >= 0.0);
    assert_eq!(transformed_event.action_identity, result.action_identity);
    assert!(transformed_event.error_class.is_none());

    for event in events {
        assert!(!event.metadata.contains_key("policy_target"));
        assert!(!event.metadata.contains_key("snapshot"));
        assert!(!event.metadata.contains_key("annotation_value"));
        assert!(!event.metadata.contains_key("tool_args"));
        assert!(!event.metadata.contains_key("tool_result"));
    }
}

#[test]
fn telemetry_decision_event_omits_raw_subject_data_by_default() {
    let raw_subject = "unsafe account 1234 secret token";
    let raw_annotation = "classifier saw unsafe account 1234 secret token";
    let raw_replacement = "redacted unsafe account 1234 secret token";
    let callback_events = no_events();
    let annotations = RecordingAnnotator::new(callback_events.clone());
    annotations.set_output("classifier", json!({"details": raw_annotation}));
    let policy = RecordingPolicy::with_output(
        json!({
            "decision": "deny",
            "reason": format!("blocked {raw_subject}"),
            "message": format!("would have replaced with: {raw_replacement}")
        }),
        callback_events,
    );
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
annotators:
  classifier:
    type: classifier"#,
    )
    .unwrap();
    let (telemetry, emitted) = RecordingTelemetry::new();
    let runtime = Runtime::with_telemetry(manifest, annotations, policy, telemetry).unwrap();

    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": raw_subject}}),
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(result.verdict.decision, Decision::Deny);
    let events = emitted.lock().unwrap().clone();
    let decision_event = events
        .iter()
        .find(|event| event.event_type == TelemetryEventType::Decision)
        .expect("decision event should be emitted");
    assert_eq!(decision_event.reason_code.as_deref(), Some("policy_reason"));
    assert!(decision_event.error_class.is_none());
    let debug = format!("{decision_event:?}");
    assert!(!debug.contains(raw_subject));
    assert!(!debug.contains(raw_annotation));
    assert!(!debug.contains(raw_replacement));
    assert!(!decision_event.metadata.contains_key("policy_target"));
    assert!(!decision_event.metadata.contains_key("snapshot"));
    assert!(!decision_event.metadata.contains_key("annotation_value"));
    assert!(!decision_event.metadata.contains_key("tool_args"));
    assert!(!decision_event.metadata.contains_key("tool_result"));
}

#[test]
fn perf_telemetry_gates_external_and_timing_events() {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
annotators:
  classifier:
    type: classifier"#,
    )
    .unwrap();

    let run = |perf_telemetry| {
        let callback_events = no_events();
        let annotations = RecordingAnnotator::new(callback_events.clone());
        annotations.set_output("classifier", json!({"risk": "low"}));
        let policy = RecordingPolicy::allow(callback_events);
        let (telemetry, emitted) = RecordingTelemetry::new();
        let runtime = Runtime::with_telemetry_and_perf(
            manifest.clone(),
            annotations,
            policy,
            telemetry,
            perf_telemetry,
        )
        .unwrap();
        let result = runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Input,
            snapshot: json!({"input": {"text": "hello"}}),
            mode: EnforcementMode::Enforce,
        });
        assert_eq!(result.verdict.decision, Decision::Allow);
        let events = emitted.lock().unwrap().clone();
        events
    };

    let off_types: Vec<_> = run(PerfTelemetry::Off)
        .iter()
        .map(|event| event.event_type)
        .collect();
    assert_eq!(off_types, vec![TelemetryEventType::Decision]);

    let external = run(PerfTelemetry::External);
    let external_types: Vec<_> = external.iter().map(|event| event.event_type).collect();
    assert_eq!(
        external_types,
        vec![
            TelemetryEventType::AnnotatorDispatch,
            TelemetryEventType::PolicyEvaluation,
            TelemetryEventType::Decision,
        ]
    );
    assert_eq!(external[0].annotators, vec!["classifier".to_string()]);
    assert_eq!(external[1].policy_id.as_deref(), Some("test_policy"));

    let full_types: Vec<_> = run(PerfTelemetry::Full)
        .iter()
        .map(|event| event.event_type)
        .collect();
    assert_eq!(
        full_types,
        vec![
            TelemetryEventType::AnnotatorDispatch,
            TelemetryEventType::PolicyEvaluation,
            TelemetryEventType::Decision,
            TelemetryEventType::EvaluationTiming,
        ]
    );
}

#[test]
fn telemetry_records_policy_failure_events() {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input"#,
    )
    .unwrap();
    let policy = RecordingPolicy::with_error(
        RuntimeError::PolicyInvocationFailed("engine down".to_string()),
        no_events(),
    );
    let (telemetry, emitted) = RecordingTelemetry::new();
    let runtime = Runtime::with_telemetry(
        manifest,
        RecordingAnnotator::new(no_events()),
        policy,
        telemetry,
    )
    .unwrap();

    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": "hello"}),
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:policy_invocation_failed")
    );

    let events = emitted.lock().unwrap().clone();
    let event_types: Vec<_> = events.iter().map(|event| event.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            TelemetryEventType::PolicyFailed,
            TelemetryEventType::Decision
        ]
    );
    let failed = &events[0];
    assert_eq!(failed.intervention_point, InterventionPoint::Input);
    assert_eq!(failed.policy_id.as_deref(), Some("test_policy"));
    assert_eq!(failed.metadata.get("policy_type").unwrap(), "test");
    assert_eq!(
        failed.reason_code.as_deref(),
        Some("runtime_error:policy_invocation_failed")
    );
    assert_eq!(failed.error_class.as_deref(), Some("runtime_error"));
    let decision = events
        .iter()
        .find(|event| event.event_type == TelemetryEventType::Decision)
        .expect("decision event");
    assert_eq!(decision.error_class.as_deref(), Some("runtime_error"));
    assert!(decision.action_identity.is_none());
}

#[test]
fn telemetry_records_annotation_failure_events() {
    let annotations = RecordingAnnotator::new(no_events());
    annotations.set_error(
        "classifier",
        RuntimeError::AnnotationFailed("down".to_string()),
    );
    let policy = RecordingPolicy::allow(no_events());
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $policy_target.text
annotators:
  classifier:
    type: classifier"#,
    )
    .unwrap();
    let (telemetry, emitted) = RecordingTelemetry::new();
    let runtime =
        Runtime::with_telemetry(manifest, annotations, policy.clone(), telemetry).unwrap();

    let result = runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Input,
        snapshot: json!({"input": {"text": "hello"}}),
        mode: EnforcementMode::Enforce,
    });

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );
    assert!(policy.seen().is_empty());

    let events = emitted.lock().unwrap().clone();
    let event_types: Vec<_> = events.iter().map(|event| event.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            TelemetryEventType::AnnotatorFailed,
            TelemetryEventType::Decision
        ]
    );
    let failed = &events[0];
    assert_eq!(failed.annotators, vec!["classifier".to_string()]);
    assert_eq!(
        failed.reason_code.as_deref(),
        Some("runtime_error:annotation_failed")
    );
    assert_eq!(failed.error_class.as_deref(), Some("runtime_error"));
}

#[test]
fn transform_applies_for_enforce_and_validates_in_evaluate_only() {
    // AGT D1 migration of the legacy multi-effect contract test. Effects are
    // sunset by `SPECIFICATION.md` §14; the only mutating decision
    // is `transform`, which carries a single replacement at one path. The
    // multi-step rewriting that this test originally covered now flows
    // through annotators per D1.3 (slated for M5). This test verifies the
    // transform decision honors enforce vs evaluate_only and that the
    // transform-invalid and transform-target-forbidden reasons surface on
    // the runtime path.
    let manifest_yaml = r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output"#;
    let snapshot = json!({
        "output": {
            "items": ["middle"],
            "note": "ok",
            "content": "héllo secret",
            "flag": false
        }
    });

    let transform_runtime = runtime(
        manifest_yaml,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_output(
            json!({
                "decision": "transform",
                "transform": {"path": "$policy_target.flag", "value": true}
            }),
            no_events(),
        ),
    );
    let transformed = transform_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Output,
        snapshot: snapshot.clone(),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(transformed.verdict.decision, Decision::Transform);
    assert_eq!(
        transformed.transformed_policy_target.unwrap(),
        json!({
            "items": ["middle"],
            "note": "ok",
            "content": "héllo secret",
            "flag": true
        })
    );

    let evaluate_only_runtime = runtime(
        manifest_yaml,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_output(
            json!({
                "decision": "transform",
                "transform": {"path": "$policy_target.flag", "value": true}
            }),
            no_events(),
        ),
    );
    let evaluate_only =
        evaluate_only_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Output,
            snapshot: snapshot.clone(),
            mode: EnforcementMode::EvaluateOnly,
        });
    assert_eq!(evaluate_only.verdict.decision, Decision::Transform);
    assert!(evaluate_only.transformed_policy_target.is_none());
    assert_eq!(
        evaluate_only.policy_input.unwrap()["policy_target"]["value"],
        snapshot["output"]
    );

    let deny_runtime = runtime(
        manifest_yaml,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_output(json!({"decision": "deny"}), no_events()),
    );
    let deny = deny_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Output,
        snapshot: snapshot.clone(),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(deny.verdict.decision, Decision::Deny);
    assert!(deny.transformed_policy_target.is_none());

    let escalate_runtime = runtime(
        manifest_yaml,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_output(json!({"decision": "escalate"}), no_events()),
    );
    let escalate = escalate_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::Output,
        snapshot: snapshot.clone(),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(escalate.verdict.decision, Decision::Escalate);
    assert!(escalate.transformed_policy_target.is_none());

    let invalid_transform_runtime = runtime(
        manifest_yaml,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_output(
            json!({
                "decision": "transform",
                "transform": {"path": "$policy_target.missing_field", "value": "x"}
            }),
            no_events(),
        ),
    );
    let invalid_transform =
        invalid_transform_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Output,
            snapshot: snapshot.clone(),
            mode: EnforcementMode::EvaluateOnly,
        });
    assert_eq!(invalid_transform.verdict.decision, Decision::Deny);
    assert_eq!(
        invalid_transform.verdict.reason.as_deref(),
        Some("runtime_error:transform_invalid")
    );

    let forbidden_target_runtime = runtime(
        manifest_yaml,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::with_output(
            json!({
                "decision": "transform",
                "transform": {"path": "$pi.policy_target.value.flag", "value": true}
            }),
            no_events(),
        ),
    );
    let forbidden_target =
        forbidden_target_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::Output,
            snapshot,
            mode: EnforcementMode::Enforce,
        });
    assert_eq!(forbidden_target.verdict.decision, Decision::Deny);
    assert_eq!(
        forbidden_target.verdict.reason.as_deref(),
        Some("runtime_error:transform_target_forbidden")
    );
}

#[test]
fn tool_metadata_projection_and_independent_tool_invocation_inputs_are_per_request() {
    let events = no_events();
    let annotations = RecordingAnnotator::new(events.clone());
    let policy = RecordingPolicy::allow(events);
    let tool_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args
tools:
  search:
    clearance:
    - public
    security_labels:
    - search_result
  transfer:
    clearance:
    - payments
    risk: high"#,
        annotations,
        policy.clone(),
    );

    for snapshot in [
        json!({"tool_call": {"id": "parallel-1", "name": "search", "args": {"q": "alice"}}}),
        json!({"tool_call": {"id": "parallel-2", "name": "transfer", "args": {"amount": 42}}}),
    ] {
        let result = tool_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::PreToolCall,
            snapshot,
            mode: EnforcementMode::Enforce,
        });
        assert_eq!(result.verdict.decision, Decision::Allow);
    }

    let calls = policy.seen();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].final_policy_input()["snapshot"]["tool_call"]["id"],
        json!("parallel-1")
    );
    assert_eq!(
        calls[0].final_policy_input()["policy_target"]["value"],
        json!({"q": "alice"})
    );
    assert_eq!(
        calls[0].final_policy_input()["tool"]["name"],
        json!("search")
    );
    assert_eq!(
        calls[0].final_policy_input()["tool"]["security_labels"],
        json!(["search_result"])
    );
    assert_eq!(
        calls[1].final_policy_input()["snapshot"]["tool_call"]["id"],
        json!("parallel-2")
    );
    assert_eq!(
        calls[1].final_policy_input()["policy_target"]["value"],
        json!({"amount": 42})
    );
    assert_eq!(
        calls[1].final_policy_input()["tool"]["name"],
        json!("transfer")
    );
    assert_eq!(calls[1].final_policy_input()["tool"]["risk"], json!("high"));

    let no_projection_policy = RecordingPolicy::allow(no_events());
    let no_projection_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args"#,
        RecordingAnnotator::new(no_events()),
        no_projection_policy.clone(),
    );
    let no_projection =
        no_projection_runtime.evaluate_intervention_point(InterventionPointRequest {
            intervention_point: InterventionPoint::PreToolCall,
            snapshot: json!({"tool_call": {"id": "call-no-tool", "name": "search", "args": {}}}),
            mode: EnforcementMode::Enforce,
        });
    assert_eq!(no_projection.verdict.decision, Decision::Allow);
    assert!(no_projection.policy_input.unwrap()["tool"].is_null());

    let unknown_tool_runtime = runtime(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  test_policy:
    type: test
intervention_points:
  pre_tool_call:
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args
tools:
  search:
    clearance:
    - public"#,
        RecordingAnnotator::new(no_events()),
        RecordingPolicy::allow(no_events()),
    );
    let unknown_tool = unknown_tool_runtime.evaluate_intervention_point(InterventionPointRequest {
        intervention_point: InterventionPoint::PreToolCall,
        snapshot: json!({"tool_call": {"name": "missing", "args": {}}}),
        mode: EnforcementMode::Enforce,
    });
    assert_eq!(unknown_tool.verdict.decision, Decision::Deny);
    assert_eq!(
        unknown_tool.verdict.reason.as_deref(),
        Some("runtime_error:tool_unknown")
    );
}
