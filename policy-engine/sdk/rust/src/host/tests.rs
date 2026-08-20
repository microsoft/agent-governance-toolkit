use super::*;
use crate::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, RuntimeError,
};
use serde_json::json;
use std::{
    collections::VecDeque,
    convert::Infallible,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

struct NoopAnnotator;

impl AnnotatorDispatcher for NoopAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(JsonValue::Null)
    }
}

#[derive(Default)]
struct QueuePolicy {
    responses: Mutex<VecDeque<JsonValue>>,
    seen: Mutex<Vec<JsonValue>>,
}

impl QueuePolicy {
    fn with_responses(responses: impl IntoIterator<Item = JsonValue>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<JsonValue> {
        self.seen.lock().unwrap().clone()
    }
}

impl PolicyDispatcher for QueuePolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        self.seen
            .lock()
            .unwrap()
            .push(invocation.policy_input().unwrap().clone());
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| json!({"decision": "allow"})))
    }
}

fn runtime(manifest_yaml: &str, policy: Arc<QueuePolicy>) -> Runtime {
    Runtime::new(
        Manifest::from_yaml_str(manifest_yaml).unwrap(),
        Arc::new(NoopAnnotator),
        policy,
    )
    .unwrap()
}

fn run_manifest() -> &'static str {
    r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
  output:
    policy_target_kind: assistant_output
    policy:
      id: test_policy
    policy_target: $snap.output"#
}

#[test]
fn policy_labels_expose_policy_ids_and_sorted_annotators() {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
annotators:
  zeta:
    type: classifier
  alpha:
    type: classifier
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      zeta:
        from: $target
      alpha:
        from: $target"#,
    )
    .unwrap();

    assert_eq!(
        policy_labels(&manifest),
        json!({
            "input": {
                "policy_id": "test_policy",
                "annotators": ["alpha", "zeta"],
            }
        })
    );
}

#[test]
fn manifest_from_url_rejects_non_https_before_fetch() {
    let error = manifest_from_url(
        "http://policy.example/manifest.yaml",
        None,
        Limits::default(),
    )
    .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(error.detail().contains("unsupported URL scheme"));
}

#[cfg(not(feature = "bundled-dispatchers"))]
#[test]
fn default_annotator_dispatcher_requires_opt_in_when_manifest_declares_annotators() {
    let manifest = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
annotators:
  classifier:
    type: classifier
intervention_points:
  input:
    policy:
      id: test_policy
    policy_target: $snap.input
    annotations:
      classifier:
        from: $target"#,
    )
    .unwrap();

    let error = match default_host_annotator_dispatcher(&manifest) {
        Ok(_) => panic!("annotator dispatcher should require explicit opt-in"),
        Err(error) => error,
    };
    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(error
        .detail()
        .contains("bundled dispatchers are not enabled"));
}

#[test]
fn from_path_zero_config_evaluates_rego_manifest() {
    let manifest_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/ifc_agent/manifest.yaml");
    let control = AgentControl::from_path(manifest_path).unwrap();

    let result = control.evaluate_intervention_point(
        InterceptionPoint::PreToolCall,
        json!({
            "tool_call": { "name": "trusted_archive", "args": { "body": "record" } },
            "ifc": { "source_labels": ["confidential"] }
        }),
        EnforcementMode::Enforce,
    );

    assert_eq!(result.verdict.decision, Decision::Allow);
    assert!(result.policy_input.is_some());
}

#[test]
fn from_manifest_with_dispatchers_and_limits_builds_and_evaluates() {
    // The limits-threading constructor is reachable with a non-default value and
    // builds a working runtime; a host policy still overrides the default
    // dispatcher, so the limits path does not change verdict behavior here.
    let limits = crate::Limits {
        max_manifest_url_bytes: 2048,
        manifest_url_timeout_ms: 5000,
        max_manifest_url_redirects: 1,
        ..crate::Limits::default()
    };
    let policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "deny",
        "reason": "host_policy"
    })]));
    let control = AgentControl::from_manifest_with_dispatchers_and_limits(
        Manifest::from_yaml_str(run_manifest()).unwrap(),
        Some(Arc::new(NoopAnnotator)),
        Some(policy.clone()),
        limits,
    )
    .unwrap();

    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({ "input": { "text": "blocked" } }),
        EnforcementMode::Enforce,
    );

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(result.verdict.reason.as_deref(), Some("host_policy"));
}

#[test]
fn from_manifest_with_dispatchers_prefers_host_policy() {
    let policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "deny",
        "reason": "host_policy"
    })]));
    let control = AgentControl::from_manifest_with_dispatchers(
        Manifest::from_yaml_str(run_manifest()).unwrap(),
        Some(Arc::new(NoopAnnotator)),
        Some(policy.clone()),
    )
    .unwrap();

    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({ "input": { "text": "blocked" } }),
        EnforcementMode::Enforce,
    );

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(result.verdict.reason.as_deref(), Some("host_policy"));
    assert_eq!(policy.seen().len(), 1);
}

fn tool_manifest(policy_target: &str) -> String {
    format!(
        r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: {policy_target}
  post_tool_call:
    policy_target_kind: tool_result
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_result
tools:
  search:
    clearance: public"#
    )
}

#[test]
#[should_panic(expected = "tool_call_id must be a non-empty string when provided")]
fn tool_run_options_reject_empty_tool_call_id() {
    let _ = ToolRunOptions::new().with_tool_call_id("");
}

fn model_manifest(pre_target: &str, post_target: &str) -> String {
    format!(
        r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
intervention_points:
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: test_policy
    policy_target: {pre_target}
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: test_policy
    policy_target: {post_target}"#
    )
}

#[test]
fn run_allows_and_blocks_input_denial_before_execute() {
    let allow_policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "allow"}),
        json!({"decision": "allow"}),
    ]));
    let control = AgentControl::new(runtime(run_manifest(), allow_policy));
    let result = control
        .run(json!({"text": "hello"}), |input| json!({"echo": input}))
        .unwrap();
    assert_eq!(result.value, json!({"echo": {"text": "hello"}}));
    assert_eq!(
        result.input_intervention_point_result.verdict.decision,
        Decision::Allow
    );
    assert_eq!(
        result.output_intervention_point_result.verdict.decision,
        Decision::Allow
    );

    let deny_policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "deny",
        "reason": "blocked_input"
    })]));
    let control = AgentControl::new(runtime(run_manifest(), deny_policy.clone()));
    let executed = Arc::new(Mutex::new(false));
    let executed_for_closure = executed.clone();
    let blocked = control
        .run(json!({"text": "stop"}), move |_| {
            *executed_for_closure.lock().unwrap() = true;
            json!({"should_not": "run"})
        })
        .unwrap_err();

    assert_eq!(blocked.intervention_point(), InterceptionPoint::Input);
    assert_eq!(
        blocked.intervention_point_result().verdict.decision,
        Decision::Deny
    );
    assert_eq!(
        blocked
            .intervention_point_result()
            .verdict
            .reason
            .as_deref(),
        Some("blocked_input")
    );
    assert!(!*executed.lock().unwrap());
    assert_eq!(deny_policy.seen().len(), 1);
}

#[test]
fn run_uses_transformed_input_and_output_in_enforce_mode() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({
            "decision": "transform", "transform": {"path": "$target.text", "value": "sanitized"}
        }),
        json!({
            "decision": "transform", "transform": {"path": "$target.text", "value": "final"}
        }),
    ]));
    let control = AgentControl::new(runtime(run_manifest(), policy));
    let executed_with = Arc::new(Mutex::new(JsonValue::Null));
    let executed_with_for_closure = executed_with.clone();

    let result = control
        .run(json!({"text": "unsafe"}), move |input| {
            *executed_with_for_closure.lock().unwrap() = input.clone();
            json!({"text": format!("echo {}", input["text"].as_str().unwrap())})
        })
        .unwrap();

    assert_eq!(*executed_with.lock().unwrap(), json!({"text": "sanitized"}));
    assert_eq!(result.value, json!({"text": "final"}));
    let output_policy_input = result
        .output_intervention_point_result
        .policy_input
        .as_ref()
        .unwrap();
    assert_eq!(
        output_policy_input["snapshot"]["input"],
        json!({"text": "sanitized"})
    );
    assert_eq!(
        output_policy_input["snapshot"]["output"],
        json!({"text": "echo sanitized"})
    );
}

#[test]
fn evaluate_only_does_not_block_or_apply_transforms() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({
            "decision": "transform", "transform": {"path": "$target.text", "value": "changed"}
        }),
        json!({"decision": "deny", "reason": "observed_only"}),
    ]));
    let control = AgentControl::new(runtime(run_manifest(), policy));
    let executed_with = Arc::new(Mutex::new(JsonValue::Null));
    let executed_with_for_closure = executed_with.clone();

    let result = control
        .run_with_options(
            json!({"text": "original"}),
            RunOptions::evaluate_only(),
            move |input| {
                *executed_with_for_closure.lock().unwrap() = input;
                json!({"text": "raw output"})
            },
        )
        .unwrap();

    assert_eq!(*executed_with.lock().unwrap(), json!({"text": "original"}));
    assert_eq!(result.value, json!({"text": "raw output"}));
    assert_eq!(
        result
            .input_intervention_point_result
            .transformed_policy_target,
        None
    );
    assert_eq!(
        result.output_intervention_point_result.verdict.decision,
        Decision::Deny
    );
}

#[test]
fn try_run_preserves_execute_errors() {
    #[derive(Debug, Clone, PartialEq)]
    struct HostError(&'static str);

    let policy = Arc::new(QueuePolicy::with_responses([json!({"decision": "allow"})]));
    let control = AgentControl::new(runtime(run_manifest(), policy));
    let error = control
        .try_run(json!({"text": "hello"}), |_input| {
            Err::<JsonValue, _>(HostError("boom"))
        })
        .unwrap_err();

    assert_eq!(error, AgentControlError::Execute(HostError("boom")));
}

#[test]
fn protected_tool_enforces_pre_and_post_with_stored_execute_repeatedly() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({
            "decision": "transform", "transform": {"path": "$target.query", "value": "safe"}
        }),
        json!({
            "decision": "transform", "transform": {"path": "$target.answer", "value": "redacted"}
        }),
    ]));
    let control = AgentControl::new(runtime(&tool_manifest("$snap.tool_call.args"), policy));
    let executed_with = Arc::new(Mutex::new(Vec::new()));
    let executed_with_for_closure = executed_with.clone();
    let protected = control.protect_tool("search", move |args| {
        executed_with_for_closure.lock().unwrap().push(args.clone());
        json!({"answer": format!("result for {}", args["query"].as_str().unwrap())})
    });

    let result = protected
        .run_with_options(
            json!({"query": "unsafe"}),
            ToolRunOptions::new().with_tool_call_id("call-1"),
        )
        .unwrap();
    let repeated_result = protected.run(json!({"query": "again"})).unwrap();

    assert_eq!(protected.name(), "search");
    assert_eq!(
        *executed_with.lock().unwrap(),
        vec![json!({"query": "safe"}), json!({"query": "again"})]
    );
    assert_eq!(result.value, json!({"answer": "redacted"}));
    assert_eq!(repeated_result.value, json!({"answer": "result for again"}));
    assert_eq!(
        result
            .post_tool_call_intervention_point_result
            .policy_input
            .as_ref()
            .unwrap()["snapshot"]["tool_call"],
        json!({"name": "search", "args": {"query": "safe"}, "id": "call-1"})
    );
    assert_eq!(
        result
            .post_tool_call_intervention_point_result
            .policy_input
            .as_ref()
            .unwrap()["snapshot"]["tool_result"],
        json!({"answer": "result for safe"})
    );
}

#[test]
fn run_model_allows_and_emits_model_snapshots() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "allow"}),
        json!({"decision": "allow"}),
    ]));
    let control = AgentControl::new(runtime(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    ));
    let mut ambient = serde_json::Map::new();
    ambient.insert("conversation".to_string(), json!({"id": "conv-1"}));

    let result = control
        .run_model_with_options(
            json!({"prompt": "hello"}),
            RunOptions::new().with_ambient_snapshot(ambient),
            |request| json!({"text": format!("echo {}", request["prompt"].as_str().unwrap())}),
        )
        .unwrap();

    assert_eq!(result.value, json!({"text": "echo hello"}));
    let post_snapshot = &result
        .post_model_call_intervention_point_result
        .policy_input
        .as_ref()
        .unwrap()["snapshot"];
    assert_eq!(post_snapshot["conversation"], json!({"id": "conv-1"}));
    assert_eq!(post_snapshot["model_request"], json!({"prompt": "hello"}));
    assert_eq!(
        post_snapshot["model_response"],
        json!({"text": "echo hello"})
    );
}

#[test]
fn run_model_uses_pre_transform_for_execute_and_post_snapshot() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({
            "decision": "transform", "transform": {"path": "$target.prompt", "value": "safe"}
        }),
        json!({"decision": "allow"}),
    ]));
    let control = AgentControl::new(runtime(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    ));
    let executed_with = Arc::new(Mutex::new(JsonValue::Null));
    let executed_with_for_closure = executed_with.clone();

    let result = control
        .run_model(json!({"prompt": "unsafe"}), move |request| {
            *executed_with_for_closure.lock().unwrap() = request.clone();
            json!({"text": request["prompt"].as_str().unwrap()})
        })
        .unwrap();

    assert_eq!(*executed_with.lock().unwrap(), json!({"prompt": "safe"}));
    assert_eq!(
        result
            .post_model_call_intervention_point_result
            .policy_input
            .as_ref()
            .unwrap()["snapshot"]["model_request"],
        json!({"prompt": "safe"})
    );
}

#[test]
fn run_model_uses_post_transform_for_returned_value() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "allow"}),
        json!({
            "decision": "transform", "transform": {"path": "$target.text", "value": "redacted"}
        }),
    ]));
    let control = AgentControl::new(runtime(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    ));

    let result = control
        .run_model(json!({"prompt": "hello"}), |_| json!({"text": "raw"}))
        .unwrap();

    assert_eq!(result.value, json!({"text": "redacted"}));
}

#[test]
fn run_model_blocks_pre_denial_before_execute() {
    let policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "deny",
        "reason": "blocked_request"
    })]));
    let control = AgentControl::new(runtime(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy.clone(),
    ));
    let executed = Arc::new(Mutex::new(false));
    let executed_for_closure = executed.clone();

    let blocked = control
        .run_model(json!({"prompt": "stop"}), move |_| {
            *executed_for_closure.lock().unwrap() = true;
            json!({"should_not": "run"})
        })
        .unwrap_err();

    assert_eq!(
        blocked.intervention_point(),
        InterceptionPoint::PreModelCall
    );
    assert_eq!(
        blocked.intervention_point_result().verdict.decision,
        Decision::Deny
    );
    assert!(!*executed.lock().unwrap());
    assert_eq!(policy.seen().len(), 1);
}

#[test]
fn run_model_blocks_post_denial() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "allow"}),
        json!({"decision": "deny", "reason": "blocked_response"}),
    ]));
    let control = AgentControl::new(runtime(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    ));

    let blocked = control
        .run_model(json!({"prompt": "hello"}), |_| json!({"text": "raw"}))
        .unwrap_err();

    assert_eq!(
        blocked.intervention_point(),
        InterceptionPoint::PostModelCall
    );
    assert_eq!(
        blocked.intervention_point_result().verdict.decision,
        Decision::Deny
    );
}

#[test]
fn malformed_tool_args_fail_closed_before_execute() {
    let policy = Arc::new(QueuePolicy::default());
    let control = AgentControl::new(runtime(
        &tool_manifest("$snap.tool_call.args.payload.query"),
        policy.clone(),
    ));
    let executed = Arc::new(Mutex::new(false));
    let executed_for_closure = executed.clone();

    let blocked = control
        .run_tool("search", json!({"payload": "not an object"}), move |_| {
            *executed_for_closure.lock().unwrap() = true;
            json!({"should_not": "run"})
        })
        .unwrap_err();

    assert_eq!(blocked.intervention_point(), InterceptionPoint::PreToolCall);
    assert_eq!(
        blocked.intervention_point_result().verdict.decision,
        Decision::Deny
    );
    assert_eq!(
        blocked
            .intervention_point_result()
            .verdict
            .reason
            .as_deref(),
        Some("runtime_error:path_type_mismatch")
    );
    assert!(!*executed.lock().unwrap());
    assert!(policy.seen().is_empty());
}

#[test]
fn lifecycle_intervention_point_names_are_current_and_aliases_are_rejected() {
    for intervention_point in ["agent_startup", "output", "agent_shutdown"] {
        assert_eq!(
            InterceptionPoint::from_str(intervention_point)
                .unwrap()
                .as_str(),
            intervention_point
        );
    }
    for alias in ["startup", "shutdown", "final_output", "state", "endpoint"] {
        assert!(
            InterceptionPoint::from_str(alias).is_err(),
            "{alias} should be rejected"
        );
    }
}

#[test]
fn rig_like_tool_wrapper_guards_tool_without_rig_dependency() {
    #[derive(Clone)]
    struct SearchTool {
        seen: Arc<Mutex<Vec<JsonValue>>>,
    }

    impl RigLikeTool for SearchTool {
        type Error = Infallible;

        fn name(&self) -> &str {
            "search"
        }

        fn call(&self, args: JsonValue) -> Result<JsonValue, Self::Error> {
            self.seen.lock().unwrap().push(args.clone());
            Ok(json!({"answer": format!("result for {}", args["query"].as_str().unwrap())}))
        }
    }

    let policy = Arc::new(QueuePolicy::with_responses([
        json!({
            "decision": "transform", "transform": {"path": "$target.query", "value": "safe"}
        }),
        json!({
            "decision": "transform", "transform": {"path": "$target.answer", "value": "redacted"}
        }),
    ]));
    let control = AgentControl::new(runtime(&tool_manifest("$snap.tool_call.args"), policy));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control.guard_rig_like_tool_with_options(
        SearchTool { seen: seen.clone() },
        ToolRunOptions::new().with_tool_call_id("rig-call-1"),
    );

    let value = guarded.call(json!({"query": "raw"})).unwrap();

    assert_eq!(guarded.name(), "search");
    assert_eq!(value, json!({"answer": "redacted"}));
    assert_eq!(*seen.lock().unwrap(), vec![json!({"query": "safe"})]);
}

#[test]
fn rig_framework_adapter_is_explicitly_deferred() {
    let error = create_unsupported_framework_adapter("rig").unwrap_err();
    assert_eq!(error.framework(), "rig");
    assert!(error.message().contains("intentionally deferred"));
    assert!(error.message().contains("run_tool/protect_tool"));
}

fn allow_resolver() -> ApprovalResolver {
    Arc::new(|_, result| ApprovalResolution::allow(result.action_identity.clone().unwrap()))
}

fn deny_resolver() -> ApprovalResolver {
    Arc::new(|_, _| ApprovalResolution::deny())
}

#[test]
fn escalate_without_resolver_fails_closed() {
    let policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "escalate",
        "reason": "needs_approval"
    })]));
    let control = AgentControl::new(runtime(run_manifest(), policy));
    let executed = Arc::new(Mutex::new(false));
    let executed_for_closure = executed.clone();

    let interruption = control
        .run(json!({"text": "x"}), move |_| {
            *executed_for_closure.lock().unwrap() = true;
            json!({})
        })
        .unwrap_err();

    assert!(matches!(interruption, AgentControlInterruption::Blocked(_)));
    assert_eq!(interruption.intervention_point(), InterceptionPoint::Input);
    assert!(!*executed.lock().unwrap());
}

#[test]
fn escalate_after_approval_proceeds_with_original_input() {
    // AGT D1 + spec §13.1: escalate carries no effects. The host
    // approval path either allows the action (it proceeds with the
    // original policy target) or denies it. There is no "approval
    // applies a deferred transform" path.
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate", "reason": "needs_approval"}),
        json!({"decision": "allow"}),
    ]));
    let control =
        AgentControl::new(runtime(run_manifest(), policy)).with_approval_resolver(allow_resolver());
    let executed_with = Arc::new(Mutex::new(JsonValue::Null));
    let executed_with_for_closure = executed_with.clone();

    let result = control
        .run(json!({"text": "original"}), move |input| {
            *executed_with_for_closure.lock().unwrap() = input;
            json!({"answer": "ok"})
        })
        .unwrap();

    // Per §13.1 escalate applies NO effects; the action executes with
    // the original policy target value, not a transformed one.
    assert_eq!(*executed_with.lock().unwrap(), json!({"text": "original"}));
    assert_eq!(result.value, json!({"answer": "ok"}));
}

#[test]
fn escalate_approval_receives_and_matches_action_identity() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate"}),
    ]));
    let control = AgentControl::new(runtime(run_manifest(), policy));
    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "x"}}),
        EnforcementMode::Enforce,
    );
    let expected = identity(result.policy_input.as_ref().unwrap()).unwrap();
    let resolver: ApprovalResolver = Arc::new(move |_, result| {
        assert_eq!(result.action_identity.as_deref(), Some(expected.as_str()));
        ApprovalResolution::allow(expected.clone())
    });

    control
        .enforce(
            InterceptionPoint::Input,
            &result,
            EnforcementMode::Enforce,
            Some(&resolver),
        )
        .unwrap();
}

#[test]
fn escalate_approval_action_mismatch_fails_closed() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate"}),
    ]));
    let control = AgentControl::new(runtime(run_manifest(), policy));
    let mut result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "x"}}),
        EnforcementMode::Enforce,
    );
    let approved = result.action_identity.clone().unwrap();
    if let Some(policy_input) = result.policy_input.as_mut() {
        policy_input["snapshot"]["input"]["text"] = json!("mutated");
    }
    let resolver: ApprovalResolver =
        Arc::new(move |_, _| ApprovalResolution::allow(approved.clone()));

    let interruption = control
        .enforce(
            InterceptionPoint::Input,
            &result,
            EnforcementMode::Enforce,
            Some(&resolver),
        )
        .unwrap_err();

    assert_eq!(
        interruption
            .intervention_point_result()
            .verdict
            .reason
            .as_deref(),
        Some("host_error:approval_identity_mismatch")
    );
}

#[test]
fn escalate_deny_blocks() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate"}),
    ]));
    let control =
        AgentControl::new(runtime(run_manifest(), policy)).with_approval_resolver(deny_resolver());

    let interruption = control.run(json!({"text": "x"}), |v| v).unwrap_err();
    assert!(matches!(interruption, AgentControlInterruption::Blocked(_)));
}

#[test]
fn escalate_suspend_raises_suspended_with_handle() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate"}),
    ]));
    let resolver: ApprovalResolver = Arc::new(|_, result| {
        ApprovalResolution::suspend(
            Some(json!({"ticket": "abc"})),
            result.action_identity.clone().unwrap(),
        )
    });
    let control =
        AgentControl::new(runtime(run_manifest(), policy)).with_approval_resolver(resolver);

    let interruption = control.run(json!({"text": "x"}), |v| v).unwrap_err();
    match interruption {
        AgentControlInterruption::Suspended(suspended) => {
            assert_eq!(suspended.intervention_point, InterceptionPoint::Input);
            assert_eq!(suspended.handle, Some(json!({"ticket": "abc"})));
        }
        other => panic!("expected suspended, got {other:?}"),
    }
}

#[test]
fn deny_does_not_consult_resolver() {
    let policy = Arc::new(QueuePolicy::with_responses([json!({"decision": "deny"})]));
    let consulted = Arc::new(Mutex::new(false));
    let consulted_for_closure = consulted.clone();
    let resolver: ApprovalResolver = Arc::new(move |_, result| {
        *consulted_for_closure.lock().unwrap() = true;
        ApprovalResolution::allow(result.action_identity.clone().unwrap())
    });
    let control =
        AgentControl::new(runtime(run_manifest(), policy)).with_approval_resolver(resolver);

    let interruption = control.run(json!({"text": "x"}), |v| v).unwrap_err();
    assert!(matches!(interruption, AgentControlInterruption::Blocked(_)));
    assert!(!*consulted.lock().unwrap());
}

#[test]
fn per_call_resolver_overrides_instance_resolver() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate"}),
        json!({"decision": "allow"}),
    ]));
    let control =
        AgentControl::new(runtime(run_manifest(), policy)).with_approval_resolver(deny_resolver());

    let result = control
        .run_with_options(
            json!({"text": "x"}),
            RunOptions::new().with_approval_resolver(allow_resolver()),
            |_| json!({"answer": "ok"}),
        )
        .unwrap();

    assert_eq!(result.value, json!({"answer": "ok"}));
}

#[test]
fn evaluate_only_does_not_consult_resolver() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate"}),
        json!({"decision": "escalate"}),
    ]));
    let consulted = Arc::new(Mutex::new(false));
    let consulted_for_closure = consulted.clone();
    let resolver: ApprovalResolver = Arc::new(move |_, result| {
        *consulted_for_closure.lock().unwrap() = true;
        ApprovalResolution::allow(result.action_identity.clone().unwrap())
    });
    let control =
        AgentControl::new(runtime(run_manifest(), policy)).with_approval_resolver(resolver);

    let result = control
        .run_with_options(
            json!({"text": "x"}),
            RunOptions::evaluate_only(),
            |_| json!({"answer": "ok"}),
        )
        .unwrap();

    assert_eq!(result.value, json!({"answer": "ok"}));
    assert!(!*consulted.lock().unwrap());
}

#[test]
fn post_tool_escalate_runs_tool_but_blocks_result() {
    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "allow"}),
        json!({"decision": "escalate"}),
    ]));
    let control = AgentControl::new(runtime(&tool_manifest("$snap.tool_call.args"), policy));
    let executed = Arc::new(Mutex::new(false));
    let executed_for_closure = executed.clone();

    let interruption = control
        .run_tool_with_options(
            "search",
            json!({"query": "x"}),
            ToolRunOptions::new().with_tool_call_id("call-1"),
            move |args| {
                *executed_for_closure.lock().unwrap() = true;
                args
            },
        )
        .unwrap_err();

    assert!(matches!(interruption, AgentControlInterruption::Blocked(_)));
    assert_eq!(
        interruption.intervention_point(),
        InterceptionPoint::PostToolCall
    );
    assert!(*executed.lock().unwrap());
}

#[test]
fn with_telemetry_emits_one_decision_event_per_evaluation() {
    use agent_control_specification_core::InMemoryTelemetrySink;

    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "deny", "reason": "blocked"}),
    ]));
    let sink = Arc::new(InMemoryTelemetrySink::new());
    let control = AgentControl::from_manifest_with_dispatchers(
        Manifest::from_yaml_str(run_manifest()).unwrap(),
        Some(Arc::new(NoopAnnotator)),
        Some(policy),
    )
    .unwrap()
    .with_telemetry(sink.clone());

    let result = control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "hi"}}),
        EnforcementMode::Enforce,
    );

    assert_eq!(result.verdict.decision, Decision::Deny);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, Some(Decision::Deny));
    assert_eq!(events[0].intervention_point, InterceptionPoint::Input);
    // The manifest binds policy "test_policy" on input; the core sources it.
    assert_eq!(events[0].policy_id.as_deref(), Some("test_policy"));
    // Free-text reason is reduced to a safe code by the core redaction helper.
    assert_eq!(events[0].reason_code.as_deref(), Some("blocked"));
}

#[test]
fn manifest_from_url_blocks_ssrf_targets() {
    // Every form the pre-retarget engine blocked, including the dual-stack
    // bypasses that motivated the IPv4 canonicalization.
    for url in [
        "https://127.0.0.1/m.yaml",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/m.yaml",
        "https://[::ffff:169.254.169.254]/m.yaml",
        "https://[::ffff:127.0.0.1]/m.yaml",
        "https://0.0.0.0/m.yaml",
        "https://255.255.255.255/m.yaml",
        "https://user:pw@127.0.0.1:8443/m.yaml",
    ] {
        let error = crate::manifest_from_url(url, None, crate::Limits::default())
            .expect_err(&format!("{url} must be refused"));
        assert!(
            error.to_string().contains("loopback or link-local"),
            "{url} gave {error}"
        );
    }

    // RFC1918 stays allowed so internal policy hosting keeps working: this
    // one fails at the fetch, not at the guard.
    let error = crate::manifest_from_url("https://10.0.0.5/m.yaml", None, crate::Limits::default())
        .expect_err("unreachable host still errors");
    assert!(
        !error.to_string().contains("loopback or link-local"),
        "RFC1918 must not be blocked by the guard: {error}"
    );
}
