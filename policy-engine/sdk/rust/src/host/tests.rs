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

fn build_control(manifest_yaml: &str, policy: Arc<QueuePolicy>) -> AgentControl {
    AgentControl::from_manifest_with_dispatchers(
        Manifest::from_yaml_str(manifest_yaml).unwrap(),
        Some(Arc::new(NoopAnnotator)),
        Some(policy),
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
fn oversized_transformed_snapshot_is_blocked_before_execution() {
    let policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "transform",
        "transform": {"path": "$target", "value": "b".repeat(100)}
    })]));
    let control = AgentControl::from_manifest_with_dispatchers_and_limits(
        Manifest::from_yaml_str(run_manifest()).unwrap(),
        Some(Arc::new(NoopAnnotator)),
        Some(policy),
        crate::Limits {
            max_snapshot_bytes: 256,
            ..crate::Limits::default()
        },
    )
    .unwrap();
    let mut executed = false;
    let error = control
        .run_with_options(
            json!("x"),
            RunOptions::default().with_ambient_snapshot(
                json!({"ambient": "a".repeat(180)})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            |input| {
                executed = true;
                input
            },
        )
        .unwrap_err();
    assert!(!executed);
    let AgentControlInterruption::Blocked(blocked) = error else {
        panic!("oversized transforms must not be liftable");
    };
    assert_eq!(
        blocked.intervention_point_result.verdict.reason.as_deref(),
        Some("host_error:transform_invalid"),
    );
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
    let control = build_control(run_manifest(), allow_policy);
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
    let control = build_control(run_manifest(), deny_policy.clone());
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
    let control = build_control(run_manifest(), policy);
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
    let control = build_control(run_manifest(), policy);
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
    let control = build_control(run_manifest(), policy);
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
    let control = build_control(&tool_manifest("$snap.tool_call.args"), policy);
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
    let control = build_control(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    );
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
    let control = build_control(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    );
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
    let control = build_control(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    );

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
    let control = build_control(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy.clone(),
    );
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
    let control = build_control(
        &model_manifest("$snap.model_request", "$snap.model_response"),
        policy,
    );

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
    let control = build_control(
        &tool_manifest("$snap.tool_call.args.payload.query"),
        policy.clone(),
    );
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
    let control = build_control(&tool_manifest("$snap.tool_call.args"), policy);
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
    let control = build_control(run_manifest(), policy);
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
    let control = build_control(run_manifest(), policy).with_approval_resolver(allow_resolver());
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
    let control = build_control(run_manifest(), policy);
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
    let control = build_control(run_manifest(), policy);
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
    let control = build_control(run_manifest(), policy).with_approval_resolver(deny_resolver());

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
    let control = build_control(run_manifest(), policy).with_approval_resolver(resolver);

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
    let control = build_control(run_manifest(), policy).with_approval_resolver(resolver);

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
    let control = build_control(run_manifest(), policy).with_approval_resolver(deny_resolver());

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
    let control = build_control(run_manifest(), policy).with_approval_resolver(resolver);

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
    let control = build_control(&tool_manifest("$snap.tool_call.args"), policy);
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
fn with_telemetry_emits_one_decision_event_per_evaluation() -> Result<(), RuntimeError> {
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
    .with_telemetry(sink.clone())?;

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
    Ok(())
}

#[test]
fn manifest_from_url_blocks_ssrf_targets() {
    // Canonical forms, the dual-stack bypasses that motivated the IPv4
    // canonicalization, and every non-canonical literal the review probe
    // showed walking past the hand-split guard: the `url` crate turns each
    // of them into 127.0.0.1 or 169.254.169.254 before the fetcher connects.
    for url in [
        // Canonical loopback, link-local, unspecified, broadcast.
        "https://127.0.0.1/m.yaml",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/m.yaml",
        "https://[::ffff:169.254.169.254]/m.yaml",
        "https://[::ffff:127.0.0.1]/m.yaml",
        "https://[::ffff:7f00:1]/m.yaml",
        "https://[::127.0.0.1]/m.yaml",
        "https://[64:ff9b::7f00:1]/m.yaml",
        "https://[fe80::1]/m.yaml",
        "https://0.0.0.0/m.yaml",
        "https://0.0.0.1/m.yaml",
        "https://255.255.255.255/m.yaml",
        "https://user:pw@127.0.0.1:8443/m.yaml",
        // Non-canonical IPv4 literals from the probe.
        "https://127.1/m.yaml",
        "https://127.0.1/m.yaml",
        "https://2130706433/m.yaml",
        "https://0x7f000001/m.yaml",
        "https://0x7f.0.0.1/m.yaml",
        "https://0177.0.0.1/m.yaml",
        "https://0177.0000.0000.0001/m.yaml",
        "https://2852039166/m.yaml",
        "https://0xA9FEA9FE/m.yaml",
        "https://0xa9.0xfe.0xa9.0xfe/m.yaml",
        "https://0251.0376.0251.0376/m.yaml",
        "https://169.254.43518/m.yaml",
        "https://127.0.0.1./m.yaml",
        "https://127.0.0\t.1/m.yaml",
        "https://127.0.0.\n1/m.yaml",
        "https://127.1:8443/m.yaml",
        // Private, shared address space and unique-local ranges.
        "https://10.0.0.5/m.yaml",
        "https://172.16.0.1/m.yaml",
        "https://172.31.255.254/m.yaml",
        "https://192.168.1.1/m.yaml",
        "https://100.100.100.200/m.yaml",
        "https://100.64.0.1/m.yaml",
        "https://[fd00:ec2::254]/m.yaml",
        "https://[fc00::1]/m.yaml",
        "https://[fec0::1]/m.yaml",
        "https://[::ffff:10.0.0.5]/m.yaml",
        "https://[::ffff:c0a8:101]/m.yaml",
        // Loopback and link-local names.
        "https://localhost/m.yaml",
        "https://LOCALHOST/m.yaml",
        "https://localhost./m.yaml",
        "https://localhost:8443/m.yaml",
        "https://api.localhost/m.yaml",
        "https://printer.local/m.yaml",
        "https://a.b.local./m.yaml",
    ] {
        let error = crate::manifest_from_url(url, None, crate::Limits::default())
            .expect_err(&format!("{url:?} must be refused"));
        assert_eq!(
            error.reason(),
            "runtime_error:manifest_invalid",
            "{url:?} gave {error}"
        );
        assert!(
            error.to_string().contains("blocked destination"),
            "{url:?} gave {error}"
        );
    }

    // A malformed URL fails closed at the guard rather than reaching the
    // fetcher.
    for url in [
        "https://",
        "https://[::1/m.yaml",
        "https://loop back.invalid/m.yaml",
        "not a url",
    ] {
        let error = super::reject_blocked_fetch_host(url).expect_err(url);
        assert_eq!(error.reason(), "runtime_error:manifest_invalid", "{url}");
    }

    // Public destinations pass the guard. Checked on the guard directly so the
    // test does not open a connection; TEST-NET-3 (RFC 5737), a public
    // hostname, a `.local`-looking label that is not the suffix, and a
    // globally routable IPv6 address.
    for url in [
        "https://203.0.113.5/m.yaml",
        "https://policy.example/m.yaml",
        "https://local.example.com/m.yaml",
        "https://localhost.example.com/m.yaml",
        "https://[2001:db8::1]/m.yaml",
        "https://[64:ff9b::cb00:7105]/m.yaml",
    ] {
        super::reject_blocked_fetch_host(url).unwrap_or_else(|error| {
            panic!("{url} must pass the guard, got {error}");
        });
    }
}

#[test]
fn manifest_from_url_never_connects_to_a_blocked_literal() {
    // The review probe: a listener on loopback and a non-canonical literal
    // for it. Before the fix the guard let `127.1` through, the fetcher
    // canonicalized it and the listener saw the TCP connect.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    for url in [
        format!("https://127.1:{port}/m.yaml"),
        format!("https://2130706433:{port}/m.yaml"),
        format!("https://0x7f000001:{port}/m.yaml"),
        format!("https://localhost:{port}/m.yaml"),
        format!("https://[::ffff:127.0.0.1]:{port}/m.yaml"),
    ] {
        let error = crate::manifest_from_url(&url, None, crate::Limits::default())
            .expect_err(&format!("{url} must be refused"));
        assert!(
            error.to_string().contains("blocked destination"),
            "{url} gave {error}"
        );
    }

    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((_, peer)) => panic!("guard let a fetch connect to loopback from {peer}"),
        Err(error) => panic!("unexpected accept error: {error}"),
    }
}

#[test]
fn manifest_from_url_forces_redirects_off() {
    // The SSRF guard runs on the URL a caller passes and on nothing deeper.
    // The upstream fetcher follows redirects inside its HTTP client without
    // re-running the guard and exposes no hook, so a vetted public URL could
    // bounce the fetch to a blocked address. `manifest_from_url` must
    // therefore refuse to follow any redirect hop.
    //
    // This asserts the helper directly, not through `manifest_from_url`, and
    // that assertion is the coverage for the zeroed budget. `manifest_from_url`
    // is the only place `Limits` reaches `Manifest::from_path_with_limits`, and
    // it applies this helper on the way. No end-to-end redirect test is
    // possible in this environment. The upstream fetcher is HTTPS-only and its
    // system root store cannot be driven against a local server without
    // shipping TLS test infrastructure. A direct 2xx URL is unaffected because
    // a zero redirect budget still loads the response.
    let limits = Limits {
        max_manifest_url_redirects: 9,
        max_manifest_url_bytes: 2048,
        ..Default::default()
    };

    let effective = super::fail_closed_url_fetch_limits(limits);

    assert_eq!(effective.max_manifest_url_redirects, 0);
    // The unrelated fetch limits are preserved.
    assert_eq!(effective.max_manifest_url_bytes, 2048);
    assert_eq!(
        effective.manifest_url_timeout_ms,
        Limits::default().manifest_url_timeout_ms
    );
}

#[test]
fn host_constructors_accept_restored_remote_sources() {
    let bundle_url = format!(
        "agent_control_specification_version: 0.4.0-alpha.1
policies:
  p:
    type: rego
    query: data.acs.result
    bundle_url:
      url: https://bundles.example/b.tar.gz
      sha256: {}
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
",
        "e".repeat(64)
    );
    let manifest = Manifest::from_yaml_str(&bundle_url).expect("upstream accepts the field");
    AgentControl::from_manifest_with_dispatchers(
        manifest,
        Some(Arc::new(NoopAnnotator)),
        Some(Arc::new(QueuePolicy::with_responses([]))),
    )
    .expect("upstream implements pinned bundle URLs");

    let prompt_url = "agent_control_specification_version: 0.4.0-alpha.1
policies:
  p:
    type: test
annotators:
  judge:
    type: llm
    system_prompt_url:
      url: https://prompts.example/p.txt
      sha256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
    annotations:
      judge:
        from: $target
";
    AgentControl::from_manifest_chain_with_dispatchers(
        &[prompt_url],
        Some(Arc::new(NoopAnnotator)),
        Some(Arc::new(QueuePolicy::with_responses([]))),
    )
    .expect("upstream implements pinned prompt URLs");
}

// ---- #3941: every control keeps its limits, dispatchers and telemetry ----

fn tight_limits() -> crate::Limits {
    crate::Limits {
        max_snapshot_bytes: 256,
        ..crate::Limits::default()
    }
}

fn oversized_transform_policy() -> Arc<QueuePolicy> {
    Arc::new(QueuePolicy::with_responses([json!({
        "decision": "transform",
        "transform": {"path": "$target", "value": "b".repeat(100)}
    })]))
}

fn tight_control(policy: Arc<QueuePolicy>) -> AgentControl {
    AgentControl::from_manifest_with_dispatchers_and_limits(
        Manifest::from_yaml_str(run_manifest()).unwrap(),
        Some(Arc::new(NoopAnnotator)),
        Some(policy),
        tight_limits(),
    )
    .unwrap()
}

fn padded_options() -> RunOptions {
    RunOptions::default().with_ambient_snapshot(
        json!({"ambient": "a".repeat(180)})
            .as_object()
            .unwrap()
            .clone(),
    )
}

/// Run the padded scenario and report whether the body executed and how
/// the input point was judged.
fn run_padded(
    control: &AgentControl,
    options: RunOptions,
) -> (bool, Result<RunResult, AgentControlInterruption>) {
    let (executed_with, outcome) = run_padded_capturing(control, options);
    (executed_with.is_some(), outcome)
}

/// As [`run_padded`], returning the input the body received when it ran.
fn run_padded_capturing(
    control: &AgentControl,
    options: RunOptions,
) -> (
    Option<JsonValue>,
    Result<RunResult, AgentControlInterruption>,
) {
    let executed_with = Arc::new(Mutex::new(None));
    let executed_with_for_closure = executed_with.clone();
    let outcome = control.run_with_options(json!("x"), options, move |input| {
        *executed_with_for_closure.lock().unwrap() = Some(input.clone());
        input
    });
    let executed_with = executed_with.lock().unwrap().clone();
    (executed_with, outcome)
}

fn blocked_reason(outcome: Result<RunResult, AgentControlInterruption>) -> String {
    match outcome {
        Err(AgentControlInterruption::Blocked(blocked)) => {
            assert_eq!(blocked.intervention_point, InterceptionPoint::Input);
            blocked
                .intervention_point_result
                .verdict
                .reason
                .expect("host errors carry a reason")
        }
        other => panic!("expected a block at input, got {other:?}"),
    }
}

#[test]
fn oversized_transform_is_reported_in_evaluate_only_mode() {
    let control = tight_control(oversized_transform_policy());
    let (executed, outcome) = run_padded(
        &control,
        padded_options().with_mode(EnforcementMode::EvaluateOnly),
    );
    // Evaluate-only never blocks, but the limit failure must still be
    // visible so the policy cannot look clean in shadow mode.
    assert!(executed);
    let result = outcome.unwrap();
    let input = result.input_intervention_point_result;
    assert_eq!(
        input.verdict.reason.as_deref(),
        Some("host_error:transform_invalid")
    );
    assert_eq!(input.transformed_policy_target, None);
}

#[test]
fn transform_at_the_snapshot_limit_passes_and_one_byte_over_blocks() {
    // Locate the boundary with the same validator the host applies, over
    // the snapshot the host assembles for this scenario.
    let probe = tight_control(Arc::new(QueuePolicy::with_responses([])));
    let (_, outcome) = run_padded(
        &probe,
        padded_options().with_mode(EnforcementMode::EvaluateOnly),
    );
    let snapshot = outcome
        .unwrap()
        .input_intervention_point_result
        .policy_input
        .unwrap()["snapshot"]
        .clone();
    let with_input = |bytes: usize| {
        let mut snapshot = snapshot.clone();
        snapshot["input"] = json!("b".repeat(bytes));
        snapshot
    };
    let at_limit = (1..=256)
        .rev()
        .find(|bytes| {
            tight_limits()
                .validate_snapshot(&with_input(*bytes))
                .is_ok()
        })
        .expect("some transform fits in 256 bytes");
    assert_eq!(
        crate::canonical_json(&with_input(at_limit)).unwrap().len(),
        256
    );
    assert!(tight_limits()
        .validate_snapshot(&with_input(at_limit + 1))
        .is_err());

    let transform_of = |bytes: usize| {
        Arc::new(QueuePolicy::with_responses([json!({
            "decision": "transform",
            "transform": {"path": "$target", "value": "b".repeat(bytes)}
        })]))
    };
    // The body receives the transformed input, so the input point admitted
    // a snapshot of exactly 256 bytes. The output snapshot then carries that
    // input plus the output and may trip the engine's own budget; that is
    // the engine's check, not the host revalidation under test here.
    let (executed_with, outcome) =
        run_padded_capturing(&tight_control(transform_of(at_limit)), padded_options());
    assert_eq!(
        executed_with,
        Some(json!("b".repeat(at_limit))),
        "a transform exactly at the limit is admitted"
    );
    if let Err(interruption) = outcome {
        assert_eq!(interruption.intervention_point(), InterceptionPoint::Output);
    }

    let (executed, outcome) =
        run_padded(&tight_control(transform_of(at_limit + 1)), padded_options());
    assert!(!executed, "one byte over the limit is blocked");
    assert_eq!(blocked_reason(outcome), "host_error:transform_invalid");
}

#[test]
fn forbidden_transform_target_is_reported_over_its_size() {
    let policy = Arc::new(QueuePolicy::with_responses([json!({
        "decision": "transform",
        "transform": {"path": "$snap.ambient", "value": "b".repeat(100)}
    })]));
    let (executed, outcome) = run_padded(&tight_control(policy), padded_options());
    assert!(!executed);
    // The engine rejects the path before the host revalidates the size, so
    // the code is the engine's; either way the target error wins over size.
    let reason = blocked_reason(outcome);
    assert!(
        reason.ends_with(":transform_target_forbidden"),
        "expected a forbidden-target code, got {reason}"
    );
}

#[test]
fn cloned_control_keeps_its_limits() {
    let original = tight_control(oversized_transform_policy());
    let clone = original.clone();
    drop(original);
    let (executed, outcome) = run_padded(&clone, padded_options());
    assert!(!executed);
    assert_eq!(blocked_reason(outcome), "host_error:transform_invalid");
}

fn deny_policy() -> Arc<QueuePolicy> {
    Arc::new(QueuePolicy::with_responses([
        json!({"decision": "deny", "reason": "blocked"}),
    ]))
}

fn manifest_file(yaml: &str) -> tempfile::NamedTempFile {
    let file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    std::fs::write(file.path(), yaml).unwrap();
    file
}

fn ifc_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/ifc_agent/manifest.yaml")
}

/// The ifc_agent manifest with its relative paths made absolute, so it can
/// be loaded as an in-memory chain where no manifest directory exists.
fn ifc_manifest_yaml_with_absolute_paths() -> String {
    let dir = ifc_manifest_path()
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap();
    std::fs::read_to_string(ifc_manifest_path())
        .unwrap()
        .replace(
            "bundle: ./policy",
            &format!("bundle: {}", dir.join("policy").display()),
        )
        .replace(
            "- ../../policy/lib/ifc.rego",
            &format!("- {}", dir.join("../../policy/lib/ifc.rego").display()),
        )
}

fn ifc_deny_snapshot() -> JsonValue {
    json!({
        "tool_call": { "name": "public_egress", "args": { "body": "secret" } },
        "ifc": { "source_labels": ["confidential"] }
    })
}

/// One public constructor under test: its name, the control it built, the
/// deny evaluation it supports, and the policy id and reason code the
/// telemetry event must carry.
type ConstructorCase = (
    &'static str,
    Result<AgentControl, RuntimeError>,
    InterceptionPoint,
    JsonValue,
    &'static str,
    &'static str,
);

/// Every public constructor, paired with the deny evaluation it supports
/// and the policy id and reason the telemetry event must carry.
fn every_constructor() -> Vec<ConstructorCase> {
    let test_input = json!({"input": {"text": "hi"}});
    let run_file = manifest_file(run_manifest());
    let ifc_yaml = ifc_manifest_yaml_with_absolute_paths();
    vec![
        (
            "from_path",
            AgentControl::from_path(ifc_manifest_path()),
            InterceptionPoint::PreToolCall,
            ifc_deny_snapshot(),
            "ifc_policy",
            "ifc_clearance_violation",
        ),
        (
            "from_path_with_dispatchers",
            AgentControl::from_path_with_dispatchers(
                run_file.path(),
                Some(Arc::new(NoopAnnotator)),
                Some(deny_policy()),
            ),
            InterceptionPoint::Input,
            test_input.clone(),
            "test_policy",
            "blocked",
        ),
        (
            "from_manifest",
            AgentControl::from_manifest(Manifest::from_path(ifc_manifest_path()).unwrap()),
            InterceptionPoint::PreToolCall,
            ifc_deny_snapshot(),
            "ifc_policy",
            "ifc_clearance_violation",
        ),
        (
            "from_manifest_with_dispatchers",
            AgentControl::from_manifest_with_dispatchers(
                Manifest::from_yaml_str(run_manifest()).unwrap(),
                Some(Arc::new(NoopAnnotator)),
                Some(deny_policy()),
            ),
            InterceptionPoint::Input,
            test_input.clone(),
            "test_policy",
            "blocked",
        ),
        (
            "from_manifest_with_dispatchers_and_limits",
            AgentControl::from_manifest_with_dispatchers_and_limits(
                Manifest::from_yaml_str(run_manifest()).unwrap(),
                Some(Arc::new(NoopAnnotator)),
                Some(deny_policy()),
                tight_limits(),
            ),
            InterceptionPoint::Input,
            test_input.clone(),
            "test_policy",
            "blocked",
        ),
        (
            "from_manifest_chain",
            AgentControl::from_manifest_chain(&[ifc_yaml.as_str()]),
            InterceptionPoint::PreToolCall,
            ifc_deny_snapshot(),
            "ifc_policy",
            "ifc_clearance_violation",
        ),
        (
            "from_manifest_chain_with_dispatchers",
            AgentControl::from_manifest_chain_with_dispatchers(
                &[run_manifest()],
                Some(Arc::new(NoopAnnotator)),
                Some(deny_policy()),
            ),
            InterceptionPoint::Input,
            test_input,
            "test_policy",
            "blocked",
        ),
    ]
}

#[test]
fn with_telemetry_delivers_events_for_every_constructor() {
    use agent_control_specification_core::InMemoryTelemetrySink;

    for (name, control, point, snapshot, policy_id, reason_code) in every_constructor() {
        let sink = Arc::new(InMemoryTelemetrySink::new());
        let control = control
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .with_telemetry(sink.clone())
            .unwrap_or_else(|error| panic!("{name}: with_telemetry: {error}"));

        let result = control.evaluate_intervention_point(point, snapshot, EnforcementMode::Enforce);

        assert_eq!(result.verdict.decision, Decision::Deny, "{name}");
        let events = sink.events();
        assert_eq!(events.len(), 1, "{name}: {events:?}");
        assert_eq!(events[0].decision, Some(Decision::Deny), "{name}");
        assert_eq!(events[0].intervention_point, point, "{name}");
        assert_eq!(events[0].policy_id.as_deref(), Some(policy_id), "{name}");
        assert_eq!(
            events[0].reason_code.as_deref(),
            Some(reason_code),
            "{name}"
        );
    }
}

#[test]
fn with_telemetry_keeps_limits_and_perf_level() -> Result<(), RuntimeError> {
    use agent_control_specification_core::InMemoryTelemetrySink;

    let sink = Arc::new(InMemoryTelemetrySink::new());
    let control = tight_control(oversized_transform_policy())
        .with_perf_telemetry_level(crate::PerfTelemetry::Full)
        .with_telemetry(sink.clone())?;

    assert_eq!(
        control.runtime().perf_telemetry(),
        crate::PerfTelemetry::Full
    );
    let (executed, outcome) = run_padded(&control, padded_options());
    assert!(!executed, "the rebuild must not widen the limits");
    assert_eq!(blocked_reason(outcome), "host_error:transform_invalid");
    assert!(
        sink.events()
            .iter()
            .any(|event| event.intervention_point == InterceptionPoint::Input),
        "the rebuilt runtime reports to the installed sink"
    );
    Ok(())
}

#[test]
fn with_perf_telemetry_level_changes_the_runtime_level() {
    let control = build_control(run_manifest(), Arc::new(QueuePolicy::with_responses([])));
    assert_eq!(
        control.runtime().perf_telemetry(),
        crate::PerfTelemetry::Off
    );
    let control = control.with_perf_telemetry_level(crate::PerfTelemetry::External);
    assert_eq!(
        control.runtime().perf_telemetry(),
        crate::PerfTelemetry::External
    );
    let control = control.with_perf_telemetry_level(crate::PerfTelemetry::Full);
    assert_eq!(
        control.runtime().perf_telemetry(),
        crate::PerfTelemetry::Full
    );
}

#[test]
fn approval_resolver_survives_with_telemetry() -> Result<(), RuntimeError> {
    use agent_control_specification_core::InMemoryTelemetrySink;

    let policy = Arc::new(QueuePolicy::with_responses([
        json!({"decision": "escalate", "reason": "needs_approval"}),
        json!({"decision": "allow"}),
    ]));
    let sink = Arc::new(InMemoryTelemetrySink::new());
    let control = build_control(run_manifest(), policy)
        .with_approval_resolver(allow_resolver())
        .with_telemetry(sink.clone())?;

    let result = control
        .run(json!({"text": "original"}), |input| input)
        .expect("the resolver installed before the rebuild still approves");
    assert_eq!(result.value, json!({"text": "original"}));
    assert_eq!(sink.events().len(), 2, "one decision event per evaluation");
    Ok(())
}

#[test]
fn second_with_telemetry_replaces_the_first_sink() -> Result<(), RuntimeError> {
    use agent_control_specification_core::InMemoryTelemetrySink;

    let first = Arc::new(InMemoryTelemetrySink::new());
    let second = Arc::new(InMemoryTelemetrySink::new());
    let control = build_control(run_manifest(), deny_policy())
        .with_telemetry(first.clone())?
        .with_telemetry(second.clone())?;

    control.evaluate_intervention_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "hi"}}),
        EnforcementMode::Enforce,
    );

    assert_eq!(first.events().len(), 0);
    assert_eq!(second.events().len(), 1);
    Ok(())
}

#[test]
fn every_constructor_rejects_removed_manifest_fields() {
    let yaml = r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  p:
    type: test
annotators:
  judge:
    type: llm
    system_prompt_file: prompts/judge.txt
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
    annotations:
      judge:
        from: $target
"#;
    let manifest = Manifest::from_yaml_str(yaml).expect("upstream accepts the field");
    let file = manifest_file(yaml);
    let noop = || -> Option<Arc<dyn AnnotatorDispatcher>> { Some(Arc::new(NoopAnnotator)) };
    let allow =
        || -> Option<Arc<dyn PolicyDispatcher>> { Some(Arc::new(QueuePolicy::with_responses([]))) };
    let attempts: Vec<(&str, Result<AgentControl, RuntimeError>)> = vec![
        ("from_path", AgentControl::from_path(file.path())),
        (
            "from_path_with_dispatchers",
            AgentControl::from_path_with_dispatchers(file.path(), noop(), allow()),
        ),
        (
            "from_manifest",
            AgentControl::from_manifest(manifest.clone()),
        ),
        (
            "from_manifest_with_dispatchers",
            AgentControl::from_manifest_with_dispatchers(manifest.clone(), noop(), allow()),
        ),
        (
            "from_manifest_with_dispatchers_and_limits",
            AgentControl::from_manifest_with_dispatchers_and_limits(
                manifest,
                noop(),
                allow(),
                tight_limits(),
            ),
        ),
        (
            "from_manifest_chain",
            AgentControl::from_manifest_chain(&[yaml]),
        ),
        (
            "from_manifest_chain_with_dispatchers",
            AgentControl::from_manifest_chain_with_dispatchers(&[yaml], noop(), allow()),
        ),
    ];
    for (name, attempt) in attempts {
        let error = attempt
            .err()
            .unwrap_or_else(|| panic!("{name} accepted system_prompt_file"));
        assert!(
            matches!(error, RuntimeError::ManifestInvalid(_)),
            "{name}: {error}"
        );
        assert!(
            error
                .to_string()
                .starts_with("runtime_error:manifest_invalid"),
            "{name}: {error}"
        );
    }
}
