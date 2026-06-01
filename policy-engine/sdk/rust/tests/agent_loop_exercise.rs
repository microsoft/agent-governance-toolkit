use agent_control_specification::{
    action_identity, AgentControl, AnnotatorDispatcher, AnnotatorInvocation, ApprovalOutcome,
    ApprovalResolution, ApprovalResolver, Decision, EnforcementMode, InterventionPoint, JsonValue,
    Manifest, PolicyDispatcher, PreparedPolicyInvocation, RigLikeTool, Runtime, RuntimeError,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;

#[derive(Default)]
struct RecordingAnnotator {
    names: Mutex<Vec<String>>,
}

impl RecordingAnnotator {
    fn names(&self) -> Vec<String> {
        self.names.lock().unwrap().clone()
    }
}

impl AnnotatorDispatcher for RecordingAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        self.names.lock().unwrap().push(annotator_name.to_string());
        Ok(json!({"target": preliminary_policy_input["policy_target"].clone()}))
    }
}

#[derive(Default)]
struct ScenarioPolicy {
    seen: Mutex<Vec<JsonValue>>,
    fail_invocation: bool,
    invalid_output: bool,
}

impl ScenarioPolicy {
    fn seen(&self) -> Vec<JsonValue> {
        self.seen.lock().unwrap().clone()
    }
}

impl PolicyDispatcher for ScenarioPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        if self.fail_invocation {
            return Err(RuntimeError::PolicyInvocationFailed(
                "policy offline".to_string(),
            ));
        }
        if self.invalid_output {
            return Ok(json!({"decision": 7}));
        }
        let input = invocation.policy_input().unwrap().clone();
        self.seen.lock().unwrap().push(input.clone());
        let point = input["intervention_point"].as_str().unwrap();
        match point {
            "pre_model_call" => Ok(json!({
                "decision": "transform",
                "reason": "prompt_rewritten",
                "transform": {"path": "$policy_target.prompt", "value": "safe research"}
            })),
            "post_model_call" => Ok(json!({
                "decision": "transform", "transform": {"path": "$policy_target.text", "value": "model secret redacted"}
            })),
            "pre_tool_call" => {
                let tool = input["tool"]["name"].as_str().unwrap();
                match tool {
                    "delete_user" => Ok(json!({"decision": "deny", "reason": "dangerous_tool"})),
                    "transfer_funds" => {
                        Ok(json!({"decision": "escalate", "reason": "sensitive_action"}))
                    }
                    _ => Ok(json!({
                        // AGT D1: multi-span redaction migrates to a single
                        // transform; for this test we collapse the redaction
                        // to its final value.
                        "decision": "transform",
                        "transform": {"path": "$policy_target.query", "value": "search [redacted]"}
                    })),
                }
            }
            "post_tool_call" => Ok(json!({
                "decision": "transform", "transform": {"path": "$policy_target.answer", "value": "tool secret redacted"}
            })),
            _ => Ok(json!({"decision": "allow"})),
        }
    }
}

fn manifest() -> Manifest {
    Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  scenario:
    type: test
intervention_points:
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: scenario
    policy_target: $snap.model_request
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: scenario
    policy_target: $snap.model_response
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $snap.tool_call.name
    policy:
      id: scenario
    policy_target: $snap.tool_call.args
    annotations:
      z_late:
        from: $policy_target
      a_first:
        from: $policy_target
  post_tool_call:
    policy_target_kind: tool_result
    tool_name_from: $snap.tool_call.name
    policy:
      id: scenario
    policy_target: $snap.tool_result
tools:
  search:
    clearance: public
  delete_user:
    clearance: restricted
  transfer_funds:
    clearance: restricted
annotators:
  z_late:
    type: classifier
  a_first:
    type: classifier"#,
    )
    .unwrap()
}

fn control(policy: Arc<ScenarioPolicy>, annotator: Arc<RecordingAnnotator>) -> AgentControl {
    AgentControl::new(Runtime::new(manifest(), annotator, policy).unwrap())
}

fn allow_resolver() -> ApprovalResolver {
    Arc::new(|_, result| ApprovalResolution::allow(result.action_identity.clone().unwrap()))
}

fn deny_resolver() -> ApprovalResolver {
    Arc::new(|_, _| ApprovalResolution::deny())
}

#[test]
fn realistic_agent_loop_exercises_model_tool_and_approval_paths() {
    let policy = Arc::new(ScenarioPolicy::default());
    let annotator = Arc::new(RecordingAnnotator::default());
    let agent_control =
        control(policy.clone(), annotator.clone()).with_approval_resolver(allow_resolver());

    let model_seen = Arc::new(Mutex::new(JsonValue::Null));
    let model_seen_for_closure = model_seen.clone();
    let model = agent_control
        .run_model(json!({"prompt": "unsafe research"}), move |request| {
            *model_seen_for_closure.lock().unwrap() = request.clone();
            json!({"text": format!("raw {} SECRET", request["prompt"].as_str().unwrap())})
        })
        .unwrap();
    assert_eq!(
        model
            .pre_model_call_intervention_point_result
            .verdict
            .decision,
        Decision::Transform
    );
    assert_eq!(
        *model_seen.lock().unwrap(),
        json!({"prompt": "safe research"})
    );
    assert_eq!(model.value, json!({"text": "model secret redacted"}));

    let tool_seen = Arc::new(Mutex::new(Vec::new()));
    let tool_seen_for_closure = tool_seen.clone();
    let tool = agent_control.protect_tool("search", move |args| {
        tool_seen_for_closure.lock().unwrap().push(args.clone());
        json!({"answer": format!("found {} SECRET", args["query"].as_str().unwrap())})
    });
    let tool_result = tool.run(json!({"query": "token SECRET123"})).unwrap();
    assert_eq!(
        *tool_seen.lock().unwrap(),
        vec![json!({"query": "search [redacted]"})]
    );
    assert_eq!(tool_result.value, json!({"answer": "tool secret redacted"}));

    let denied = agent_control
        .run_tool(
            "delete_user",
            json!({"user": "u1"}),
            |_| json!({"deleted": true}),
        )
        .unwrap_err();
    assert_eq!(denied.intervention_point(), InterventionPoint::PreToolCall);
    assert_eq!(
        denied.intervention_point_result().verdict.reason.as_deref(),
        Some("dangerous_tool")
    );

    let approved = agent_control
        .run_tool(
            "transfer_funds",
            json!({"amount": 10}),
            |args| json!({"answer": args}),
        )
        .unwrap();
    assert_eq!(
        approved
            .pre_tool_call_intervention_point_result
            .verdict
            .decision,
        Decision::Escalate
    );

    let rejected = control(policy, Arc::new(RecordingAnnotator::default()))
        .with_approval_resolver(deny_resolver())
        .run_tool(
            "transfer_funds",
            json!({"amount": 10}),
            |_| json!({"answer": "no"}),
        )
        .unwrap_err();
    assert_eq!(
        rejected.intervention_point(),
        InterventionPoint::PreToolCall
    );

    let names = annotator.names();
    assert!(names.windows(2).any(|pair| pair == ["a_first", "z_late"]));
}

#[test]
fn runtime_policy_failures_and_invalid_outputs_fail_closed() {
    for (policy, reason) in [
        (
            ScenarioPolicy {
                fail_invocation: true,
                ..ScenarioPolicy::default()
            },
            "runtime_error:policy_invocation_failed",
        ),
        (
            ScenarioPolicy {
                invalid_output: true,
                ..ScenarioPolicy::default()
            },
            "runtime_error:policy_output_invalid",
        ),
    ] {
        let control = control(Arc::new(policy), Arc::new(RecordingAnnotator::default()));
        let error = control
            .run_tool("search", json!({"query": "token SECRET123"}), |_| json!({}))
            .unwrap_err();
        assert_eq!(error.intervention_point(), InterventionPoint::PreToolCall);
        assert_eq!(
            error.intervention_point_result().verdict.reason.as_deref(),
            Some(reason)
        );
    }
}

#[test]
fn approval_resolver_panic_fails_closed() {
    let policy = Arc::new(ScenarioPolicy::default());
    let resolver: ApprovalResolver = Arc::new(|_, _| panic!("approval service crashed"));
    let control =
        control(policy, Arc::new(RecordingAnnotator::default())).with_approval_resolver(resolver);

    let error = control
        .run_tool(
            "transfer_funds",
            json!({"amount": 10}),
            |_| json!({"answer": "no"}),
        )
        .unwrap_err();

    assert_eq!(error.intervention_point(), InterventionPoint::PreToolCall);
    assert_eq!(
        error.intervention_point_result().verdict.reason.as_deref(),
        Some("runtime_error:approval_resolver_failed")
    );
}

#[test]
fn concurrent_guarded_flows_do_not_share_policy_state() {
    let mut handles = Vec::new();
    for (tool, expect_allowed) in [("search", true), ("delete_user", false)] {
        handles.push(thread::spawn(move || {
            let control = control(
                Arc::new(ScenarioPolicy::default()),
                Arc::new(RecordingAnnotator::default()),
            );
            let result = control.run_tool(
                tool,
                json!({"query": "token SECRET123"}),
                |args| json!({"answer": args}),
            );
            assert_eq!(result.is_ok(), expect_allowed);
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

#[derive(Clone)]
struct EchoRigLike {
    seen: Arc<Mutex<Vec<JsonValue>>>,
}

impl RigLikeTool for EchoRigLike {
    type Error = std::convert::Infallible;

    fn name(&self) -> &str {
        "search"
    }

    fn call(&self, args: JsonValue) -> Result<JsonValue, Self::Error> {
        self.seen.lock().unwrap().push(args.clone());
        Ok(json!({"answer": args}))
    }
}

#[test]
fn retained_unwrapped_rig_like_tool_reference_is_host_contract_bypass() {
    let control = control(
        Arc::new(ScenarioPolicy::default()),
        Arc::new(RecordingAnnotator::default()),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let inner = EchoRigLike { seen: seen.clone() };
    let guarded = control.guard_rig_like_tool(inner.clone());

    let guarded_output = guarded.call(json!({"query": "token SECRET123"})).unwrap();
    assert_eq!(guarded_output, json!({"answer": "tool secret redacted"}));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![json!({"query": "search [redacted]"})]
    );

    let bypass_output = inner.call(json!({"query": "token SECRET123"})).unwrap();
    assert_eq!(
        bypass_output,
        json!({"answer": {"query": "token SECRET123"}})
    );
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        &json!({"query": "token SECRET123"})
    );
}

#[test]
fn evaluate_only_observes_without_blocking_or_transforming() {
    let policy = Arc::new(ScenarioPolicy::default());
    let control = control(policy.clone(), Arc::new(RecordingAnnotator::default()));
    let result = control
        .run_tool_with_options(
            "delete_user",
            json!({"user": "u1"}),
            agent_control_specification::ToolRunOptions::evaluate_only(),
            |args| json!({"answer": args}),
        )
        .unwrap();

    assert_eq!(
        result
            .pre_tool_call_intervention_point_result
            .verdict
            .decision,
        Decision::Deny
    );
    assert_eq!(result.value, json!({"answer": {"user": "u1"}}));
    assert!(result
        .pre_tool_call_intervention_point_result
        .transformed_policy_target
        .is_none());
    assert!(policy.seen().iter().any(|input| {
        input["intervention_point"] == "pre_tool_call" && input["tool"]["name"] == "delete_user"
    }));
}

#[test]
fn manual_evaluate_and_enforce_approval_identity_remains_deterministic() {
    let control = control(
        Arc::new(ScenarioPolicy::default()),
        Arc::new(RecordingAnnotator::default()),
    );
    let result = control.evaluate_intervention_point(
        InterventionPoint::PreToolCall,
        json!({"tool_call": {"name": "transfer_funds", "args": {"amount": 10}}}),
        EnforcementMode::Enforce,
    );
    let expected_identity = action_identity(result.policy_input.as_ref().unwrap()).unwrap();
    let resolver: ApprovalResolver = Arc::new(
        move |_, _result: &agent_control_specification::InterventionPointResult| {
            ApprovalResolution::allow(expected_identity.clone())
        },
    );

    assert!(control
        .enforce(
            InterventionPoint::PreToolCall,
            &result,
            EnforcementMode::Enforce,
            Some(&resolver)
        )
        .is_ok());
}

#[derive(Default)]
struct PaymentPolicy;

impl PolicyDispatcher for PaymentPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let input = invocation.policy_input().unwrap();
        if input["intervention_point"] == "pre_tool_call"
            && input["tool"]["name"] == "wire_transfer"
            && input["policy_target"]["value"]["amount"]
                .as_i64()
                .unwrap_or_default()
                >= 10_000
        {
            return Ok(json!({
                "decision": "escalate",
                "reason": "high_value_transfer"
                // AGT D1 + §13.1: escalate carries no effects. The
                // memo redaction this used to do can no longer ride the
                // escalate decision; if the host needs to pre-sanitise
                // the memo it must use a separate transform at an
                // earlier intervention point.
            }));
        }
        Ok(json!({"decision": "allow"}))
    }
}

fn payment_manifest() -> Manifest {
    Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  payments:
    type: test
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $snap.tool_call.name
    policy:
      id: payments
    policy_target: $snap.tool_call.args
  post_tool_call:
    policy_target_kind: tool_result
    tool_name_from: $snap.tool_call.name
    policy:
      id: payments
    policy_target: $snap.tool_result
tools:
  wire_transfer:
    clearance: restricted"#,
    )
    .unwrap()
}

fn payment_control(resolver: ApprovalResolver) -> AgentControl {
    AgentControl::new(
        Runtime::new(
            payment_manifest(),
            Arc::new(RecordingAnnotator::default()),
            Arc::new(PaymentPolicy),
        )
        .unwrap(),
    )
    .with_approval_resolver(resolver)
}

#[test]
fn payment_escalation_hitl_exercises_identity_effects_and_isolation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_resolver = calls.clone();
    let approve: ApprovalResolver = Arc::new(move |_, result| {
        calls_for_resolver.fetch_add(1, Ordering::SeqCst);
        ApprovalResolution::allow(result.action_identity.clone().unwrap())
    });
    let control = payment_control(approve);
    let executed_with = Arc::new(Mutex::new(Vec::new()));
    let executed_with_for_closure = executed_with.clone();

    let approved = control
        .run_tool_with_options(
            "wire_transfer",
            json!({"amount": 25_000, "beneficiary": "acct-1", "memo": "payroll secret"}),
            agent_control_specification::ToolRunOptions::new().with_tool_call_id("wire-approve"),
            move |args| {
                executed_with_for_closure.lock().unwrap().push(args.clone());
                json!({"charged": args})
            },
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(executed_with.lock().unwrap().len(), 1);
    // AGT D1 + §13.1: escalate carries no effects. The host that
    // wants to redact the memo before execution must do so via a
    // transform at an earlier intervention point; the action proceeds
    // with the original payload after approval.
    assert_eq!(
        executed_with.lock().unwrap()[0]["memo"],
        json!("payroll secret")
    );
    assert_eq!(approved.value["charged"]["memo"], json!("payroll secret"));

    let rejected_executed = Arc::new(Mutex::new(false));
    let rejected_executed_for_closure = rejected_executed.clone();
    let rejected = payment_control(deny_resolver())
        .run_tool_with_options(
            "wire_transfer",
            json!({"amount": 30_000, "beneficiary": "acct-2", "memo": "reject secret"}),
            agent_control_specification::ToolRunOptions::new().with_tool_call_id("wire-reject"),
            move |_| {
                *rejected_executed_for_closure.lock().unwrap() = true;
                json!({"charged": true})
            },
        )
        .unwrap_err();
    assert_eq!(
        rejected.intervention_point(),
        InterventionPoint::PreToolCall
    );
    assert_eq!(
        rejected
            .intervention_point_result()
            .verdict
            .reason
            .as_deref(),
        Some("high_value_transfer")
    );
    assert!(!*rejected_executed.lock().unwrap());

    let stale_result = control.evaluate_intervention_point(
        InterventionPoint::PreToolCall,
        json!({"tool_call": {"id": "wire-replay", "name": "wire_transfer", "args": {"amount": 40_000, "beneficiary": "acct-3", "memo": "memo"}}}),
        EnforcementMode::Enforce,
    );
    let stale_identity = stale_result.action_identity.clone().unwrap();
    let stale_resolver: ApprovalResolver =
        Arc::new(move |_, _| ApprovalResolution::allow(stale_identity.clone()));
    let stale = payment_control(stale_resolver)
        .run_tool_with_options(
            "wire_transfer",
            json!({"amount": 40_001, "beneficiary": "acct-3", "memo": "memo"}),
            agent_control_specification::ToolRunOptions::new().with_tool_call_id("wire-replay"),
            |args| json!({"charged": args}),
        )
        .unwrap_err();
    assert_eq!(
        stale.intervention_point_result().verdict.reason.as_deref(),
        Some("runtime_error:approval_action_mismatch")
    );

    let ordered = json!({"snapshot": {"tool_call": {"id": "stable", "name": "wire_transfer", "args": {"amount": 50_000, "beneficiary": "acct-4", "memo": "memo"}}}, "intervention_point": "pre_tool_call"});
    let reordered = json!({"intervention_point": "pre_tool_call", "snapshot": {"tool_call": {"args": {"memo": "memo", "beneficiary": "acct-4", "amount": 50_000}, "name": "wire_transfer", "id": "stable"}}});
    let string_amount = json!({"snapshot": {"tool_call": {"id": "stable", "name": "wire_transfer", "args": {"amount": "50000", "beneficiary": "acct-4", "memo": "memo"}}}, "intervention_point": "pre_tool_call"});
    assert_eq!(
        action_identity(&ordered).unwrap(),
        action_identity(&reordered).unwrap()
    );
    assert_ne!(
        action_identity(&ordered).unwrap(),
        action_identity(&string_amount).unwrap()
    );

    let malformed: ApprovalResolver = Arc::new(|_, _| ApprovalResolution {
        outcome: ApprovalOutcome::Allow,
        handle: None,
        action_identity: None,
    });
    let malformed_error = payment_control(malformed)
        .run_tool_with_options(
            "wire_transfer",
            json!({"amount": 70_000, "beneficiary": "acct-6", "memo": "bad"}),
            agent_control_specification::ToolRunOptions::new().with_tool_call_id("wire-malformed"),
            |args| json!({"charged": args}),
        )
        .unwrap_err();
    assert_eq!(
        malformed_error
            .intervention_point_result()
            .verdict
            .reason
            .as_deref(),
        Some("runtime_error:approval_action_mismatch")
    );
}

#[test]
fn concurrent_payment_escalations_do_not_cross_authorize() {
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let calls_for_resolver = resolver_calls.clone();
    let resolver: ApprovalResolver = Arc::new(move |_, result| {
        calls_for_resolver.fetch_add(1, Ordering::SeqCst);
        ApprovalResolution::allow(result.action_identity.clone().unwrap())
    });
    let control = payment_control(resolver);
    let mut handles = Vec::new();
    for (call_id, amount) in [("wire-c1", 80_000), ("wire-c2", 90_000)] {
        let control = control.clone();
        handles.push(thread::spawn(move || {
            let result = control
                .run_tool_with_options(
                    "wire_transfer",
                    json!({"amount": amount, "beneficiary": call_id, "memo": "concurrent"}),
                    agent_control_specification::ToolRunOptions::new().with_tool_call_id(call_id),
                    |args| json!({"charged": args}),
                )
                .unwrap();
            assert_eq!(result.value["charged"]["amount"], json!(amount));
            // AGT D1 + §13.1: escalate carries no effects; the action
            // proceeds with the original memo after approval.
            assert_eq!(result.value["charged"]["memo"], json!("concurrent"));
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2);
}
