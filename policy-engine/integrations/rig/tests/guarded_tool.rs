use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agent_control_specification::{
    AgentControl, AnnotatorDispatcher, AnnotatorInvocation, ApprovalResolution, ApprovalResolver,
    InterventionPoint, InterventionPointResult, JsonValue, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError,
};
use agent_control_specification_rig::AgentControlRigExt;
use rig::completion::ToolDefinition;
use rig::tool::{Tool, ToolDyn, ToolError};
use serde::Deserialize;
use serde_json::json;

struct NoopAnnotator;

impl AnnotatorDispatcher for NoopAnnotator {
    fn dispatch(
        &self,
        _name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(JsonValue::Null)
    }
}

/// Returns queued verdicts in order, defaulting to allow once drained.
struct QueuePolicy {
    responses: Mutex<VecDeque<JsonValue>>,
}

impl QueuePolicy {
    fn new<I: IntoIterator<Item = JsonValue>>(responses: I) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into_iter().collect()),
        })
    }
}

impl PolicyDispatcher for QueuePolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| json!({ "decision": "allow" })))
    }
}

struct AmbientSnapshotPolicy;

impl PolicyDispatcher for AmbientSnapshotPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let input = invocation.policy_input().expect("policy input");
        if input["intervention_point"] == "pre_tool_call" {
            let labels = input
                .pointer("/snapshot/ifc/source_labels")
                .and_then(JsonValue::as_array)
                .cloned()
                .unwrap_or_default();
            if labels == vec![json!("confidential")] {
                return Ok(json!({ "decision": "allow" }));
            }
            return Ok(json!({
                "decision": "deny",
                "reason": "ifc_missing_or_invalid_source_labels"
            }));
        }
        Ok(json!({ "decision": "allow" }))
    }
}

/// Inner Rig tool that records the args it received and echoes them back.
struct EchoTool {
    seen: Arc<Mutex<Vec<JsonValue>>>,
}

struct NamedEchoTool {
    name: &'static str,
    seen: Arc<Mutex<Vec<JsonValue>>>,
}

struct SmokeRigTool {
    calls: Arc<AtomicUsize>,
}

#[derive(Deserialize)]
struct SmokeRigArgs {
    message: String,
    response_mode: Option<String>,
}

impl ToolDyn for EchoTool {
    fn name(&self) -> String {
        "search".to_string()
    }

    fn definition<'a>(
        &'a self,
        _prompt: String,
    ) -> Pin<Box<dyn Future<Output = ToolDefinition> + Send + 'a>> {
        Box::pin(async {
            ToolDefinition {
                name: "search".to_string(),
                description: String::new(),
                parameters: json!({}),
            }
        })
    }

    fn call<'a>(
        &'a self,
        args: String,
    ) -> Pin<Box<dyn Future<Output = Result<String, ToolError>> + Send + 'a>> {
        let seen = self.seen.clone();
        Box::pin(async move {
            let parsed: JsonValue = serde_json::from_str(&args)?;
            seen.lock().unwrap().push(parsed.clone());
            let query = parsed["query"].as_str().unwrap_or_default();
            Ok(format!("result for {query}"))
        })
    }
}

impl ToolDyn for NamedEchoTool {
    fn name(&self) -> String {
        self.name.to_string()
    }

    fn definition<'a>(
        &'a self,
        _prompt: String,
    ) -> Pin<Box<dyn Future<Output = ToolDefinition> + Send + 'a>> {
        let name = self.name.to_string();
        Box::pin(async move {
            ToolDefinition {
                name,
                description: String::new(),
                parameters: json!({}),
            }
        })
    }

    fn call<'a>(
        &'a self,
        args: String,
    ) -> Pin<Box<dyn Future<Output = Result<String, ToolError>> + Send + 'a>> {
        let seen = self.seen.clone();
        Box::pin(async move {
            let parsed: JsonValue = serde_json::from_str(&args)?;
            seen.lock().unwrap().push(parsed.clone());
            let query = parsed["query"].as_str().unwrap_or_default();
            Ok(format!("result for {query}"))
        })
    }
}

impl Tool for SmokeRigTool {
    const NAME: &'static str = "echo_tool";

    type Error = Infallible;
    type Args = SmokeRigArgs;
    type Output = String;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Echoes the message or returns a sentinel response for ACS smoke tests."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" },
                    "response_mode": { "type": "string" }
                },
                "required": ["message"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if args.response_mode.as_deref() == Some("blocked_output") {
            Ok("BLOCKME returned by real rig tool".to_string())
        } else {
            Ok(format!("echo: {}", args.message))
        }
    }
}

fn manifest() -> Manifest {
    let yaml = r#"agent_control_specification_version: 0.3.1-beta
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
  post_tool_call:
    policy_target_kind: tool_result
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_result
tools:
  search:
    clearance: public"#;
    Manifest::from_yaml_str(yaml).unwrap()
}

fn control<I: IntoIterator<Item = JsonValue>>(verdicts: I) -> AgentControl {
    let runtime = Runtime::new(
        manifest(),
        Arc::new(NoopAnnotator),
        QueuePolicy::new(verdicts),
    )
    .expect("runtime");
    AgentControl::new(runtime)
}

fn ifc_ambient_control() -> AgentControl {
    let yaml = r#"agent_control_specification_version: 0.3.1-beta
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
  post_tool_call:
    policy_target_kind: tool_result
    tool_name_from: $snap.tool_call.name
    policy:
      id: test_policy
    policy_target: $snap.tool_result
tools:
  trusted_archive:
    clearance: confidential"#;
    let runtime = Runtime::new(
        Manifest::from_yaml_str(yaml).unwrap(),
        Arc::new(NoopAnnotator),
        Arc::new(AmbientSnapshotPolicy),
    )
    .expect("runtime");
    AgentControl::new(runtime)
}

fn smoke_control() -> AgentControl {
    AgentControl::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/smoke/manifest.yaml"
    ))
    .unwrap()
}

fn replace(path: &str, value: JsonValue) -> JsonValue {
    // AGT D1: effects[] is rejected; the canonical single-target
    // replacement is decision: "transform" + transform body.
    json!({ "decision": "transform", "transform": { "path": path, "value": value } })
}

fn allow_resolver() -> ApprovalResolver {
    Arc::new(|_: InterventionPoint, result: &InterventionPointResult| {
        ApprovalResolution::allow(result.action_identity.clone().unwrap())
    })
}

fn deny_resolver() -> ApprovalResolver {
    Arc::new(|_: InterventionPoint, _: &InterventionPointResult| ApprovalResolution::deny())
}

fn suspend_resolver() -> ApprovalResolver {
    Arc::new(|_: InterventionPoint, result: &InterventionPointResult| {
        ApprovalResolution::suspend(
            Some(json!({ "ticket": "T-1" })),
            result.action_identity.clone().unwrap(),
        )
    })
}

#[tokio::test]
async fn zero_config_from_path_guards_rig_tool() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let manifest_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/ifc_agent/manifest.yaml");
    let control = AgentControl::from_path(manifest_path).unwrap();
    let guarded = control.guard_rig_tool(Arc::new(NamedEchoTool {
        name: "trusted_archive",
        seen: seen.clone(),
    }));

    let error = guarded
        .call(json!({ "query": "confidential record" }).to_string())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("IFC clearance violation"));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ambient_snapshot_reaches_rig_tool_policy_input() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ambient_snapshot = json!({
        "ifc": {
            "source_labels": ["confidential"]
        }
    })
    .as_object()
    .unwrap()
    .clone();
    let guarded = ifc_ambient_control()
        .guard_rig_tool(Arc::new(NamedEchoTool {
            name: "trusted_archive",
            seen: seen.clone(),
        }))
        .with_ambient_snapshot(ambient_snapshot);

    let output = guarded
        .call(json!({ "query": "confidential record" }).to_string())
        .await
        .unwrap();

    assert_eq!(output, "result for confidential record");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![json!({ "query": "confidential record" })]
    );
}

#[tokio::test]
async fn call_with_result_exposes_post_tool_result_labels() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([
        json!({ "decision": "allow" }),
        json!({ "decision": "allow", "result_labels": ["internal"] }),
    ])
    .guard_rig_tool(Arc::new(EchoTool { seen }));

    let result = guarded
        .call_with_result(json!({ "query": "labeled result" }).to_string())
        .await
        .unwrap();

    assert_eq!(result.value, "result for labeled result");
    assert_eq!(
        result
            .post_tool_call_intervention_point_result
            .verdict
            .result_labels,
        vec!["internal".to_string()]
    );
}

#[tokio::test]
async fn real_rig_tool_enforces_smoke_policy_at_pre_and_post_tool_call() {
    let calls = Arc::new(AtomicUsize::new(0));
    let guarded = smoke_control().guard_rig_tool(Arc::new(SmokeRigTool {
        calls: calls.clone(),
    }));

    let benign = guarded
        .call(json!({ "message": "hello" }).to_string())
        .await
        .unwrap();
    assert_eq!(benign, "echo: hello");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let pre_error = guarded
        .call(json!({ "message": "BLOCKME only in args" }).to_string())
        .await
        .unwrap_err();
    assert!(pre_error.to_string().contains("pre_tool_call"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let post_error = guarded
        .call(json!({ "message": "hello", "response_mode": "blocked_output" }).to_string())
        .await
        .unwrap_err();
    assert!(post_error.to_string().contains("post_tool_call"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn bulk_wraps_rig_tools_for_agent_builder_shape() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let tools: Vec<Arc<dyn ToolDyn>> = vec![Arc::new(EchoTool { seen })];
    let guarded: Vec<Box<dyn ToolDyn>> = control([]).guard_rig_tools(tools);

    assert_eq!(guarded.len(), 1);
    assert_eq!(guarded[0].name(), "search");
}

#[tokio::test]
async fn allows_and_passes_args_through() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([]).guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let output = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap();

    assert_eq!(guarded.name(), "search");
    assert_eq!(output, "result for raw");
    assert_eq!(*seen.lock().unwrap(), vec![json!({ "query": "raw" })]);
}

#[tokio::test]
async fn pre_deny_fails_closed_without_calling_inner() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([json!({ "decision": "deny", "reason": "nope" })])
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let error = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("pre_tool_call"));
    assert!(error.to_string().contains("nope"));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pre_transform_rewrites_args_reaching_inner() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([replace("$policy_target.query", json!("safe"))])
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let output = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap();

    assert_eq!(output, "result for safe");
    assert_eq!(*seen.lock().unwrap(), vec![json!({ "query": "safe" })]);
}

#[tokio::test]
async fn post_transform_rewrites_output() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([
        json!({ "decision": "allow" }),
        replace("$policy_target", json!("redacted")),
    ])
    .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let output = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap();

    assert_eq!(output, "redacted");
}

#[tokio::test]
async fn post_deny_fails_closed() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([
        json!({ "decision": "allow" }),
        json!({ "decision": "deny", "reason": "leaked" }),
    ])
    .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let error = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("post_tool_call"));
    assert!(error.to_string().contains("leaked"));
}

#[tokio::test]
async fn escalate_without_resolver_fails_closed() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([json!({ "decision": "escalate", "reason": "needs review" })])
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let error = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("pre_tool_call"));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn escalate_after_resolver_proceeds_with_original_args() {
    // AGT D1 + §13.1: escalate carries no effects. After approval, the
    // tool runs with the original args; there is no way to bundle a
    // deferred transform with the escalate decision.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([json!({"decision": "escalate", "reason": "needs review"})])
        .with_approval_resolver(allow_resolver())
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let output = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap();

    assert_eq!(output, "result for raw");
    assert_eq!(*seen.lock().unwrap(), vec![json!({ "query": "raw" })]);
}

#[tokio::test]
async fn escalate_deny_resolver_blocks() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([json!({ "decision": "escalate", "reason": "denied by approver" })])
        .with_approval_resolver(deny_resolver())
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }));

    let error = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("pre_tool_call"));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn escalate_suspend_resolver_blocks_with_suspension_message() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([json!({ "decision": "escalate" })])
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }))
        .with_approval_resolver(suspend_resolver());

    let error = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("suspended"));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn per_tool_resolver_overrides_instance_resolver() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let guarded = control([json!({ "decision": "escalate" })])
        .with_approval_resolver(deny_resolver())
        .guard_rig_tool(Arc::new(EchoTool { seen: seen.clone() }))
        .with_approval_resolver(allow_resolver());

    let output = guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .unwrap();

    assert_eq!(output, "result for raw");
}

#[tokio::test]
async fn retained_unwrapped_rig_tool_reference_is_host_contract_bypass() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let inner: Arc<dyn ToolDyn> = Arc::new(EchoTool { seen: seen.clone() });
    let guarded =
        control([json!({ "decision": "deny", "reason": "blocked" })]).guard_rig_tool(inner.clone());

    assert!(guarded
        .call(json!({ "query": "raw" }).to_string())
        .await
        .is_err());
    assert!(seen.lock().unwrap().is_empty());

    let output = inner
        .call(json!({ "query": "bypass" }).to_string())
        .await
        .unwrap();
    assert_eq!(output, "result for bypass");
    assert_eq!(*seen.lock().unwrap(), vec![json!({ "query": "bypass" })]);
}

#[tokio::test]
async fn concurrent_guarded_rig_tools_keep_independent_decisions() {
    let allowed_seen = Arc::new(Mutex::new(Vec::new()));
    let denied_seen = Arc::new(Mutex::new(Vec::new()));
    let allowed = control([
        json!({ "decision": "allow" }),
        json!({ "decision": "allow" }),
    ])
    .guard_rig_tool(Arc::new(EchoTool {
        seen: allowed_seen.clone(),
    }));
    let denied = control([json!({ "decision": "deny", "reason": "blocked" })]).guard_rig_tool(
        Arc::new(EchoTool {
            seen: denied_seen.clone(),
        }),
    );

    let (allowed_result, denied_result) = tokio::join!(
        allowed.call(json!({ "query": "allowed" }).to_string()),
        denied.call(json!({ "query": "denied" }).to_string())
    );

    assert_eq!(allowed_result.unwrap(), "result for allowed");
    assert!(denied_result.unwrap_err().to_string().contains("blocked"));
    assert_eq!(
        *allowed_seen.lock().unwrap(),
        vec![json!({ "query": "allowed" })]
    );
    assert!(denied_seen.lock().unwrap().is_empty());
}
