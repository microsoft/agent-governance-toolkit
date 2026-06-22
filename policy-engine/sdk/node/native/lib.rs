use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, InterventionPointResult, JsonValue, Manifest, PerfTelemetry,
    PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError, Verdict,
};
use napi::bindgen_prelude::{Env, Error, JsFunction, Promise, Result};
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;

fn sync_bridge_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("acs-sync-bridge")
            .build()
            .expect("failed to build acs sync bridge runtime")
    })
}

fn call_tsfn_blocking(
    tsfn: &ThreadsafeFunction<String, ErrorStrategy::CalleeHandled>,
    arg: String,
) -> std::result::Result<String, String> {
    let fut = async {
        let promise: std::result::Result<Promise<String>, napi::Error> =
            tsfn.call_async::<Promise<String>>(Ok(arg)).await;
        match promise {
            Ok(p) => p.await.map_err(|e| format!("{e}")),
            Err(e) => Err(format!("{e}")),
        }
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        sync_bridge_runtime().block_on(fut)
    }
}

fn make_string_tsfn(
    env: &Env,
    callback: JsFunction,
) -> Result<ThreadsafeFunction<String, ErrorStrategy::CalleeHandled>> {
    let mut tsfn = callback.create_threadsafe_function(0, |ctx| Ok(vec![ctx.value]))?;
    tsfn.unref(env)?;
    Ok(tsfn)
}

/// Build URL fetch limits from optional overrides, mirroring the FFI setter and
/// the Python binding. `None` keeps the built in default for each field;
/// `Some(0)` for `max_url_redirects` forbids redirects.
fn url_fetch_limits(
    max_bytes: Option<u32>,
    timeout_ms: Option<u32>,
    max_redirects: Option<u32>,
) -> agent_control_specification_core::Limits {
    let mut limits = agent_control_specification_core::Limits::default();
    if let Some(bytes) = max_bytes {
        limits.max_manifest_url_bytes = bytes as usize;
    }
    if let Some(timeout) = timeout_ms {
        limits.manifest_url_timeout_ms = timeout as u64;
    }
    if let Some(redirects) = max_redirects {
        limits.max_manifest_url_redirects = redirects as usize;
    }
    limits
}

struct JsAnnotatorDispatcher(ThreadsafeFunction<String, ErrorStrategy::CalleeHandled>);

fn js_annotation_error(detail: String) -> RuntimeError {
    if detail.contains(agent_control_specification_core::reserved_reason::ANNOTATION_TIMEOUT) {
        RuntimeError::AnnotationTimeout("annotation dispatcher timed out".to_string())
    } else {
        RuntimeError::AnnotationFailed("annotation dispatcher failed".to_string())
    }
}

impl AnnotatorDispatcher for JsAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> std::result::Result<JsonValue, RuntimeError> {
        let envelope = json!({
            "annotator_name": annotator_name,
            "annotator": annotator,
            "preliminary_policy_input": preliminary_policy_input,
        });
        let payload = serde_json::to_string(&envelope)
            .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
        let returned = call_tsfn_blocking(&self.0, payload).map_err(js_annotation_error)?;
        serde_json::from_str(&returned)
            .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))
    }
}

struct JsPolicyDispatcher(ThreadsafeFunction<String, ErrorStrategy::CalleeHandled>);

impl PolicyDispatcher for JsPolicyDispatcher {
    fn evaluate(
        &self,
        invocation: &PreparedPolicyInvocation,
    ) -> std::result::Result<JsonValue, RuntimeError> {
        let envelope = json!({ "invocation": invocation });
        let payload = serde_json::to_string(&envelope)
            .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))?;
        let returned =
            call_tsfn_blocking(&self.0, payload).map_err(RuntimeError::PolicyInvocationFailed)?;
        serde_json::from_str(&returned)
            .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))
    }
}

enum ParsedRequest {
    Request(InterventionPointRequest),
    RuntimeError(RuntimeError),
    RequestInvalid,
}

fn parse_request(request: Value) -> ParsedRequest {
    let Some(object) = request.as_object() else {
        return ParsedRequest::RequestInvalid;
    };
    let Some(intervention_point) = object.get("intervention_point").and_then(Value::as_str) else {
        return ParsedRequest::RequestInvalid;
    };
    let intervention_point = match InterventionPoint::from_str(intervention_point) {
        Ok(value) => value,
        Err(_) => {
            return ParsedRequest::RuntimeError(RuntimeError::InterventionPointUnknown(
                intervention_point.to_string(),
            ));
        }
    };
    let Some(snapshot) = object.get("snapshot").cloned() else {
        return ParsedRequest::RequestInvalid;
    };
    if !snapshot.is_object() {
        return ParsedRequest::RequestInvalid;
    }
    let mode = match object.get("mode") {
        None => EnforcementMode::Enforce,
        Some(Value::String(value)) => match EnforcementMode::from_str(value) {
            Ok(mode) => mode,
            Err(_) => return ParsedRequest::RequestInvalid,
        },
        Some(_) => return ParsedRequest::RequestInvalid,
    };
    ParsedRequest::Request(InterventionPointRequest {
        intervention_point,
        snapshot,
        mode,
    })
}

fn result_to_value(
    result: agent_control_specification_core::InterventionPointResult,
) -> Result<Value> {
    let verdict = serde_json::to_value(result.verdict)
        .map_err(|err| Error::from_reason(format!("serialize verdict: {err}")))?;
    // AGT D1.4: surface both `input_identity` and `enforced_identity`
    // alongside the back-compat `action_identity` alias so the Node
    // SDK can persist what the policy saw and what the host enforced.
    // AGT D1 + D2: `verdict.transform` and `verdict.evidence` already
    // serialize via serde on the Verdict struct above and ride through
    // this response verbatim.
    Ok(json!({
        "verdict": verdict,
        "transformed_policy_target": result.transformed_policy_target,
        "transformed_policy_target_applied": result.transformed_policy_target.is_some(),
        "policy_input": result.policy_input,
        "action_identity": result.action_identity,
        "input_identity": result.input_identity,
        "enforced_identity": result.enforced_identity,
    }))
}

fn runtime_error_value(error: RuntimeError) -> Result<Value> {
    result_to_value(InterventionPointResult {
        verdict: Verdict::runtime_error(&error),
        transformed_policy_target: None,
        policy_input: None,
        action_identity: None,
        input_identity: None,
        enforced_identity: None,
    })
}

fn request_invalid_value() -> Result<Value> {
    result_to_value(InterventionPointResult {
        verdict: Verdict {
            decision: Decision::Deny,
            reason: Some("runtime_error:request_invalid".to_string()),
            message: Some("Request blocked by Agent Control Specification.".to_string()),
            transform: None,
            evidence: None,
            result_labels: Vec::new(),
        },
        transformed_policy_target: None,
        policy_input: None,
        action_identity: None,
        input_identity: None,
        enforced_identity: None,
    })
}

#[napi]
pub struct NativeRuntime {
    runtime: Runtime,
}

#[napi]
impl NativeRuntime {
    #[napi(constructor)]
    pub fn new(
        env: Env,
        manifest: String,
        annotator_callback: Option<JsFunction>,
        policy_callback: Option<JsFunction>,
        perf_telemetry: Option<u8>,
    ) -> Result<Self> {
        let manifest = Manifest::from_yaml_str(&manifest)
            .map_err(|err| Error::from_reason(err.to_string()))?;
        Self::from_manifest(
            env,
            manifest,
            annotator_callback,
            policy_callback,
            perf_telemetry,
            agent_control_specification_core::Limits::default(),
        )
    }

    #[napi(factory)]
    pub fn from_path(
        env: Env,
        path: String,
        annotator_callback: Option<JsFunction>,
        policy_callback: Option<JsFunction>,
        perf_telemetry: Option<u8>,
    ) -> Result<Self> {
        let manifest = Manifest::from_path(std::path::Path::new(&path))
            .map_err(|err| Error::from_reason(err.to_string()))?;
        Self::from_manifest(
            env,
            manifest,
            annotator_callback,
            policy_callback,
            perf_telemetry,
            agent_control_specification_core::Limits::default(),
        )
    }

    #[napi(factory)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_url(
        env: Env,
        url: String,
        sha256: Option<String>,
        annotator_callback: Option<JsFunction>,
        policy_callback: Option<JsFunction>,
        perf_telemetry: Option<u8>,
        max_url_bytes: Option<u32>,
        url_timeout_ms: Option<u32>,
        max_url_redirects: Option<u32>,
    ) -> Result<Self> {
        let manifest = Manifest::from_url(&url, sha256.as_deref())
            .map_err(|err| Error::from_reason(err.to_string()))?;
        let limits = url_fetch_limits(max_url_bytes, url_timeout_ms, max_url_redirects);
        Self::from_manifest(
            env,
            manifest,
            annotator_callback,
            policy_callback,
            perf_telemetry,
            limits,
        )
    }

    #[napi(factory)]
    pub fn from_manifest_chain(
        env: Env,
        manifests: Vec<String>,
        annotator_callback: Option<JsFunction>,
        policy_callback: Option<JsFunction>,
        perf_telemetry: Option<u8>,
    ) -> Result<Self> {
        let refs: Vec<&str> = manifests.iter().map(String::as_str).collect();
        let manifest =
            Manifest::from_yaml_chain(&refs).map_err(|err| Error::from_reason(err.to_string()))?;
        Self::from_manifest(
            env,
            manifest,
            annotator_callback,
            policy_callback,
            perf_telemetry,
            agent_control_specification_core::Limits::default(),
        )
    }

    fn from_manifest(
        env: Env,
        manifest: Manifest,
        annotator_callback: Option<JsFunction>,
        policy_callback: Option<JsFunction>,
        perf_telemetry: Option<u8>,
        limits: agent_control_specification_core::Limits,
    ) -> Result<Self> {
        let annotations: Arc<dyn AnnotatorDispatcher> = match annotator_callback {
            Some(callback) => Arc::new(JsAnnotatorDispatcher(make_string_tsfn(&env, callback)?)),
            None => {
                agent_control_specification_core::dispatchers::default_annotator_dispatcher_for(
                    &manifest, limits,
                )
            }
        };
        let policy: Arc<dyn PolicyDispatcher> = match policy_callback {
            Some(callback) => Arc::new(JsPolicyDispatcher(make_string_tsfn(&env, callback)?)),
            None => {
                agent_control_specification_core::dispatchers::default_policy_dispatcher_with_limits(
                    &manifest, limits,
                )
                .map_err(|err| Error::from_reason(err.to_string()))?
            }
        };
        let perf_telemetry = PerfTelemetry::from_u8(perf_telemetry.unwrap_or(0))
            .ok_or_else(|| Error::from_reason("perf_telemetry must be 0, 1, or 2"))?;
        let runtime = Runtime::with_perf_telemetry(manifest, annotations, policy, perf_telemetry)
            .map_err(|err| Error::from_reason(err.to_string()))?;
        Ok(Self { runtime })
    }

    #[napi]
    pub async fn evaluate(&self, request: Value) -> Result<Value> {
        let request = match parse_request(request) {
            ParsedRequest::Request(request) => request,
            ParsedRequest::RuntimeError(error) => return runtime_error_value(error),
            ParsedRequest::RequestInvalid => return request_invalid_value(),
        };
        let runtime = self.runtime.clone();
        let result =
            tokio::task::spawn_blocking(move || runtime.evaluate_intervention_point(request))
                .await
                .map_err(|err| Error::from_reason(format!("evaluate: join: {err}")))?;
        result_to_value(result)
    }
}
