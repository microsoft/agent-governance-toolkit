use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, PerfTelemetry, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError,
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

struct JsAnnotatorDispatcher(ThreadsafeFunction<String, ErrorStrategy::CalleeHandled>);

fn js_annotation_error(detail: String) -> RuntimeError {
    if detail.contains("runtime_error:annotation_timeout") {
        RuntimeError::AnnotationTimeout(detail)
    } else {
        RuntimeError::AnnotationFailed(detail)
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

fn parse_request(request: Value) -> Result<InterventionPointRequest> {
    let object = request
        .as_object()
        .ok_or_else(|| Error::from_reason("request must be an object"))?;
    let intervention_point = object
        .get("intervention_point")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::from_reason("request.intervention_point is required"))?;
    let intervention_point =
        InterventionPoint::from_str(intervention_point).map_err(Error::from_reason)?;
    let snapshot = object
        .get("snapshot")
        .cloned()
        .ok_or_else(|| Error::from_reason("request.snapshot is required"))?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("enforce");
    let mode = EnforcementMode::from_str(mode).map_err(Error::from_reason)?;
    Ok(InterventionPointRequest {
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
    Ok(json!({
        "verdict": verdict,
        "transformed_policy_target": result.transformed_policy_target,
        "policy_input": result.policy_input,
        "action_identity": result.action_identity,
    }))
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
        )
    }

    fn from_manifest(
        env: Env,
        manifest: Manifest,
        annotator_callback: Option<JsFunction>,
        policy_callback: Option<JsFunction>,
        perf_telemetry: Option<u8>,
    ) -> Result<Self> {
        let annotations: Arc<dyn AnnotatorDispatcher> = match annotator_callback {
            Some(callback) => Arc::new(JsAnnotatorDispatcher(make_string_tsfn(&env, callback)?)),
            None => agent_control_specification_core::dispatchers::default_annotator_dispatcher(),
        };
        let policy: Arc<dyn PolicyDispatcher> = match policy_callback {
            Some(callback) => Arc::new(JsPolicyDispatcher(make_string_tsfn(&env, callback)?)),
            None => {
                agent_control_specification_core::dispatchers::default_policy_dispatcher(&manifest)
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
        let request = parse_request(request)?;
        let runtime = self.runtime.clone();
        let result =
            tokio::task::spawn_blocking(move || runtime.evaluate_intervention_point(request))
                .await
                .map_err(|err| Error::from_reason(format!("evaluate: join: {err}")))?;
        result_to_value(result)
    }
}
