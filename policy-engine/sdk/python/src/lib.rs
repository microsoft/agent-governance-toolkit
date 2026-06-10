use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, EnforcementMode, InterventionPoint,
    InterventionPointRequest, InterventionPointResult, JsonValue, Manifest, PerfTelemetry,
    PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError, Verdict,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

fn json_value_to_py(py: Python<'_>, val: &JsonValue) -> PyResult<Py<PyAny>> {
    Ok(match val {
        JsonValue::Null => py.None(),
        JsonValue::Bool(b) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.to_owned().into_any().unbind()
            } else if let Some(u) = n.as_u64() {
                u.into_pyobject(py)?.to_owned().into_any().unbind()
            } else if let Some(f) = n.as_f64() {
                f.into_pyobject(py)?.to_owned().into_any().unbind()
            } else {
                py.None()
            }
        }
        JsonValue::String(s) => s.into_pyobject(py)?.into_any().unbind(),
        JsonValue::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_value_to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        JsonValue::Object(map) => {
            let dict = PyDict::new(py);
            for (key, value) in map {
                dict.set_item(key, json_value_to_py(py, value)?)?;
            }
            dict.into_any().unbind()
        }
    })
}

fn py_to_json_value(obj: &Bound<'_, PyAny>) -> PyResult<JsonValue> {
    if obj.is_none() {
        Ok(JsonValue::Null)
    } else if let Ok(value) = obj.extract::<bool>() {
        Ok(JsonValue::Bool(value))
    } else if let Ok(value) = obj.extract::<i64>() {
        Ok(JsonValue::Number(value.into()))
    } else if let Ok(value) = obj.extract::<u64>() {
        Ok(JsonValue::Number(value.into()))
    } else if let Ok(value) = obj.extract::<f64>() {
        Ok(serde_json::json!(value))
    } else if let Ok(value) = obj.extract::<String>() {
        Ok(JsonValue::String(value))
    } else if let Ok(list) = obj.cast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(py_to_json_value(&item)?);
        }
        Ok(JsonValue::Array(arr))
    } else if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict.iter() {
            map.insert(key.extract()?, py_to_json_value(&value)?);
        }
        Ok(JsonValue::Object(map))
    } else {
        Ok(JsonValue::String(obj.str()?.to_string()))
    }
}

fn runtime_error(error: RuntimeError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn annotation_error(error: PyErr) -> RuntimeError {
    let detail = error.to_string();
    if detail.contains(agent_control_specification_core::reserved_reason::ANNOTATION_TIMEOUT) {
        RuntimeError::AnnotationTimeout("annotation dispatcher timed out".to_string())
    } else {
        RuntimeError::AnnotationFailed("annotation dispatcher failed".to_string())
    }
}

fn result_to_py(py: Python<'_>, result: InterventionPointResult) -> PyResult<Py<PyAny>> {
    let output = PyDict::new(py);
    let verdict = serde_json::to_value(&result.verdict)
        .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
    output.set_item("verdict", json_value_to_py(py, &verdict)?)?;
    output.set_item(
        "transformed_policy_target_applied",
        result.transformed_policy_target.is_some(),
    )?;
    match &result.transformed_policy_target {
        Some(value) => {
            output.set_item("transformed_policy_target", json_value_to_py(py, value)?)?
        }
        None => output.set_item("transformed_policy_target", py.None())?,
    }
    match &result.policy_input {
        Some(value) => output.set_item("policy_input", json_value_to_py(py, value)?)?,
        None => output.set_item("policy_input", py.None())?,
    }
    match &result.action_identity {
        Some(value) => output.set_item("action_identity", value)?,
        None => output.set_item("action_identity", py.None())?,
    }
    Ok(output.into_any().unbind())
}

fn runtime_error_result(error: RuntimeError) -> InterventionPointResult {
    InterventionPointResult {
        verdict: Verdict::runtime_error(&error),
        transformed_policy_target: None,
        policy_input: None,
        action_identity: None,
        input_identity: None,
        enforced_identity: None,
    }
}

fn request_invalid_result() -> InterventionPointResult {
    InterventionPointResult {
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
    }
}

struct PyAnnotatorDispatcher {
    cb: Py<PyAny>,
}

impl AnnotatorDispatcher for PyAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Python::attach(|py| {
            let annotator_value = serde_json::to_value(annotator)
                .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
            let annotator_py = json_value_to_py(py, &annotator_value)
                .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
            let preliminary_py = json_value_to_py(py, preliminary_policy_input)
                .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))?;
            let returned = self
                .cb
                .call1(py, (annotator_name, annotator_py, preliminary_py))
                .map_err(annotation_error)?;
            py_to_json_value(returned.bind(py))
                .map_err(|err| RuntimeError::AnnotationFailed(err.to_string()))
        })
    }
}

struct PyPolicyDispatcher {
    cb: Py<PyAny>,
}

impl PolicyDispatcher for PyPolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Python::attach(|py| {
            let invocation_value = serde_json::to_value(invocation)
                .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))?;
            let invocation_py = json_value_to_py(py, &invocation_value)
                .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))?;
            let returned = self
                .cb
                .call1(py, (invocation_py,))
                .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))?;
            py_to_json_value(returned.bind(py))
                .map_err(|err| RuntimeError::PolicyInvocationFailed(err.to_string()))
        })
    }
}

#[pyclass]
struct NativeRuntime {
    runtime: Runtime,
}

#[pymethods]
impl NativeRuntime {
    #[new]
    #[pyo3(signature = (manifest, annotator_cb = None, policy_cb = None, perf_telemetry = 0))]
    fn new(
        manifest: String,
        annotator_cb: Option<Py<PyAny>>,
        policy_cb: Option<Py<PyAny>>,
        perf_telemetry: u8,
    ) -> PyResult<Self> {
        let manifest = Manifest::from_yaml_str(&manifest).map_err(runtime_error)?;
        Self::from_manifest(manifest, annotator_cb, policy_cb, perf_telemetry)
    }

    #[staticmethod]
    #[pyo3(signature = (path, annotator_cb = None, policy_cb = None, perf_telemetry = 0))]
    fn from_path(
        path: String,
        annotator_cb: Option<Py<PyAny>>,
        policy_cb: Option<Py<PyAny>>,
        perf_telemetry: u8,
    ) -> PyResult<Self> {
        let manifest = Manifest::from_path(Path::new(&path)).map_err(runtime_error)?;
        Self::from_manifest(manifest, annotator_cb, policy_cb, perf_telemetry)
    }

    #[staticmethod]
    #[pyo3(signature = (manifests, annotator_cb = None, policy_cb = None, perf_telemetry = 0))]
    fn from_manifest_chain(
        manifests: Vec<String>,
        annotator_cb: Option<Py<PyAny>>,
        policy_cb: Option<Py<PyAny>>,
        perf_telemetry: u8,
    ) -> PyResult<Self> {
        let refs: Vec<&str> = manifests.iter().map(String::as_str).collect();
        let manifest = Manifest::from_yaml_chain(&refs).map_err(runtime_error)?;
        Self::from_manifest(manifest, annotator_cb, policy_cb, perf_telemetry)
    }

    fn evaluate(&self, py: Python<'_>, request: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let request = match py_to_json_value(request) {
            Ok(value) => value,
            Err(_) => return result_to_py(py, request_invalid_result()),
        };
        let Some(object) = request.as_object() else {
            return result_to_py(py, request_invalid_result());
        };
        let Some(intervention_point) = object.get("intervention_point").and_then(JsonValue::as_str)
        else {
            return result_to_py(py, request_invalid_result());
        };
        let intervention_point = match InterventionPoint::from_str(intervention_point) {
            Ok(value) => value,
            Err(_) => {
                return result_to_py(
                    py,
                    runtime_error_result(RuntimeError::InterventionPointUnknown(
                        intervention_point.to_string(),
                    )),
                );
            }
        };
        let Some(snapshot) = object.get("snapshot").cloned() else {
            return result_to_py(py, request_invalid_result());
        };
        if !snapshot.is_object() {
            return result_to_py(py, request_invalid_result());
        }
        let mode = match object.get("mode") {
            None => EnforcementMode::Enforce,
            Some(JsonValue::String(value)) => match EnforcementMode::from_str(value) {
                Ok(mode) => mode,
                Err(_) => return result_to_py(py, request_invalid_result()),
            },
            Some(_) => return result_to_py(py, request_invalid_result()),
        };
        let request = InterventionPointRequest {
            intervention_point,
            snapshot,
            mode,
        };

        // Release the GIL while the Rust core runs. If the core invokes host
        // dispatchers, those synchronous Python callables re-acquire it with
        // `Python::attach` on the calling thread.
        let result = py.detach(|| self.runtime.evaluate_intervention_point(request));

        result_to_py(py, result)
    }
}

impl NativeRuntime {
    fn from_manifest(
        manifest: Manifest,
        annotator_cb: Option<Py<PyAny>>,
        policy_cb: Option<Py<PyAny>>,
        perf_telemetry: u8,
    ) -> PyResult<Self> {
        let perf_telemetry = PerfTelemetry::from_u8(perf_telemetry)
            .ok_or_else(|| PyValueError::new_err("perf_telemetry must be 0, 1, or 2"))?;
        let annotations: Arc<dyn AnnotatorDispatcher> = match annotator_cb {
            Some(cb) => Arc::new(PyAnnotatorDispatcher { cb }),
            None => agent_control_specification_core::dispatchers::default_annotator_dispatcher(),
        };
        let policy: Arc<dyn PolicyDispatcher> = match policy_cb {
            Some(cb) => Arc::new(PyPolicyDispatcher { cb }),
            None => {
                agent_control_specification_core::dispatchers::default_policy_dispatcher(&manifest)
                    .map_err(runtime_error)?
            }
        };
        let runtime = Runtime::with_perf_telemetry(manifest, annotations, policy, perf_telemetry)
            .map_err(runtime_error)?;
        Ok(Self { runtime })
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeRuntime>()?;
    Ok(())
}
