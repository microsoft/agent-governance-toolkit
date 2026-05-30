use agent_control_specification_core::{
    AnnotatorDispatcher, AnnotatorInvocation, EnforcementMode, InterventionPoint,
    InterventionPointRequest, JsonValue, Manifest, PerfTelemetry, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError,
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
    if detail.contains("runtime_error:annotation_timeout") {
        RuntimeError::AnnotationTimeout(detail)
    } else {
        RuntimeError::AnnotationFailed(detail)
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
        let request = py_to_json_value(request)?;
        let object = request
            .as_object()
            .ok_or_else(|| PyValueError::new_err("request must be a mapping"))?;
        let intervention_point = object
            .get("intervention_point")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| PyValueError::new_err("request.intervention_point is required"))?;
        let intervention_point =
            InterventionPoint::from_str(intervention_point).map_err(PyValueError::new_err)?;
        let snapshot = object
            .get("snapshot")
            .cloned()
            .ok_or_else(|| PyValueError::new_err("request.snapshot is required"))?;
        let mode = object
            .get("mode")
            .and_then(JsonValue::as_str)
            .unwrap_or("enforce");
        let mode = EnforcementMode::from_str(mode).map_err(PyValueError::new_err)?;
        let request = InterventionPointRequest {
            intervention_point,
            snapshot,
            mode,
        };

        // Release the GIL while the Rust core runs. If the core invokes host
        // dispatchers, those synchronous Python callables re-acquire it with
        // `Python::attach` on the calling thread.
        let result = py.detach(|| self.runtime.evaluate_intervention_point(request));

        let output = PyDict::new(py);
        let verdict = serde_json::to_value(&result.verdict)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        output.set_item("verdict", json_value_to_py(py, &verdict)?)?;
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
