// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{
    manifest::parse_manifest_yaml_value, opa::OpaRegoRunner, JsonValue, Manifest, RuntimeError,
};
use jsonschema::JSONSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MANIFEST_SCHEMA: &str = include_str!("../schema/manifest.schema.json");
const APPROVAL_SCHEMA: &str = include_str!("../schema/approval.schema.json");
const APPROVAL_SCHEMA_ID: &str = "https://agent-control-specification.test/approval.schema.json";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REGO_BYTES: usize = 1_048_576;
const MAX_REGO_MODULES: usize = 64;
const MAX_DIAGNOSTICS: usize = 100;
const MAX_DIAGNOSTIC_TEXT: usize = 4096;
const MAX_SOURCE_LABEL: usize = 512;
const MAX_OPA_OUTPUT_BYTES: usize = 65_536;

/// One structured validation failure from the manifest or a Rego module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationDiagnostic {
    pub component: String,
    pub code: String,
    pub message: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

impl ValidationDiagnostic {
    fn new(component: &str, code: &str, message: impl Into<String>, source: &str) -> Self {
        Self {
            component: component.to_string(),
            code: code.to_string(),
            message: truncate(message.into(), MAX_DIAGNOSTIC_TEXT),
            source: truncate(source.to_string(), MAX_SOURCE_LABEL),
            path: None,
            line: None,
            column: None,
            snippet: None,
        }
    }

    fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(truncate(path.into(), MAX_DIAGNOSTIC_TEXT));
        self
    }
}

/// The bounded validation outcome shared by every language SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactValidationResult {
    pub valid: bool,
    pub diagnostics: Vec<ValidationDiagnostic>,
}

impl ArtifactValidationResult {
    fn from_diagnostics(mut diagnostics: Vec<ValidationDiagnostic>) -> Self {
        if diagnostics.len() > MAX_DIAGNOSTICS {
            diagnostics.truncate(MAX_DIAGNOSTICS);
            diagnostics.push(ValidationDiagnostic::new(
                "validation",
                "validation_diagnostics_truncated",
                format!("Additional diagnostics were omitted after the first {MAX_DIAGNOSTICS}."),
                "validation",
            ));
        }
        Self {
            valid: diagnostics.is_empty(),
            diagnostics,
        }
    }
}

/// Validates ACS manifest text and supplied Rego modules without constructing a runtime.
pub fn validate_acs_artifacts(
    manifest: &str,
    rego_modules: &BTreeMap<String, String>,
    opa_path: Option<&Path>,
) -> ArtifactValidationResult {
    let (parsed, mut diagnostics) = validate_manifest_source(manifest);
    let modules = validate_rego_inputs(rego_modules, &mut diagnostics);
    if parsed.as_ref().is_some_and(manifest_declares_rego)
        && modules.is_empty()
        && rego_modules.is_empty()
    {
        diagnostics.push(ValidationDiagnostic::new(
            "rego",
            "rego_missing",
            "The manifest declares a Rego policy but no Rego module was supplied.",
            "rego",
        ));
    }
    if !modules.is_empty() {
        diagnostics.extend(validate_rego_modules(&modules, opa_path));
    }

    ArtifactValidationResult::from_diagnostics(diagnostics)
}

/// Validates ACS manifest text without requiring Rego policy sources.
pub fn validate_acs_manifest(manifest: &str) -> ArtifactValidationResult {
    let (_, diagnostics) = validate_manifest_source(manifest);
    ArtifactValidationResult::from_diagnostics(diagnostics)
}

fn validate_manifest_source(manifest: &str) -> (Option<JsonValue>, Vec<ValidationDiagnostic>) {
    let mut diagnostics = Vec::new();
    let parsed = match parse_manifest_yaml_value(manifest) {
        Ok(value) => Some(value),
        Err(error) => {
            diagnostics.push(runtime_diagnostic(
                "manifest",
                "manifest_parse_error",
                error,
            ));
            None
        }
    };

    if let Some(parsed) = parsed.as_ref() {
        if !parsed.is_object() {
            diagnostics.push(
                ValidationDiagnostic::new(
                    "manifest",
                    "manifest_root_invalid",
                    "Manifest must decode to a YAML or JSON object.",
                    "manifest",
                )
                .with_path("$"),
            );
        } else {
            let schema_diagnostics = validate_schema(parsed);
            let schema_valid = schema_diagnostics.is_empty();
            diagnostics.extend(schema_diagnostics);
            if schema_valid {
                if let Err(error) = validate_typed_manifest(parsed.clone(), has_extends(parsed)) {
                    diagnostics.push(runtime_diagnostic(
                        "manifest",
                        "manifest_semantic_error",
                        error,
                    ));
                }
            }
        }
    }
    (parsed, diagnostics)
}

fn validate_schema(instance: &JsonValue) -> Vec<ValidationDiagnostic> {
    let schema: JsonValue = match serde_json::from_str(MANIFEST_SCHEMA) {
        Ok(value) => value,
        Err(error) => {
            return vec![ValidationDiagnostic::new(
                "validation",
                "validation_internal_error",
                format!("Failed to parse embedded manifest schema: {error}"),
                "manifest.schema.json",
            )];
        }
    };
    let approval: JsonValue = match serde_json::from_str(APPROVAL_SCHEMA) {
        Ok(value) => value,
        Err(error) => {
            return vec![ValidationDiagnostic::new(
                "validation",
                "validation_internal_error",
                format!("Failed to parse embedded approval schema: {error}"),
                "approval.schema.json",
            )];
        }
    };
    let mut options = JSONSchema::options();
    options.with_document(APPROVAL_SCHEMA_ID.to_string(), approval);
    let compiled = match options.compile(&schema) {
        Ok(compiled) => compiled,
        Err(error) => {
            return vec![ValidationDiagnostic::new(
                "validation",
                "validation_internal_error",
                format!("Failed to compile embedded manifest schema: {error}"),
                "manifest.schema.json",
            )];
        }
    };
    let mut diagnostics = Vec::new();
    if let Err(errors) = compiled.validate(instance) {
        for error in errors.take(MAX_DIAGNOSTICS + 1) {
            diagnostics.push(
                ValidationDiagnostic::new(
                    "manifest",
                    "manifest_schema_error",
                    error.to_string(),
                    "manifest",
                )
                .with_path(error.instance_path.to_string()),
            );
        }
    }
    diagnostics
}

fn validate_typed_manifest(value: JsonValue, overlay: bool) -> Result<(), RuntimeError> {
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|error| RuntimeError::ManifestInvalid(error.to_string()))?;
    if overlay {
        manifest.validate_overlay()
    } else {
        manifest.validate()
    }
}

fn has_extends(value: &JsonValue) -> bool {
    value
        .get("extends")
        .and_then(JsonValue::as_array)
        .is_some_and(|extends| !extends.is_empty())
}

fn manifest_declares_rego(value: &JsonValue) -> bool {
    value
        .get("policies")
        .and_then(JsonValue::as_object)
        .is_some_and(|policies| {
            policies
                .values()
                .any(|policy| policy.get("type").and_then(JsonValue::as_str) == Some("rego"))
        })
}

fn validate_rego_inputs(
    modules: &BTreeMap<String, String>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) -> Vec<(String, String)> {
    if modules.len() > MAX_REGO_MODULES {
        diagnostics.push(ValidationDiagnostic::new(
            "rego",
            "rego_module_limit_exceeded",
            format!(
                "Received {} Rego modules, exceeding the limit of {MAX_REGO_MODULES}.",
                modules.len()
            ),
            "rego",
        ));
        return Vec::new();
    }
    let mut total = 0usize;
    let mut valid = Vec::new();
    for (source, contents) in modules {
        if source.trim().is_empty() || source.len() > MAX_SOURCE_LABEL {
            diagnostics.push(ValidationDiagnostic::new(
                "rego",
                "rego_source_invalid",
                "Each Rego module must have a non-empty bounded source name.",
                source,
            ));
            continue;
        }
        total = total.saturating_add(contents.len());
        if total > MAX_REGO_BYTES {
            diagnostics.push(ValidationDiagnostic::new(
                "rego",
                "rego_size_exceeded",
                format!("Rego modules exceed the {MAX_REGO_BYTES}-byte total validation limit."),
                "rego",
            ));
            return Vec::new();
        }
        if contents.trim().is_empty() {
            diagnostics.push(ValidationDiagnostic::new(
                "rego",
                "rego_empty",
                "Rego module must not be empty.",
                source,
            ));
            continue;
        }
        valid.push((source.clone(), contents.clone()));
    }
    valid
}

fn validate_rego_modules(
    modules: &[(String, String)],
    opa_path: Option<&Path>,
) -> Vec<ValidationDiagnostic> {
    validate_rego_modules_with_timeout(modules, opa_path, DEFAULT_TIMEOUT)
}

fn validate_rego_modules_with_timeout(
    modules: &[(String, String)],
    opa_path: Option<&Path>,
    timeout: Duration,
) -> Vec<ValidationDiagnostic> {
    let deadline = Instant::now() + timeout;
    let executable = opa_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| OpaRegoRunner::from_environment().executable().to_path_buf());
    if let Some(error) = validate_opa_executable(&executable, deadline) {
        return vec![error];
    }

    let temp = match ValidationTempDir::new() {
        Ok(temp) => temp,
        Err(error) => {
            return vec![ValidationDiagnostic::new(
                "rego",
                "rego_staging_error",
                format!("Could not create temporary storage for OPA validation: {error}"),
                "rego",
            )];
        }
    };
    let mut diagnostics = Vec::new();
    for (index, (source, contents)) in modules.iter().enumerate() {
        let path = temp.path().join(format!("module-{index:04}.rego"));
        if let Err(error) = fs::write(&path, contents) {
            diagnostics.push(ValidationDiagnostic::new(
                "rego",
                "rego_staging_error",
                format!("Could not stage Rego module: {error}"),
                source,
            ));
            continue;
        }
        let Some(timeout) = deadline.checked_duration_since(Instant::now()) else {
            diagnostics.push(ValidationDiagnostic::new(
                "rego",
                "opa_timeout",
                "OPA validation exceeded the total timeout.",
                source,
            ));
            break;
        };
        match run_opa(
            &executable,
            &["parse", path.to_string_lossy().as_ref(), "--format=json"],
            timeout,
        ) {
            Ok(output) if output.status.success() => {}
            Ok(output) => diagnostics.extend(opa_diagnostics(&output, &path, source)),
            Err(error) => diagnostics.push(opa_error_diagnostic(error, source)),
        }
        if diagnostics.len() > MAX_DIAGNOSTICS {
            break;
        }
    }
    diagnostics
}

fn validate_opa_executable(executable: &Path, deadline: Instant) -> Option<ValidationDiagnostic> {
    let Some(timeout) = deadline.checked_duration_since(Instant::now()) else {
        return Some(ValidationDiagnostic::new(
            "rego",
            "opa_timeout",
            "OPA validation exceeded the total timeout.",
            "opa",
        ));
    };
    match run_opa(executable, &["version"], timeout) {
        Ok(output)
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .trim_start()
                    .starts_with("Version:") =>
        {
            None
        }
        Ok(output) => Some(ValidationDiagnostic::new(
            "rego",
            "opa_invalid_executable",
            format!(
                "Configured OPA executable did not return the expected version banner. {}",
                output_detail(&output)
            ),
            "opa",
        )),
        Err(error) => Some(opa_error_diagnostic(error, "opa")),
    }
}

fn run_opa(executable: &Path, args: &[&str], timeout: Duration) -> std::io::Result<Output> {
    let temp = ValidationTempDir::new()?;
    let mut stdout = output_file(&temp.path().join("stdout"))?;
    let mut stderr = output_file(&temp.path().join("stderr"))?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    let mut child = command.spawn()?;
    let status = wait_for_exit_or_timeout(&mut child, timeout)?;
    let stdout = read_bounded(&mut stdout)?;
    let stderr = read_bounded(&mut stderr)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn opa_error_diagnostic(error: std::io::Error, source: &str) -> ValidationDiagnostic {
    let code = if error.kind() == std::io::ErrorKind::TimedOut {
        "opa_timeout"
    } else {
        "opa_execution_error"
    };
    ValidationDiagnostic::new(
        "rego",
        code,
        format!("OPA validation failed: {error}"),
        source,
    )
}

fn output_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
}

fn read_bounded(file: &mut File) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take((MAX_OPA_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OPA_OUTPUT_BYTES {
        bytes.truncate(MAX_OPA_OUTPUT_BYTES);
        bytes.extend_from_slice(b"...");
    }
    Ok(bytes)
}

fn wait_for_exit_or_timeout(child: &mut Child, timeout: Duration) -> std::io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "OPA validation exceeded timeout of {} ms",
                    timeout.as_millis()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Debug, Deserialize)]
struct OpaErrorEnvelope {
    #[serde(default)]
    errors: Vec<OpaError>,
}

#[derive(Debug, Deserialize)]
struct OpaError {
    message: Option<String>,
    code: Option<String>,
    location: Option<OpaLocation>,
    details: Option<OpaDetails>,
}

#[derive(Debug, Deserialize)]
struct OpaLocation {
    row: Option<u64>,
    col: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OpaDetails {
    line: Option<String>,
}

fn opa_diagnostics(output: &Output, path: &Path, source: &str) -> Vec<ValidationDiagnostic> {
    for candidate in [&output.stderr, &output.stdout] {
        if let Ok(envelope) = serde_json::from_slice::<OpaErrorEnvelope>(candidate) {
            if !envelope.errors.is_empty() {
                return envelope
                    .errors
                    .into_iter()
                    .map(|error| ValidationDiagnostic {
                        component: "rego".to_string(),
                        code: error
                            .code
                            .unwrap_or_else(|| "rego_validation_error".to_string()),
                        message: truncate(
                            error
                                .message
                                .unwrap_or_else(|| "OPA rejected the Rego module.".to_string())
                                .replace(&path.to_string_lossy().to_string(), source),
                            MAX_DIAGNOSTIC_TEXT,
                        ),
                        source: truncate(source.to_string(), MAX_SOURCE_LABEL),
                        path: None,
                        line: error.location.as_ref().and_then(|location| location.row),
                        column: error.location.as_ref().and_then(|location| location.col),
                        snippet: error
                            .details
                            .and_then(|details| details.line)
                            .map(|line| truncate(line, MAX_DIAGNOSTIC_TEXT)),
                    })
                    .collect();
            }
        }
    }
    vec![ValidationDiagnostic::new(
        "rego",
        "opa_validation_error",
        output_detail(output),
        source,
    )]
}

fn output_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    truncate(
        if stderr.is_empty() { stdout } else { stderr },
        MAX_DIAGNOSTIC_TEXT,
    )
}

fn runtime_diagnostic(
    component: &str,
    default_code: &str,
    error: RuntimeError,
) -> ValidationDiagnostic {
    let code = match error {
        RuntimeError::ResourceLimitExceeded(_) => "manifest_resource_limit",
        _ => default_code,
    };
    ValidationDiagnostic::new(component, code, error.to_string(), component)
}

fn truncate(value: String, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value;
    }
    value.chars().take(limit).collect::<String>() + "..."
}

struct ValidationTempDir {
    path: PathBuf,
}

impl ValidationTempDir {
    fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = env::temp_dir().join(format!(
            "acs-artifact-validation-{}-{nanos}-{count}",
            std::process::id()
        ));
        crate::opa::create_private_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ValidationTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn valid_manifest() -> &'static str {
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: rego
    query: data.p.verdict
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: p
"#
    }

    #[test]
    fn packaged_schemas_match_canonical_spec() {
        let spec = Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/schema");
        assert_eq!(
            MANIFEST_SCHEMA.as_bytes(),
            fs::read(spec.join("manifest.schema.json")).unwrap()
        );
        assert_eq!(
            APPROVAL_SCHEMA.as_bytes(),
            fs::read(spec.join("approval.schema.json")).unwrap()
        );
    }

    #[test]
    fn validates_manifest_and_rego_with_structured_diagnostics() {
        let runner = OpaRegoRunner::from_environment();
        if !runner.is_available() {
            return;
        }
        let modules = BTreeMap::from([(
            "policy.rego".to_string(),
            "package p\nimport rego.v1\ndefault verdict := {\"decision\": \"allow\"}\n".to_string(),
        )]);

        let result = validate_acs_artifacts(valid_manifest(), &modules, None);
        assert!(result.valid, "{:?}", result.diagnostics);
    }

    #[test]
    fn reports_schema_and_rego_parse_errors_together() {
        let runner = OpaRegoRunner::from_environment();
        if !runner.is_available() {
            return;
        }
        let modules = BTreeMap::from([(
            "bad.rego".to_string(),
            "package p\nallow if { value := }\n".to_string(),
        )]);

        let result = validate_acs_artifacts("metadata: []\n", &modules, None);
        assert!(!result.valid);
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "manifest_schema_error"));
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "rego_parse_error"));
    }

    #[test]
    fn validates_partial_manifest_version_without_requiring_resolution() {
        let result = validate_acs_artifacts(
            "agent_control_specification_version: banana\nextends: [base.yaml]\n",
            &BTreeMap::new(),
            None,
        );
        assert!(!result.valid);
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "manifest_semantic_error"));
    }

    #[test]
    fn manifest_schema_preserves_extends_composition_contract() {
        let valid = [
            r#"agent_control_specification_version: 0.3.1-beta
metadata:
  name: composition-root
extends:
  - layers/base.yaml
  - url: https://example.test/remote.yaml
    sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
            r#"agent_control_specification_version: 0.3.1-beta
extends:
  - base/manifest.yaml
annotators:
  overlay:
    type: classifier
intervention_points:
  input:
    annotations:
      overlay:
        from: $policy_target.text
"#,
        ];
        for manifest in valid {
            let result = validate_acs_manifest(manifest);
            assert!(result.valid, "{:?}", result.diagnostics);
        }

        let invalid = [
            "agent_control_specification_version: 0.3.1-beta\n",
            "agent_control_specification_version: 0.3.1-beta\nextends: [http://example.test/base.yaml]\n",
            r#"agent_control_specification_version: 0.3.1-beta
extends:
  - url: https://example.test/base.yaml
    integrity: sha256-abc
    sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
            r#"agent_control_specification_version: 0.3.1-beta
extends:
  - base/manifest.yaml
annotators:
  overlay:
    type: classifier
intervention_points:
  input:
    annotations:
      review_signal:
        from: $policy_target.text
        annotator: overlay
"#,
        ];
        for manifest in invalid {
            let result = validate_acs_manifest(manifest);
            assert!(!result.valid, "{manifest}");
            assert!(result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "manifest_schema_error"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn applies_one_timeout_budget_across_all_rego_modules() {
        let script = validation_script(
            r#"#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Version: 0.70.0"
  exit 0
fi
sleep 0.08
exit 0
"#,
        );
        let modules = vec![
            ("one.rego".to_string(), "package one".to_string()),
            ("two.rego".to_string(), "package two".to_string()),
        ];
        let started = Instant::now();
        let diagnostics = validate_rego_modules_with_timeout(
            &modules,
            Some(&script.path),
            Duration::from_millis(120),
        );

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "opa_timeout"));
    }

    #[cfg(unix)]
    #[test]
    fn bounds_opa_diagnostic_output_before_loading_it() {
        let script = validation_script(
            r#"#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Version: 0.70.0"
  exit 0
fi
yes x | head -c 1000000 >&2
exit 1
"#,
        );
        let modules = vec![("bad.rego".to_string(), "package bad".to_string())];
        let diagnostics = validate_rego_modules_with_timeout(
            &modules,
            Some(&script.path),
            Duration::from_secs(2),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.len() <= MAX_DIAGNOSTIC_TEXT + 3);
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_validation_directories() {
        let temp = ValidationTempDir::new().unwrap();
        let mode = fs::metadata(temp.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[cfg(unix)]
    fn validation_script(contents: &str) -> ValidationScript {
        let temp = ValidationTempDir::new().unwrap();
        let path = temp.path().join("fake-opa");
        fs::write(&path, contents).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        ValidationScript { _temp: temp, path }
    }

    #[cfg(unix)]
    struct ValidationScript {
        _temp: ValidationTempDir,
        path: PathBuf,
    }
}
