use crate::{
    runtime::PolicyDispatcher, JsonValue, Limits, PreparedPolicyInvocation, RegoPolicyInvocation,
    RuntimeError,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

pub const OPA_PATH_ENV: &str = "ACS_OPA_PATH";
pub const OPA_TIMEOUT_ENV: &str = "ACS_OPA_TIMEOUT_MS";
const DEFAULT_OPA_TIMEOUT: Duration = Duration::from_secs(5);
const OPA_DATA_KEYS: [&str; 2] = ["data", "data_paths"];
const ERROR_OUTPUT_LIMIT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaRegoRunner {
    executable: PathBuf,
    data_paths: Vec<PathBuf>,
    eval_timeout: Duration,
    limits: Limits,
}

impl OpaRegoRunner {
    pub fn new() -> Self {
        Self {
            executable: PathBuf::from("opa"),
            data_paths: Vec::new(),
            eval_timeout: DEFAULT_OPA_TIMEOUT,
            limits: Limits::default(),
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn from_environment() -> Self {
        let mut runner = match env::var_os(OPA_PATH_ENV) {
            Some(value) if !value.is_empty() => {
                Self::new().with_executable(Self::resolve_opa_executable_hint(PathBuf::from(value)))
            }
            _ => Self::new(),
        };
        if let Some(timeout) = eval_timeout_from_environment() {
            runner = runner.with_eval_timeout(timeout);
        }
        runner
    }

    pub fn with_executable(mut self, executable: impl Into<PathBuf>) -> Self {
        self.executable = executable.into();
        self
    }

    pub fn with_eval_timeout(mut self, timeout: Duration) -> Self {
        self.eval_timeout = timeout;
        self
    }

    pub fn eval_timeout(&self) -> Duration {
        self.eval_timeout
    }

    fn resolve_opa_executable_hint(hint: PathBuf) -> PathBuf {
        if hint.is_dir() {
            hint.join(Self::opa_binary_name())
        } else {
            hint
        }
    }

    #[cfg(windows)]
    fn opa_binary_name() -> &'static str {
        "opa.exe"
    }

    #[cfg(not(windows))]
    fn opa_binary_name() -> &'static str {
        "opa"
    }

    pub fn with_data_path(mut self, data_path: impl Into<PathBuf>) -> Self {
        self.data_paths.push(data_path.into());
        self
    }

    pub fn with_data_paths<I, P>(mut self, data_paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.data_paths
            .extend(data_paths.into_iter().map(Into::into));
        self
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn data_paths(&self) -> &[PathBuf] {
        &self.data_paths
    }

    pub fn is_available(&self) -> bool {
        Command::new(&self.executable)
            .arg("version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    pub fn evaluate(&self, invocation: &RegoPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let output = self.run_opa_eval(invocation)?;
        if !output.status.success() {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "opa eval failed with {}: {}",
                output.status,
                process_error_output(&output)
            )));
        }
        parse_opa_eval_output(&output.stdout)
    }

    fn run_opa_eval(&self, invocation: &RegoPolicyInvocation) -> Result<Output, RuntimeError> {
        let adapter_data_paths = adapter_data_paths(&invocation.adapter_config)?;
        // Resolve a pinned remote bundle to a verified local path before
        // invoking opa. The temp dir is cleaned up when `remote_bundle` drops
        // at the end of this function, after opa has finished reading it.
        let remote_bundle = match &invocation.bundle_url {
            Some(value) => Some(fetch_remote_bundle(value, self.limits)?),
            None => None,
        };
        let mut command = Command::new(&self.executable);
        command
            .arg("eval")
            .arg("--format")
            .arg("json")
            .arg("--stdin-input");

        if let Some(bundle) = &invocation.bundle {
            command.arg("--bundle").arg(opa_command_path_arg(bundle));
        }
        if let Some(remote) = &remote_bundle {
            command
                .arg("--bundle")
                .arg(opa_command_path_arg(remote.path()));
        }
        for data_path in &self.data_paths {
            command.arg("--data").arg(opa_command_path_arg(data_path));
        }
        for data_path in adapter_data_paths {
            command.arg("--data").arg(opa_command_path_arg(&data_path));
        }
        command
            .arg(&invocation.query)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| opa_spawn_error(&self.executable, err))?;

        match child.stdin.take() {
            Some(mut stdin) => stdin
                .write_all(invocation.canonical_input.as_bytes())
                .map_err(|err| {
                    let _ = child.wait();
                    RuntimeError::PolicyInvocationFailed(format!(
                        "failed to write OPA stdin input: {err}"
                    ))
                })?,
            None => {
                let _ = child.wait();
                return Err(RuntimeError::PolicyInvocationFailed(
                    "failed to open OPA stdin input pipe".to_string(),
                ));
            }
        }

        let output = wait_with_timeout(child, self.eval_timeout).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!("failed to read OPA output: {err}"))
        })?;
        // `remote_bundle` stays in scope until here so the temp bundle exists
        // for the full duration of the opa evaluation.
        drop(remote_bundle);
        Ok(output)
    }
}

/// A temp directory that holds a verified remote rego bundle for the lifetime
/// of one `opa eval` invocation. The directory is removed on drop.
struct RemoteBundle {
    dir: PathBuf,
    bundle: PathBuf,
}

impl RemoteBundle {
    fn path(&self) -> &Path {
        &self.bundle
    }
}

impl Drop for RemoteBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static REMOTE_BUNDLE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn remote_bundle_token() -> String {
    let count = REMOTE_BUNDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}-{count}", std::process::id())
}

/// Fetch a pinned HTTPS rego bundle to a fresh temp directory and return a
/// guard owning the verified local path. Reuses the extends https-only and
/// sha256/integrity trust gate, so a non HTTPS URL, a missing pin, a fetch
/// error, a size breach, or a hash mismatch fails closed before opa runs.
///
/// The shared fetch helper reports trust failures as `ManifestInvalid` because
/// it is also used by manifest construction. At dispatch a `bundle_url` failure
/// is a runtime policy invocation failure, not a static manifest error, so the
/// reason is remapped to `PolicyInvocationFailed`. A size breach keeps its
/// `ResourceLimitExceeded` reason.
fn fetch_remote_bundle(value: &JsonValue, limits: Limits) -> Result<RemoteBundle, RuntimeError> {
    let body =
        crate::manifest::fetch_pinned_https_bytes(value, limits).map_err(|err| match err {
            RuntimeError::ResourceLimitExceeded(_) => err,
            other => RuntimeError::PolicyInvocationFailed(format!(
                "failed to resolve remote rego bundle: {}",
                other.detail()
            )),
        })?;
    write_remote_bundle(&body)
}

/// Create a directory accessible only to the current user (mode 0o700 on Unix).
/// On non-Unix platforms `std::fs::create_dir` is used unchanged because
/// Windows uses ACLs rather than POSIX permission bits.
#[cfg(unix)]
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

/// Materialize verified bundle bytes into a fresh temp directory. Split from
/// the network fetch so the temp directory lifecycle is unit testable.
fn write_remote_bundle(body: &[u8]) -> Result<RemoteBundle, RuntimeError> {
    let dir = env::temp_dir().join(format!("acs-rego-bundle-{}", remote_bundle_token()));
    create_private_dir(&dir).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to create temp directory '{}' for remote rego bundle: {err}",
            dir.display()
        ))
    })?;
    let bundle = dir.join("bundle.tar.gz");
    if let Err(err) = std::fs::write(&bundle, body) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "failed to write remote rego bundle to '{}': {err}",
            bundle.display()
        )));
    }
    Ok(RemoteBundle { dir, bundle })
}

fn eval_timeout_from_environment() -> Option<Duration> {
    let value = env::var(OPA_TIMEOUT_ENV).ok()?;
    let millis = value.parse::<u64>().ok()?;
    (millis > 0).then(|| Duration::from_millis(millis))
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> io::Result<Output> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("failed to open OPA stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to open OPA stderr pipe"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });

    let status = wait_for_exit_or_timeout(&mut child, timeout)?;
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_exit_or_timeout(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("OPA eval exceeded timeout of {} ms", timeout.as_millis()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn join_reader(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| io::Error::other("OPA output reader thread panicked"))?
}

fn opa_command_path_arg(path: impl AsRef<Path>) -> OsString {
    strip_windows_verbatim_prefix(path.as_ref())
}

fn strip_windows_verbatim_prefix(path: &Path) -> OsString {
    let value = path.to_string_lossy();
    if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
        OsString::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = value.strip_prefix(r"\\?\") {
        OsString::from(stripped)
    } else {
        path.as_os_str().to_os_string()
    }
}

impl Default for OpaRegoRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpaPolicyDispatcher {
    runner: OpaRegoRunner,
}

impl OpaPolicyDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_runner(runner: OpaRegoRunner) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &OpaRegoRunner {
        &self.runner
    }
}

impl PolicyDispatcher for OpaPolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Rego(invocation) => self.runner.evaluate(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "OPA policy dispatcher only supports Rego invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OpaEvalResponse {
    #[serde(default)]
    result: Vec<OpaEvalResult>,
    #[serde(default)]
    errors: Vec<OpaEvalError>,
}

#[derive(Debug, Deserialize)]
struct OpaEvalResult {
    #[serde(default)]
    expressions: Vec<OpaEvalExpression>,
}

#[derive(Debug, Deserialize)]
struct OpaEvalExpression {
    value: JsonValue,
}

#[derive(Debug, Deserialize)]
struct OpaEvalError {
    code: Option<String>,
    message: String,
}

fn adapter_data_paths(
    adapter_config: &BTreeMap<String, JsonValue>,
) -> Result<Vec<PathBuf>, RuntimeError> {
    let mut paths = Vec::new();
    for key in OPA_DATA_KEYS {
        if let Some(value) = adapter_config.get(key) {
            push_adapter_data_paths(key, value, &mut paths)?;
        }
    }
    Ok(paths)
}

fn push_adapter_data_paths(
    key: &str,
    value: &JsonValue,
    paths: &mut Vec<PathBuf>,
) -> Result<(), RuntimeError> {
    match value {
        JsonValue::Null => Ok(()),
        JsonValue::String(path) => push_data_path(key, path, paths),
        JsonValue::Array(items) => {
            for item in items {
                match item {
                    JsonValue::String(path) => push_data_path(key, path, paths)?,
                    _ => {
                        return Err(RuntimeError::PolicyInvocationFailed(format!(
                            "OPA adapter_config.{key} must be a string or array of strings"
                        )))
                    }
                }
            }
            Ok(())
        }
        _ => Err(RuntimeError::PolicyInvocationFailed(format!(
            "OPA adapter_config.{key} must be a string or array of strings"
        ))),
    }
}

fn push_data_path(key: &str, path: &str, paths: &mut Vec<PathBuf>) -> Result<(), RuntimeError> {
    if path.trim().is_empty() {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "OPA adapter_config.{key} entries must not be empty"
        )));
    }
    paths.push(PathBuf::from(path));
    Ok(())
}

fn opa_spawn_error(executable: &Path, err: io::Error) -> RuntimeError {
    if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(2) {
        let message = match env::var_os(OPA_PATH_ENV) {
            Some(value) if !value.is_empty() => format!(
                "default policy dispatcher could not execute OPA from ${OPA_PATH_ENV}: '{}'; explicit OPA paths do not fall back to PATH",
                executable.display()
            ),
            _ => format!(
                "OPA executable '{}' was not found; install OPA or configure OpaRegoRunner::with_executable(...)",
                executable.display()
            ),
        };
        RuntimeError::PolicyInvocationFailed(message)
    } else {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to start OPA executable '{}': {err}",
            executable.display()
        ))
    }
}

fn parse_opa_eval_output(stdout: &[u8]) -> Result<JsonValue, RuntimeError> {
    let response: OpaEvalResponse = serde_json::from_slice(stdout).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!("failed to parse OPA JSON output: {err}"))
    })?;

    if !response.errors.is_empty() {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "OPA returned errors: {}",
            format_opa_errors(&response.errors)
        )));
    }

    let result = match response.result.as_slice() {
        [] => {
            return Err(RuntimeError::PolicyInvocationFailed(
                "OPA query returned no result".to_string(),
            ))
        }
        [result] => result,
        _ => {
            return Err(RuntimeError::PolicyInvocationFailed(
                "OPA query returned multiple results; policy query must resolve to one verdict"
                    .to_string(),
            ))
        }
    };

    match result.expressions.as_slice() {
        [expression] => Ok(expression.value.clone()),
        [] => Err(RuntimeError::PolicyInvocationFailed(
            "OPA query returned a result with no expression value".to_string(),
        )),
        _ => Err(RuntimeError::PolicyInvocationFailed(
            "OPA query returned multiple expression values; policy query must resolve to one verdict"
                .to_string(),
        )),
    }
}

fn format_opa_errors(errors: &[OpaEvalError]) -> String {
    errors
        .iter()
        .map(|error| match &error.code {
            Some(code) => format!("{code}: {}", error.message),
            None => error.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn process_error_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    };
    if detail.is_empty() {
        "OPA produced no error output".to_string()
    } else {
        truncate(&detail)
    }
}

fn truncate(value: &str) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(ERROR_OUTPUT_LIMIT).collect();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::{opa_command_path_arg, write_remote_bundle};
    use std::path::Path;

    #[test]
    fn opa_command_path_arg_strips_windows_verbatim_disk_prefix() {
        assert_eq!(
            opa_command_path_arg(Path::new(r"\\?\C:\Temp\acs\policy")).to_string_lossy(),
            r"C:\Temp\acs\policy"
        );
    }

    #[test]
    fn opa_command_path_arg_strips_windows_verbatim_unc_prefix() {
        assert_eq!(
            opa_command_path_arg(Path::new(r"\\?\UNC\server\share\policy")).to_string_lossy(),
            r"\\server\share\policy"
        );
    }

    #[test]
    fn write_remote_bundle_materializes_and_cleans_up() {
        let body = b"opa bundle bytes";
        let dir;
        {
            let bundle = write_remote_bundle(body).expect("write temp bundle");
            dir = bundle.path().parent().unwrap().to_path_buf();
            assert!(bundle.path().exists(), "bundle file must exist during eval");
            assert_eq!(std::fs::read(bundle.path()).unwrap(), body);
            assert_eq!(
                bundle.path().file_name().unwrap().to_string_lossy(),
                "bundle.tar.gz"
            );
        }
        assert!(!dir.exists(), "temp dir must be removed when guard drops");
    }
}
