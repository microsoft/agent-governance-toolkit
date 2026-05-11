// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

use super::*;

// ---------------------------------------------------------------------------
// SandboxConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn sandbox_config_defaults() {
    let cfg = SandboxConfig::default();
    assert!((cfg.timeout_seconds - 60.0).abs() < f64::EPSILON);
    assert_eq!(cfg.memory_mb, 512);
    assert!((cfg.cpu_limit - 1.0).abs() < f64::EPSILON);
    assert!(!cfg.network_enabled);
    assert!(cfg.read_only_fs);
    assert!(cfg.env_vars.is_empty());
}

#[test]
fn sandbox_config_custom() {
    let cfg = SandboxConfig {
        timeout_seconds: 120.0,
        memory_mb: 1024,
        cpu_limit: 2.0,
        network_enabled: true,
        read_only_fs: false,
        env_vars: [("FOO".into(), "bar".into())].into_iter().collect(),
    };
    assert!((cfg.timeout_seconds - 120.0).abs() < f64::EPSILON);
    assert_eq!(cfg.memory_mb, 1024);
    assert!(cfg.network_enabled);
    assert!(!cfg.read_only_fs);
    assert_eq!(cfg.env_vars.get("FOO").unwrap(), "bar");
}

// ---------------------------------------------------------------------------
// SandboxResult defaults
// ---------------------------------------------------------------------------

#[test]
fn sandbox_result_defaults() {
    let r = SandboxResult::default();
    assert!(!r.success);
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.is_empty());
    assert!(!r.killed);
    assert!(r.kill_reason.is_empty());
}

// ---------------------------------------------------------------------------
// Enum Display
// ---------------------------------------------------------------------------

#[test]
fn session_status_display() {
    assert_eq!(SessionStatus::Provisioning.to_string(), "provisioning");
    assert_eq!(SessionStatus::Ready.to_string(), "ready");
    assert_eq!(SessionStatus::Executing.to_string(), "executing");
    assert_eq!(SessionStatus::Destroying.to_string(), "destroying");
    assert_eq!(SessionStatus::Destroyed.to_string(), "destroyed");
    assert_eq!(SessionStatus::Failed.to_string(), "failed");
}

#[test]
fn execution_status_display() {
    assert_eq!(ExecutionStatus::Pending.to_string(), "pending");
    assert_eq!(ExecutionStatus::Running.to_string(), "running");
    assert_eq!(ExecutionStatus::Completed.to_string(), "completed");
    assert_eq!(ExecutionStatus::Cancelled.to_string(), "cancelled");
    assert_eq!(ExecutionStatus::Failed.to_string(), "failed");
}

// ---------------------------------------------------------------------------
// DockerSandboxProvider::new — graceful degradation
// ---------------------------------------------------------------------------

#[test]
fn docker_provider_new_handles_missing_docker() {
    // On CI or machines without Docker the provider should not panic.
    let provider = DockerSandboxProvider::new("python:3.11-slim");
    assert_eq!(provider.image(), "python:3.11-slim");
    // is_available may be true or false depending on the host
}

// ---------------------------------------------------------------------------
// Default trait impl — run() returns failure
// ---------------------------------------------------------------------------

struct StubProvider;

impl SandboxProvider for StubProvider {
    fn create_session(
        &mut self,
        _agent_id: &str,
        _config: Option<&SandboxConfig>,
    ) -> Result<SessionHandle, String> {
        Err("stub".into())
    }

    fn execute_code(
        &mut self,
        _agent_id: &str,
        _session_id: &str,
        _code: &str,
    ) -> Result<ExecutionHandle, String> {
        Err("stub".into())
    }

    fn destroy_session(
        &mut self,
        _agent_id: &str,
        _session_id: &str,
    ) -> Result<(), String> {
        Err("stub".into())
    }

    fn is_available(&self) -> bool {
        false
    }
}

#[test]
fn default_run_returns_failure() {
    let mut stub = StubProvider;
    let result = stub.run("agent-1", &["echo", "hello"], None);
    assert!(!result.success);
    assert_eq!(result.exit_code, -1);
    assert!(result.stderr.contains("not implemented"));
}

// ---------------------------------------------------------------------------
// Session lifecycle — skipped when Docker is unavailable
// ---------------------------------------------------------------------------

#[test]
fn docker_create_session_without_docker() {
    let mut provider = DockerSandboxProvider::new("python:3.11-slim");
    if provider.is_available() {
        // Docker is present — run the full lifecycle test
        let handle = provider.create_session("test-agent", None);
        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.status, SessionStatus::Ready);
        assert_eq!(handle.agent_id, "test-agent");

        // Execute code
        let exec = provider.execute_code(
            "test-agent",
            &handle.session_id,
            "echo hello",
        );
        assert!(exec.is_ok());
        let exec = exec.unwrap();
        assert!(exec.result.is_some());
        let result = exec.result.unwrap();
        assert!(result.stdout.contains("hello"));

        // Destroy session
        let destroy = provider.destroy_session("test-agent", &handle.session_id);
        assert!(destroy.is_ok());
    } else {
        // Docker is not available — create_session should return an error
        let result = provider.create_session("test-agent", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not available"));
    }
}

#[test]
fn docker_execute_code_no_session() {
    let mut provider = DockerSandboxProvider::new("python:3.11-slim");
    let result = provider.execute_code("agent-x", "nonexistent", "echo hi");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No active session"));
}

#[test]
fn docker_destroy_session_no_session() {
    let mut provider = DockerSandboxProvider::new("python:3.11-slim");
    let result = provider.destroy_session("agent-x", "nonexistent");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No active session"));
}

#[test]
fn generate_id_uniqueness() {
    let id1 = super::generate_id();
    let id2 = super::generate_id();
    // IDs should be 16-char hex strings
    assert_eq!(id1.len(), 16);
    assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    // Consecutive IDs should differ (not guaranteed but overwhelmingly likely)
    assert_ne!(id1, id2);
}
