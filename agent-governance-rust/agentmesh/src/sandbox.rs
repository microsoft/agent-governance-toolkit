// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

//! Sandbox provider trait and Docker-based implementation.
//!
//! Defines the backend-agnostic API for sandboxed agent execution. Any
//! sandbox backend — Docker, Hyperlight micro-VMs, cloud sandbox services,
//! or custom providers — implements the [`SandboxProvider`] trait.
//!
//! The [`DockerSandboxProvider`] uses the Docker CLI (`std::process::Command`)
//! to manage hardened containers with dropped capabilities, read-only
//! filesystems, and network isolation.

use std::collections::HashMap;
use std::fmt;
use std::process::Command;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Lifecycle state of a sandbox session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Provisioning,
    Ready,
    Executing,
    Destroying,
    Destroyed,
    Failed,
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Executing => "executing",
            Self::Destroying => "destroying",
            Self::Destroyed => "destroyed",
            Self::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// State of a single code execution within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Cancelled,
    Failed,
}

impl fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Configuration for a sandbox environment.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub timeout_seconds: f64,
    pub memory_mb: u32,
    pub cpu_limit: f64,
    pub network_enabled: bool,
    pub read_only_fs: bool,
    pub env_vars: HashMap<String, String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 60.0,
            memory_mb: 512,
            cpu_limit: 1.0,
            network_enabled: false,
            read_only_fs: true,
            env_vars: HashMap::new(),
        }
    }
}

/// Result from a sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_seconds: f64,
    pub killed: bool,
    pub kill_reason: String,
}

impl Default for SandboxResult {
    fn default() -> Self {
        Self {
            success: false,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_seconds: 0.0,
            killed: false,
            kill_reason: String::new(),
        }
    }
}

/// Returned by [`SandboxProvider::create_session`] — identifies an active sandbox session.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub agent_id: String,
    pub session_id: String,
    pub status: SessionStatus,
}

/// Returned by [`SandboxProvider::execute_code`] — wraps the result of a single execution.
#[derive(Debug, Clone)]
pub struct ExecutionHandle {
    pub execution_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub status: ExecutionStatus,
    pub result: Option<SandboxResult>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstract interface for sandbox providers.
///
/// Defines session-based lifecycle methods (`create_session`, `execute_code`,
/// `destroy_session`) and an availability check.
pub trait SandboxProvider {
    /// Provision a sandbox with optional resource constraints.
    fn create_session(
        &mut self,
        agent_id: &str,
        config: Option<&SandboxConfig>,
    ) -> Result<SessionHandle, String>;

    /// Run code inside an existing session.
    fn execute_code(
        &mut self,
        agent_id: &str,
        session_id: &str,
        code: &str,
    ) -> Result<ExecutionHandle, String>;

    /// Tear down the sandbox and release resources.
    fn destroy_session(
        &mut self,
        agent_id: &str,
        session_id: &str,
    ) -> Result<(), String>;

    /// Check if this sandbox provider is available.
    fn is_available(&self) -> bool;

    /// Run a raw command in the sandbox (low-level helper).
    ///
    /// The default implementation returns a failure result so that providers
    /// that do not support raw commands behave predictably.
    fn run(
        &mut self,
        agent_id: &str,
        command: &[&str],
        config: Option<&SandboxConfig>,
    ) -> SandboxResult {
        let _ = (agent_id, command, config);
        SandboxResult {
            success: false,
            exit_code: -1,
            stderr: format!(
                "{} run() is not implemented for this provider",
                std::any::type_name::<Self>()
            ),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Docker implementation
// ---------------------------------------------------------------------------

/// Container name prefix used to namespace sandbox containers.
const CONTAINER_PREFIX: &str = "agentmesh-sandbox";

/// Generate a simple unique ID (hex string) without external crates.
fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = {
        // Mix in thread ID for uniqueness across threads
        let tid = format!("{:?}", std::thread::current().id());
        let combined = format!("{}{}", nanos, tid);
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in combined.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h
    };
    format!("{:016x}", hash)
}

/// Format a Docker-safe container name from agent and session IDs.
fn container_name(agent_id: &str, session_id: &str) -> String {
    format!("{}-{}-{}", CONTAINER_PREFIX, agent_id, session_id)
}

/// `SandboxProvider` backed by hardened Docker containers.
///
/// Uses the Docker CLI via `std::process::Command` — no external Docker
/// crate dependency required.
pub struct DockerSandboxProvider {
    image: String,
    available: bool,
    /// Maps `(agent_id, session_id)` → Docker container name.
    containers: HashMap<(String, String), String>,
    runtime: String,
}

impl DockerSandboxProvider {
    /// Create a new provider, checking Docker CLI availability via `docker info`.
    pub fn new(image: &str) -> Self {
        let available = Command::new("docker")
            .args(["info"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        Self {
            image: image.to_string(),
            available,
            containers: HashMap::new(),
            runtime: String::from("runc"),
        }
    }

    /// Return the configured Docker image.
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Return the OCI runtime name.
    pub fn runtime(&self) -> &str {
        &self.runtime
    }
}

impl SandboxProvider for DockerSandboxProvider {
    fn is_available(&self) -> bool {
        self.available
    }

    fn create_session(
        &mut self,
        agent_id: &str,
        config: Option<&SandboxConfig>,
    ) -> Result<SessionHandle, String> {
        if !self.available {
            return Err("Docker daemon is not available".into());
        }

        let cfg = config.cloned().unwrap_or_default();
        let session_id = generate_id();
        let name = container_name(agent_id, &session_id);

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            name.clone(),
            format!("--memory={}m", cfg.memory_mb),
            format!("--cpus={}", cfg.cpu_limit),
            "--cap-drop=ALL".to_string(),
            "--security-opt=no-new-privileges".to_string(),
        ];

        if cfg.read_only_fs {
            args.push("--read-only".to_string());
        }

        if !cfg.network_enabled {
            args.push("--network=none".to_string());
        }

        for (k, v) in &cfg.env_vars {
            args.push("-e".to_string());
            args.push(format!("{}={}", k, v));
        }

        args.push(self.image.clone());
        args.push("sleep".to_string());
        args.push("infinity".to_string());

        let output = Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| format!("Failed to run docker: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("docker run failed: {}", stderr.trim()));
        }

        self.containers
            .insert((agent_id.to_string(), session_id.clone()), name);

        Ok(SessionHandle {
            agent_id: agent_id.to_string(),
            session_id,
            status: SessionStatus::Ready,
        })
    }

    fn execute_code(
        &mut self,
        agent_id: &str,
        session_id: &str,
        code: &str,
    ) -> Result<ExecutionHandle, String> {
        let key = (agent_id.to_string(), session_id.to_string());
        let name = self
            .containers
            .get(&key)
            .ok_or_else(|| {
                format!(
                    "No active session for agent '{}' with session_id '{}'. \
                     Call create_session() first.",
                    agent_id, session_id
                )
            })?
            .clone();

        let execution_id = generate_id();
        let start = Instant::now();

        let output = Command::new("docker")
            .args(["exec", &name, "sh", "-c", code])
            .output()
            .map_err(|e| format!("Failed to run docker exec: {}", e))?;

        let duration = start.elapsed().as_secs_f64();
        let exit_code = output.status.code().unwrap_or(-1);
        let success = output.status.success();

        let result = SandboxResult {
            success,
            exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_seconds: duration,
            killed: false,
            kill_reason: String::new(),
        };

        let status = if success {
            ExecutionStatus::Completed
        } else {
            ExecutionStatus::Failed
        };

        Ok(ExecutionHandle {
            execution_id,
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            status,
            result: Some(result),
        })
    }

    fn destroy_session(
        &mut self,
        agent_id: &str,
        session_id: &str,
    ) -> Result<(), String> {
        let key = (agent_id.to_string(), session_id.to_string());
        let name = match self.containers.remove(&key) {
            Some(n) => n,
            None => return Err(format!("No active session '{}'", session_id)),
        };

        let output = Command::new("docker")
            .args(["rm", "-f", &name])
            .output()
            .map_err(|e| format!("Failed to run docker rm: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("docker rm failed: {}", stderr.trim()));
        }

        Ok(())
    }

    fn run(
        &mut self,
        agent_id: &str,
        command: &[&str],
        config: Option<&SandboxConfig>,
    ) -> SandboxResult {
        let cfg = config.cloned().unwrap_or_default();

        // Create a one-shot container, run the command, remove on exit.
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            format!("--memory={}m", cfg.memory_mb),
            format!("--cpus={}", cfg.cpu_limit),
            "--cap-drop=ALL".to_string(),
            "--security-opt=no-new-privileges".to_string(),
        ];

        if cfg.read_only_fs {
            args.push("--read-only".to_string());
        }
        if !cfg.network_enabled {
            args.push("--network=none".to_string());
        }
        for (k, v) in &cfg.env_vars {
            args.push("-e".to_string());
            args.push(format!("{}={}", k, v));
        }

        args.push(self.image.clone());
        for part in command {
            args.push(part.to_string());
        }

        let _ = agent_id; // reserved for future per-agent auditing
        let start = Instant::now();

        match Command::new("docker").args(&args).output() {
            Ok(output) => {
                let duration = start.elapsed().as_secs_f64();
                let exit_code = output.status.code().unwrap_or(-1);
                SandboxResult {
                    success: output.status.success(),
                    exit_code,
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    duration_seconds: duration,
                    killed: false,
                    kill_reason: String::new(),
                }
            }
            Err(e) => SandboxResult {
                success: false,
                exit_code: -1,
                stderr: format!("Failed to execute docker run: {}", e),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod sandbox_test;
