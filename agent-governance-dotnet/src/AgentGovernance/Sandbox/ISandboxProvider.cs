// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Generic;

namespace AgentGovernance.Sandbox;

/// <summary>
/// Lifecycle state of a sandbox session.
/// </summary>
public enum SessionStatus
{
    /// <summary>Session is being provisioned.</summary>
    Provisioning,

    /// <summary>Session is ready to execute code.</summary>
    Ready,

    /// <summary>Session is currently executing code.</summary>
    Executing,

    /// <summary>Session is being torn down.</summary>
    Destroying,

    /// <summary>Session has been destroyed.</summary>
    Destroyed,

    /// <summary>Session encountered an unrecoverable error.</summary>
    Failed
}

/// <summary>
/// State of a single code execution within a session.
/// </summary>
public enum ExecutionStatus
{
    /// <summary>Execution is queued but has not started.</summary>
    Pending,

    /// <summary>Execution is in progress.</summary>
    Running,

    /// <summary>Execution finished successfully.</summary>
    Completed,

    /// <summary>Execution was cancelled.</summary>
    Cancelled,

    /// <summary>Execution failed.</summary>
    Failed
}

/// <summary>
/// Configuration for a sandbox environment.
/// </summary>
public sealed class SandboxConfig
{
    /// <summary>Maximum execution time in seconds.</summary>
    public double TimeoutSeconds { get; init; } = 60.0;

    /// <summary>Memory limit in megabytes.</summary>
    public int MemoryMb { get; init; } = 512;

    /// <summary>CPU core limit (e.g. 1.0 = one core).</summary>
    public double CpuLimit { get; init; } = 1.0;

    /// <summary>Whether outbound network access is allowed.</summary>
    public bool NetworkEnabled { get; init; } = false;

    /// <summary>Whether the root filesystem is mounted read-only.</summary>
    public bool ReadOnlyFs { get; init; } = true;

    /// <summary>Environment variables injected into the sandbox.</summary>
    public Dictionary<string, string> EnvVars { get; init; } = new();
}

/// <summary>
/// Result from a sandbox execution.
/// </summary>
public sealed class SandboxResult
{
    /// <summary>Whether the execution completed successfully.</summary>
    public bool Success { get; init; }

    /// <summary>Process exit code.</summary>
    public int ExitCode { get; init; }

    /// <summary>Standard output captured from the execution.</summary>
    public string Stdout { get; init; } = string.Empty;

    /// <summary>Standard error captured from the execution.</summary>
    public string Stderr { get; init; } = string.Empty;

    /// <summary>Wall-clock duration in seconds.</summary>
    public double DurationSeconds { get; init; }

    /// <summary>Whether the process was killed (e.g. timeout).</summary>
    public bool Killed { get; init; }

    /// <summary>Reason the process was killed, if applicable.</summary>
    public string KillReason { get; init; } = string.Empty;
}

/// <summary>
/// Identifies an active sandbox session.
/// </summary>
public sealed class SessionHandle
{
    /// <summary>The agent that owns this session.</summary>
    public string AgentId { get; init; } = string.Empty;

    /// <summary>Unique session identifier.</summary>
    public string SessionId { get; init; } = string.Empty;

    /// <summary>Current lifecycle state.</summary>
    public SessionStatus Status { get; init; } = SessionStatus.Ready;
}

/// <summary>
/// Wraps the result of a single code execution.
/// </summary>
public sealed class ExecutionHandle
{
    /// <summary>Unique execution identifier.</summary>
    public string ExecutionId { get; init; } = string.Empty;

    /// <summary>The agent that owns this execution.</summary>
    public string AgentId { get; init; } = string.Empty;

    /// <summary>Session this execution belongs to.</summary>
    public string SessionId { get; init; } = string.Empty;

    /// <summary>Current execution state.</summary>
    public ExecutionStatus Status { get; init; } = ExecutionStatus.Completed;

    /// <summary>Execution result, if available.</summary>
    public SandboxResult? Result { get; init; }
}

/// <summary>
/// Backend-agnostic interface for sandboxed agent execution.
/// </summary>
public interface ISandboxProvider
{
    /// <summary>
    /// Provision a sandbox session for the given agent.
    /// </summary>
    /// <param name="agentId">Identifier of the agent requesting the session.</param>
    /// <param name="config">Optional sandbox configuration overrides.</param>
    /// <returns>A handle identifying the created session.</returns>
    Task<SessionHandle> CreateSessionAsync(string agentId, SandboxConfig? config = null);

    /// <summary>
    /// Execute code inside an existing sandbox session.
    /// </summary>
    /// <param name="agentId">Identifier of the agent that owns the session.</param>
    /// <param name="sessionId">Session to execute in.</param>
    /// <param name="code">Code string to execute.</param>
    /// <returns>A handle containing the execution result.</returns>
    Task<ExecutionHandle> ExecuteCodeAsync(string agentId, string sessionId, string code);

    /// <summary>
    /// Tear down a sandbox session and release resources.
    /// </summary>
    /// <param name="agentId">Identifier of the agent that owns the session.</param>
    /// <param name="sessionId">Session to destroy.</param>
    Task DestroySessionAsync(string agentId, string sessionId);

    /// <summary>
    /// Check whether this sandbox provider is available (e.g. Docker daemon is running).
    /// </summary>
    /// <returns><c>true</c> if the provider can create sessions.</returns>
    Task<bool> IsAvailableAsync();
}
