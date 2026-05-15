// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGovernance.Sandbox;

/// <summary>
/// <see cref="ISandboxProvider"/> backed by hardened Docker containers.
/// Uses the Docker CLI via <see cref="Process"/> — no external NuGet packages required.
/// Each agent session gets its own container with capabilities dropped, no-new-privileges,
/// optional read-only filesystem, and network isolation.
/// </summary>
public sealed class DockerSandboxProvider : ISandboxProvider
{
    private static readonly Regex SafeNamePattern = new(
        @"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$",
        RegexOptions.Compiled);

    private readonly string _image;

    // Maps (agentId, sessionId) → Docker container ID.
    private readonly ConcurrentDictionary<(string AgentId, string SessionId), string> _containers = new();

    // Maps (agentId, sessionId) → SandboxConfig used at creation.
    private readonly ConcurrentDictionary<(string AgentId, string SessionId), SandboxConfig> _configs = new();

    /// <summary>
    /// Initializes a new <see cref="DockerSandboxProvider"/>.
    /// </summary>
    /// <param name="image">Docker image to use for sandbox containers.</param>
    public DockerSandboxProvider(string image = "python:3.11-slim")
    {
        if (string.IsNullOrWhiteSpace(image))
            throw new ArgumentException("Image name must not be empty.", nameof(image));

        _image = image;
    }

    /// <inheritdoc />
    public async Task<SessionHandle> CreateSessionAsync(string agentId, SandboxConfig? config = null)
    {
        ValidateResourceName(agentId, nameof(agentId));

        var cfg = config ?? new SandboxConfig();
        var sessionId = Guid.NewGuid().ToString("N")[..8];
        var containerName = $"agt-{agentId}-{sessionId}";

        var args = new StringBuilder();
        args.Append("run -d");
        args.Append($" --name {containerName}");

        // Security hardening
        args.Append(" --cap-drop ALL");
        args.Append(" --security-opt no-new-privileges");

        if (cfg.ReadOnlyFs)
            args.Append(" --read-only");

        if (!cfg.NetworkEnabled)
            args.Append(" --network none");

        // Resource limits
        args.Append($" --memory {cfg.MemoryMb}m");
        args.Append($" --cpus {cfg.CpuLimit:F1}");
        args.Append(" --pids-limit 256");

        // Environment variables — quote values to prevent argument injection
        foreach (var kvp in cfg.EnvVars)
        {
            ValidateResourceName(kvp.Key, "EnvVars key");
            args.Append($" -e \"{kvp.Key}={kvp.Value.Replace("\"", "\\\"")}\"");
        }

        // Keep container alive with a blocking process
        args.Append($" {_image} tail -f /dev/null");

        var (exitCode, stdout, stderr) = await RunDockerAsync(args.ToString()).ConfigureAwait(false);

        if (exitCode != 0)
        {
            return new SessionHandle
            {
                AgentId = agentId,
                SessionId = sessionId,
                Status = SessionStatus.Failed
            };
        }

        var containerId = stdout.Trim();
        var key = (agentId, sessionId);
        _containers[key] = containerId;
        _configs[key] = cfg;

        return new SessionHandle
        {
            AgentId = agentId,
            SessionId = sessionId,
            Status = SessionStatus.Ready
        };
    }

    /// <inheritdoc />
    public async Task<ExecutionHandle> ExecuteCodeAsync(string agentId, string sessionId, string code)
    {
        ValidateResourceName(agentId, nameof(agentId));

        var key = (agentId, sessionId);
        if (!_containers.TryGetValue(key, out var containerId))
        {
            throw new InvalidOperationException(
                $"No active session for agent '{agentId}' with session_id '{sessionId}'. " +
                "Call CreateSessionAsync() first.");
        }

        _configs.TryGetValue(key, out var cfg);
        var timeout = cfg?.TimeoutSeconds ?? 60.0;

        var executionId = Guid.NewGuid().ToString("N")[..8];

        // Avoid shell interpolation: pipe code via stdin instead of python -c.
        var sw = Stopwatch.StartNew();
        var (exitCode, stdout, stderr) = await RunDockerWithStdinAsync(
            $"exec -i {containerId} python",
            code,
            timeoutSeconds: timeout).ConfigureAwait(false);
        sw.Stop();

        var killed = exitCode == -1;
        var result = new SandboxResult
        {
            Success = exitCode == 0,
            ExitCode = exitCode,
            Stdout = stdout,
            Stderr = stderr,
            DurationSeconds = sw.Elapsed.TotalSeconds,
            Killed = killed,
            KillReason = killed ? "timeout" : string.Empty
        };

        return new ExecutionHandle
        {
            ExecutionId = executionId,
            AgentId = agentId,
            SessionId = sessionId,
            Status = exitCode == 0 ? ExecutionStatus.Completed : (killed ? ExecutionStatus.Cancelled : ExecutionStatus.Failed),
            Result = result
        };
    }

    /// <inheritdoc />
    public async Task DestroySessionAsync(string agentId, string sessionId)
    {
        ValidateResourceName(agentId, nameof(agentId));

        var key = (agentId, sessionId);
        if (!_containers.TryRemove(key, out var containerId))
        {
            return; // Already destroyed or never created — idempotent.
        }

        _configs.TryRemove(key, out _);

        await RunDockerAsync($"rm -f {containerId}").ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> IsAvailableAsync()
    {
        try
        {
            var (exitCode, _, _) = await RunDockerAsync("info").ConfigureAwait(false);
            return exitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void ValidateResourceName(string value, string label)
    {
        if (string.IsNullOrEmpty(value) || !SafeNamePattern.IsMatch(value))
        {
            throw new ArgumentException(
                $"Invalid {label} '{value}': must match [a-zA-Z0-9][a-zA-Z0-9_.-]{{0,127}}",
                label);
        }
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunDockerAsync(
        string arguments, double timeoutSeconds = 30.0)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        var timeoutMs = (int)(timeoutSeconds * 1000);
        var exited = await Task.Run(() => process.WaitForExit(timeoutMs)).ConfigureAwait(false);

        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            var partialStdout = await stdoutTask.ConfigureAwait(false);
            var partialStderr = await stderrTask.ConfigureAwait(false);
            return (-1, partialStdout, partialStderr);
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return (process.ExitCode, stdout, stderr);
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunDockerWithStdinAsync(
        string arguments, string stdinContent, double timeoutSeconds = 30.0)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = arguments,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        process.Start();

        await process.StandardInput.WriteAsync(stdinContent).ConfigureAwait(false);
        process.StandardInput.Close();

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        var timeoutMs = (int)(timeoutSeconds * 1000);
        var exited = await Task.Run(() => process.WaitForExit(timeoutMs)).ConfigureAwait(false);

        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            var partialStdout = await stdoutTask.ConfigureAwait(false);
            var partialStderr = await stderrTask.ConfigureAwait(false);
            return (-1, partialStdout, partialStderr);
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return (process.ExitCode, stdout, stderr);
    }
}
