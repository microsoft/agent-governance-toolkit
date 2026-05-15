// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Sandbox;
using Xunit;

namespace AgentGovernance.Tests;

public class SandboxTests
{
    // ------------------------------------------------------------------
    // SandboxConfig defaults
    // ------------------------------------------------------------------

    [Fact]
    public void SandboxConfig_DefaultValues_MatchSpec()
    {
        var cfg = new SandboxConfig();

        Assert.Equal(60.0, cfg.TimeoutSeconds);
        Assert.Equal(512, cfg.MemoryMb);
        Assert.Equal(1.0, cfg.CpuLimit);
        Assert.False(cfg.NetworkEnabled);
        Assert.True(cfg.ReadOnlyFs);
        Assert.NotNull(cfg.EnvVars);
        Assert.Empty(cfg.EnvVars);
    }

    [Fact]
    public void SandboxConfig_CustomValues_ArePreserved()
    {
        var cfg = new SandboxConfig
        {
            TimeoutSeconds = 120.0,
            MemoryMb = 1024,
            CpuLimit = 2.0,
            NetworkEnabled = true,
            ReadOnlyFs = false,
            EnvVars = new() { ["KEY"] = "value" }
        };

        Assert.Equal(120.0, cfg.TimeoutSeconds);
        Assert.Equal(1024, cfg.MemoryMb);
        Assert.Equal(2.0, cfg.CpuLimit);
        Assert.True(cfg.NetworkEnabled);
        Assert.False(cfg.ReadOnlyFs);
        Assert.Single(cfg.EnvVars);
        Assert.Equal("value", cfg.EnvVars["KEY"]);
    }

    // ------------------------------------------------------------------
    // SandboxResult defaults
    // ------------------------------------------------------------------

    [Fact]
    public void SandboxResult_DefaultValues()
    {
        var result = new SandboxResult();

        Assert.False(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(string.Empty, result.Stdout);
        Assert.Equal(string.Empty, result.Stderr);
        Assert.Equal(0.0, result.DurationSeconds);
        Assert.False(result.Killed);
        Assert.Equal(string.Empty, result.KillReason);
    }

    // ------------------------------------------------------------------
    // Handle defaults
    // ------------------------------------------------------------------

    [Fact]
    public void SessionHandle_DefaultStatus_IsReady()
    {
        var handle = new SessionHandle { AgentId = "a1", SessionId = "s1" };

        Assert.Equal("a1", handle.AgentId);
        Assert.Equal("s1", handle.SessionId);
        Assert.Equal(SessionStatus.Ready, handle.Status);
    }

    [Fact]
    public void ExecutionHandle_DefaultStatus_IsCompleted()
    {
        var handle = new ExecutionHandle
        {
            ExecutionId = "e1",
            AgentId = "a1",
            SessionId = "s1"
        };

        Assert.Equal(ExecutionStatus.Completed, handle.Status);
        Assert.Null(handle.Result);
    }

    // ------------------------------------------------------------------
    // DockerSandboxProvider construction
    // ------------------------------------------------------------------

    [Fact]
    public void DockerSandboxProvider_DefaultImage()
    {
        var provider = new DockerSandboxProvider();
        Assert.NotNull(provider);
    }

    [Fact]
    public void DockerSandboxProvider_CustomImage()
    {
        var provider = new DockerSandboxProvider("node:20-slim");
        Assert.NotNull(provider);
    }

    [Fact]
    public void DockerSandboxProvider_EmptyImage_Throws()
    {
        Assert.Throws<ArgumentException>(() => new DockerSandboxProvider(""));
    }

    [Fact]
    public void DockerSandboxProvider_WhitespaceImage_Throws()
    {
        Assert.Throws<ArgumentException>(() => new DockerSandboxProvider("   "));
    }

    // ------------------------------------------------------------------
    // IsAvailableAsync — handles missing Docker gracefully
    // ------------------------------------------------------------------

    [Fact]
    public async Task IsAvailableAsync_ReturnsWithoutThrowing()
    {
        var provider = new DockerSandboxProvider();
        // Should return true or false, never throw.
        var available = await provider.IsAvailableAsync();
        Assert.IsType<bool>(available);
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("agent with spaces")]
    [InlineData("agent;rm -rf")]
    [InlineData("../escape")]
    public async Task CreateSessionAsync_InvalidAgentId_Throws(string badId)
    {
        var provider = new DockerSandboxProvider();
        await Assert.ThrowsAsync<ArgumentException>(
            () => provider.CreateSessionAsync(badId));
    }

    [Theory]
    [InlineData("")]
    [InlineData("agent;inject")]
    public async Task ExecuteCodeAsync_InvalidAgentId_Throws(string badId)
    {
        var provider = new DockerSandboxProvider();
        await Assert.ThrowsAsync<ArgumentException>(
            () => provider.ExecuteCodeAsync(badId, "sess1", "print(1)"));
    }

    [Fact]
    public async Task ExecuteCodeAsync_NoSession_Throws()
    {
        var provider = new DockerSandboxProvider();
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.ExecuteCodeAsync("agent1", "nonexistent", "print(1)"));
    }

    // ------------------------------------------------------------------
    // Full lifecycle (skipped when Docker is unavailable)
    // ------------------------------------------------------------------

    [Fact]
    public async Task FullLifecycle_CreateExecuteDestroy()
    {
        var provider = new DockerSandboxProvider();
        var available = await provider.IsAvailableAsync();
        if (!available)
        {
            // Docker not installed or daemon not running — skip gracefully.
            return;
        }

        // Create
        var session = await provider.CreateSessionAsync("testagent", new SandboxConfig
        {
            TimeoutSeconds = 30,
            MemoryMb = 128,
            CpuLimit = 0.5,
            NetworkEnabled = false,
            ReadOnlyFs = false // allow /tmp writes inside container
        });

        Assert.Equal(SessionStatus.Ready, session.Status);
        Assert.Equal("testagent", session.AgentId);
        Assert.False(string.IsNullOrEmpty(session.SessionId));

        try
        {
            // Execute
            var exec = await provider.ExecuteCodeAsync(
                session.AgentId, session.SessionId, "print('hello sandbox')");

            Assert.Equal(ExecutionStatus.Completed, exec.Status);
            Assert.NotNull(exec.Result);
            Assert.True(exec.Result!.Success);
            Assert.Equal(0, exec.Result.ExitCode);
            Assert.Contains("hello sandbox", exec.Result.Stdout);
            Assert.False(exec.Result.Killed);
        }
        finally
        {
            // Destroy — always clean up
            await provider.DestroySessionAsync(session.AgentId, session.SessionId);
        }

        // Verify destroyed — executing should throw
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.ExecuteCodeAsync("testagent", session.SessionId, "print(1)"));
    }

    [Fact]
    public async Task DestroySession_Idempotent()
    {
        var provider = new DockerSandboxProvider();
        // Destroying a non-existent session should not throw.
        await provider.DestroySessionAsync("agent1", "nonexistent");
    }
}
