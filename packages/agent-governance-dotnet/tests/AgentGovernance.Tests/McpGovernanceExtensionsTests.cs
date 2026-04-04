// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Extensions;
using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using Xunit;

namespace AgentGovernance.Tests;

public class McpGovernanceExtensionsTests
{
    // ── AddMcpGovernance ─────────────────────────────────────────────────

    [Fact]
    public void AddMcpGovernance_DefaultOptions_ReturnsAllComponents()
    {
        var (kernel, gateway, scanner, handler) = McpGovernanceExtensions.AddMcpGovernance();

        Assert.NotNull(kernel);
        Assert.NotNull(gateway);
        Assert.NotNull(scanner);
        Assert.NotNull(handler);
    }

    [Fact]
    public void AddMcpGovernance_WithPolicies_KernelHasPolicies()
    {
        var (kernel, _, _, _) = McpGovernanceExtensions.AddMcpGovernance(
            kernelOptions: new GovernanceOptions
            {
                PolicyPaths = new() // No files, but exercise the path
            });

        Assert.NotNull(kernel.PolicyEngine);
    }

    [Fact]
    public void AddMcpGovernance_WithDeniedTools_GatewayBlocksThem()
    {
        var (_, gateway, _, _) = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                DeniedTools = new() { "dangerous_tool" }
            });

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "dangerous_tool", new());
        Assert.False(allowed);
    }

    [Fact]
    public void AddMcpGovernance_WithAllowedTools_GatewayFilters()
    {
        var (_, gateway, _, _) = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                AllowedTools = new() { "safe_tool" }
            });

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "other_tool", new());
        Assert.False(allowed);

        var (allowed2, _) = gateway.InterceptToolCall("did:mesh:a1", "safe_tool", new());
        Assert.True(allowed2);
    }

    [Fact]
    public void AddMcpGovernance_WithMaxToolCalls_RespectsBudget()
    {
        var (_, gateway, _, _) = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                MaxToolCallsPerAgent = 2
            });

        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.False(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
    }

    [Fact]
    public void AddMcpGovernance_CustomAgentId_UsedByHandler()
    {
        var (_, _, _, handler) = McpGovernanceExtensions.AddMcpGovernance(
            agentId: "did:mesh:custom-agent");

        // Handler should work with the custom agent ID — just verify it doesn't throw.
        var response = handler.HandleMessage(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = "prompts/list",
            ["params"] = new Dictionary<string, object>(),
            ["id"] = 1
        });

        Assert.NotNull(response["result"]);
    }

    // ── UseMcpGovernance ─────────────────────────────────────────────────

    [Fact]
    public void UseMcpGovernance_ExistingKernel_ReturnsGateway()
    {
        var kernel = new GovernanceKernel();
        var gateway = McpGovernanceExtensions.UseMcpGovernance(kernel);

        Assert.NotNull(gateway);
    }

    [Fact]
    public void UseMcpGovernance_WithOptions_AppliesConfig()
    {
        var kernel = new GovernanceKernel();
        var gateway = McpGovernanceExtensions.UseMcpGovernance(kernel, new McpGovernanceOptions
        {
            DeniedTools = new() { "blocked" },
            MaxToolCallsPerAgent = 5
        });

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "blocked", new());
        Assert.False(allowed);
    }

    [Fact]
    public void UseMcpGovernance_NullKernel_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            McpGovernanceExtensions.UseMcpGovernance(null!));
    }

    [Fact]
    public void UseMcpGovernance_NullOptions_UsesDefaults()
    {
        var kernel = new GovernanceKernel();
        var gateway = McpGovernanceExtensions.UseMcpGovernance(kernel, null);

        // Default behavior: no deny-list, no allow-list — tool should pass.
        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "any_tool", new());
        Assert.True(allowed);
    }

    // ── McpGovernanceOptions defaults ────────────────────────────────────

    [Fact]
    public void McpGovernanceOptions_Defaults_AreCorrect()
    {
        var opts = new McpGovernanceOptions();

        Assert.Empty(opts.DeniedTools);
        Assert.Empty(opts.AllowedTools);
        Assert.Empty(opts.SensitiveTools);
        Assert.True(opts.EnableBuiltinSanitization);
        Assert.False(opts.RequireHumanApproval);
        Assert.Equal(1000, opts.MaxToolCallsPerAgent);
        Assert.Null(opts.CustomToolMappings);
        Assert.Null(opts.ApprovalCallback);
        Assert.True(opts.EnableResponseScanning);
        Assert.True(opts.EnableCredentialRedaction);
        Assert.Equal(TimeSpan.FromHours(1), opts.SessionTtl);
        Assert.Equal(10, opts.MaxSessionsPerAgent);
        Assert.Null(opts.MessageSigningKey);
        Assert.Equal(TimeSpan.FromMinutes(5), opts.MessageReplayWindow);
        Assert.Equal(TimeSpan.FromMinutes(5), opts.RateLimitWindow);
    }

    // ── McpGovernanceStack ───────────────────────────────────────────────

    [Fact]
    public void AddMcpGovernance_DefaultStack_HasOptionalComponents()
    {
        var stack = McpGovernanceExtensions.AddMcpGovernance();

        Assert.NotNull(stack.Kernel);
        Assert.NotNull(stack.Gateway);
        Assert.NotNull(stack.Scanner);
        Assert.NotNull(stack.Handler);
        Assert.NotNull(stack.ResponseScanner);      // enabled by default
        Assert.NotNull(stack.SessionAuthenticator);  // enabled by default (1h TTL)
        Assert.Null(stack.MessageSigner);            // needs explicit key
    }

    [Fact]
    public void AddMcpGovernance_WithSigningKey_CreatesMessageSigner()
    {
        var key = McpMessageSigner.GenerateKey();
        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions { MessageSigningKey = key });

        Assert.NotNull(stack.MessageSigner);
    }

    [Fact]
    public void AddMcpGovernance_DisableResponseScanning_NullScanner()
    {
        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions { EnableResponseScanning = false });

        Assert.Null(stack.ResponseScanner);
    }

    [Fact]
    public void AddMcpGovernance_DisableSessionAuth_NullAuthenticator()
    {
        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions { SessionTtl = null });

        Assert.Null(stack.SessionAuthenticator);
    }

    [Fact]
    public void McpGovernanceStack_Deconstruct_MatchesTuplePattern()
    {
        var stack = McpGovernanceExtensions.AddMcpGovernance();
        var (kernel, gateway, scanner, handler) = stack;

        Assert.Same(stack.Kernel, kernel);
        Assert.Same(stack.Gateway, gateway);
        Assert.Same(stack.Scanner, scanner);
        Assert.Same(stack.Handler, handler);
    }

    [Fact]
    public void AddMcpGovernance_CustomSessionConfig_Applied()
    {
        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                SessionTtl = TimeSpan.FromMinutes(30),
                MaxSessionsPerAgent = 5
            });

        Assert.NotNull(stack.SessionAuthenticator);
        Assert.Equal(TimeSpan.FromMinutes(30), stack.SessionAuthenticator!.SessionTtl);
        Assert.Equal(5, stack.SessionAuthenticator.MaxSessionsPerAgent);
    }

    [Fact]
    public void AddMcpGovernance_CustomReplayWindow_Applied()
    {
        var key = McpMessageSigner.GenerateKey();
        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                MessageSigningKey = key,
                MessageReplayWindow = TimeSpan.FromMinutes(10)
            });

        Assert.NotNull(stack.MessageSigner);
        Assert.Equal(TimeSpan.FromMinutes(10), stack.MessageSigner!.ReplayWindow);
    }

    [Fact]
    public void AddMcpGovernance_CustomInfrastructure_UsesInjectedDependencies()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T12:00:00Z"));
        var sessionStore = new TrackingSessionStore();
        var nonceStore = new TrackingNonceStore();
        var rateLimitStore = new TrackingRateLimitStore();
        var auditSink = new TrackingAuditSink();
        var key = McpMessageSigner.GenerateKey();

        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                MessageSigningKey = key,
                MaxToolCallsPerAgent = 1
            },
            timeProvider: timeProvider,
            sessionStore: sessionStore,
            nonceStore: nonceStore,
            rateLimitStore: rateLimitStore,
            auditSink: auditSink);

        var token = stack.SessionAuthenticator!.CreateSession("did:mesh:a1");
        Assert.NotNull(token);
        Assert.True(sessionStore.SetCalls > 0);

        stack.Gateway.InterceptToolCall("did:mesh:a1", "tool", new());
        Assert.Single(auditSink.Entries);
        Assert.Equal(timeProvider.GetUtcNow(), auditSink.Entries[0].Timestamp);
        Assert.True(rateLimitStore.GetCalls > 0);
        Assert.True(rateLimitStore.SetCalls > 0);

        var envelope = stack.MessageSigner!.SignMessage("""{"ok":true}""");
        var verification = stack.MessageSigner.VerifyMessage(envelope);
        Assert.True(verification.IsValid);
        Assert.True(nonceStore.AddCalls > 0);
    }

    [Fact]
    public void UseMcpGovernance_CustomInfrastructure_UsesInjectedDependencies()
    {
        var kernel = new GovernanceKernel();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T12:00:00Z"));
        var rateLimitStore = new TrackingRateLimitStore();
        var auditSink = new TrackingAuditSink();

        var gateway = McpGovernanceExtensions.UseMcpGovernance(
            kernel,
            new McpGovernanceOptions
            {
                MaxToolCallsPerAgent = 1
            },
            timeProvider: timeProvider,
            rateLimitStore: rateLimitStore,
            auditSink: auditSink);

        gateway.InterceptToolCall("did:mesh:a1", "tool", new());

        Assert.Single(auditSink.Entries);
        Assert.Equal(timeProvider.GetUtcNow(), auditSink.Entries[0].Timestamp);
        Assert.True(rateLimitStore.GetCalls > 0);
        Assert.True(rateLimitStore.SetCalls > 0);
    }

    // ── McpGovernanceDefaults ────────────────────────────────────────────

    [Fact]
    public void McpGovernanceDefaults_DeniedTools_NotEmpty()
    {
        Assert.NotEmpty(McpGovernanceDefaults.DeniedTools);
        Assert.Contains("rm_rf", McpGovernanceDefaults.DeniedTools);
        Assert.Contains("drop_database", McpGovernanceDefaults.DeniedTools);
        Assert.Contains("exec_shell", McpGovernanceDefaults.DeniedTools);
    }

    [Fact]
    public void McpGovernanceDefaults_SensitiveTools_NotEmpty()
    {
        Assert.NotEmpty(McpGovernanceDefaults.SensitiveTools);
        Assert.Contains("send_email", McpGovernanceDefaults.SensitiveTools);
        Assert.Contains("deploy_production", McpGovernanceDefaults.SensitiveTools);
        Assert.Contains("write_file", McpGovernanceDefaults.SensitiveTools);
    }

    [Fact]
    public void McpGovernanceDefaults_CanBeUsedWithOptions()
    {
        var stack = McpGovernanceExtensions.AddMcpGovernance(
            mcpOptions: new McpGovernanceOptions
            {
                DeniedTools = McpGovernanceDefaults.DeniedTools.ToList(),
                SensitiveTools = McpGovernanceDefaults.SensitiveTools.ToList()
            });

        // Denied tool blocked
        var (allowed, _) = stack.Gateway.InterceptToolCall("did:mesh:a1", "rm_rf", new());
        Assert.False(allowed);

        // Non-denied, non-sensitive tool allowed
        var (allowed2, _) = stack.Gateway.InterceptToolCall("did:mesh:a1", "file_read", new());
        Assert.True(allowed2);
    }

    [Fact]
    public void McpGovernanceDefaults_NoOverlapBetweenLists()
    {
        var overlap = McpGovernanceDefaults.DeniedTools
            .Intersect(McpGovernanceDefaults.SensitiveTools)
            .ToList();
        Assert.Empty(overlap);
    }

    private sealed class TrackingSessionStore : IMcpSessionStore
    {
        private readonly InMemoryMcpSessionStore _inner = new();

        public int GetCalls { get; private set; }

        public int SetCalls { get; private set; }

        public int DeleteCalls { get; private set; }

        public Task<McpSession?> GetAsync(string sessionToken, CancellationToken cancellationToken = default)
        {
            GetCalls++;
            return _inner.GetAsync(sessionToken, cancellationToken);
        }

        public Task SetAsync(string sessionToken, McpSession session, CancellationToken cancellationToken = default)
        {
            SetCalls++;
            return _inner.SetAsync(sessionToken, session, cancellationToken);
        }

        public Task<bool> DeleteAsync(string sessionToken, CancellationToken cancellationToken = default)
        {
            DeleteCalls++;
            return _inner.DeleteAsync(sessionToken, cancellationToken);
        }
    }

    private sealed class TrackingNonceStore : IMcpNonceStore
    {
        private readonly InMemoryMcpNonceStore _inner = new();

        public int ContainsCalls { get; private set; }

        public int AddCalls { get; private set; }

        public int CleanupCalls { get; private set; }

        public Task<bool> ContainsAsync(string nonce, CancellationToken cancellationToken = default)
        {
            ContainsCalls++;
            return _inner.ContainsAsync(nonce, cancellationToken);
        }

        public Task<bool> AddAsync(string nonce, DateTimeOffset observedAt, CancellationToken cancellationToken = default)
        {
            AddCalls++;
            return _inner.AddAsync(nonce, observedAt, cancellationToken);
        }

        public Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
        {
            CleanupCalls++;
            return _inner.CleanupAsync(cutoff, cancellationToken);
        }
    }

    private sealed class TrackingRateLimitStore : IMcpRateLimitStore
    {
        private readonly InMemoryMcpRateLimitStore _inner = new();

        public int GetCalls { get; private set; }

        public int SetCalls { get; private set; }

        public Task<McpRateLimitBucket?> GetBucketAsync(string agentId, CancellationToken cancellationToken = default)
        {
            GetCalls++;
            return _inner.GetBucketAsync(agentId, cancellationToken);
        }

        public Task SetBucketAsync(string agentId, McpRateLimitBucket bucket, CancellationToken cancellationToken = default)
        {
            SetCalls++;
            return _inner.SetBucketAsync(agentId, bucket, cancellationToken);
        }
    }

    private sealed class TrackingAuditSink : IMcpAuditSink
    {
        public List<McpAuditEntry> Entries { get; } = new();

        public Task RecordAsync(McpAuditEntry entry, CancellationToken cancellationToken = default)
        {
            Entries.Add(entry);
            return Task.CompletedTask;
        }
    }
}
