// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using Xunit;

namespace AgentGovernance.Tests;

public class McpGatewayTests
{
    private static GovernanceKernel CreateKernel(string? yaml = null)
    {
        var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableAudit = true
        });

        if (yaml is not null)
        {
            kernel.LoadPolicyFromYaml(yaml);
        }

        return kernel;
    }

    private static McpGateway CreateGateway(
        GovernanceKernel? kernel = null,
        IEnumerable<string>? deniedTools = null,
        IEnumerable<string>? allowedTools = null,
        IEnumerable<string>? sensitiveTools = null,
        Func<string, string, Dictionary<string, object>, ApprovalStatus>? approvalCallback = null,
        bool requireHumanApproval = false,
        int maxCalls = 1000,
        bool enableCredentialRedaction = true,
        TimeProvider? timeProvider = null)
    {
        return new McpGateway(
            kernel ?? CreateKernel(),
            deniedTools: deniedTools,
            allowedTools: allowedTools,
            sensitiveTools: sensitiveTools,
            approvalCallback: approvalCallback,
            requireHumanApproval: requireHumanApproval,
            enableCredentialRedaction: enableCredentialRedaction,
            auditSink: new InMemoryMcpAuditSink(),
            timeProvider: timeProvider)
        {
            MaxToolCallsPerAgent = maxCalls,
            RateLimiter = maxCalls > 0
                ? new McpSlidingRateLimiter
                {
                    MaxCallsPerWindow = maxCalls,
                    WindowSize = TimeSpan.FromMinutes(5)
                }
                : null
        };
    }

    // ── Stage 1: Deny-list ───────────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_DeniedTool_Blocked()
    {
        var gateway = CreateGateway(deniedTools: new[] { "rm_rf", "drop_table" });

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "rm_rf", new());

        Assert.False(allowed);
        Assert.Contains("deny list", reason);
    }

    [Fact]
    public void InterceptToolCall_DenyList_CaseInsensitive()
    {
        var gateway = CreateGateway(deniedTools: new[] { "dangerous_tool" });

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "DANGEROUS_TOOL", new());

        Assert.False(allowed);
    }

    // ── Stage 2: Allow-list ──────────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_NotOnAllowList_Blocked()
    {
        var gateway = CreateGateway(allowedTools: new[] { "safe_tool" });

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "other_tool", new());

        Assert.False(allowed);
        Assert.Contains("allow list", reason);
    }

    [Fact]
    public void InterceptToolCall_OnAllowList_Allowed()
    {
        var gateway = CreateGateway(allowedTools: new[] { "safe_tool" });

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "safe_tool", new());

        Assert.True(allowed);
    }

    [Fact]
    public void InterceptToolCall_EmptyAllowList_AllToolsAllowed()
    {
        var gateway = CreateGateway(); // No allow-list

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "anything", new());

        Assert.True(allowed);
    }

    // ── Stage 3: Parameter sanitization ──────────────────────────────────

    [Fact]
    public void InterceptToolCall_SsnInParams_Blocked()
    {
        var gateway = CreateGateway();
        var args = new Dictionary<string, object> { ["data"] = "My SSN is 123-45-6789" };

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "send_data", args);

        Assert.False(allowed);
        Assert.Contains("SSN", reason);
    }

    [Fact]
    public void InterceptToolCall_CreditCardInParams_Blocked()
    {
        var gateway = CreateGateway();
        var args = new Dictionary<string, object> { ["card"] = "4111-1111-1111-1111" };

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "pay", args);

        Assert.False(allowed);
        Assert.Contains("Credit card", reason);
    }

    [Fact]
    public void InterceptToolCall_ShellInjectionInParams_Blocked()
    {
        var gateway = CreateGateway();
        var args = new Dictionary<string, object> { ["cmd"] = "ls; rm -rf /" };

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "exec", args);

        Assert.False(allowed);
        Assert.Contains("Shell destructive", reason);
    }

    [Fact]
    public void InterceptToolCall_CommandSubstitutionInParams_Blocked()
    {
        var gateway = CreateGateway();
        var args = new Dictionary<string, object> { ["input"] = "$(cat /etc/passwd)" };

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "tool", args);

        Assert.False(allowed);
        Assert.Contains("Command substitution", reason);
    }

    [Fact]
    public void InterceptToolCall_CleanParams_Allowed()
    {
        var gateway = CreateGateway();
        var args = new Dictionary<string, object> { ["query"] = "SELECT name FROM users" };

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "db_query", args);

        Assert.True(allowed);
    }

    // ── Stage 4: Rate limiting (budget) ──────────────────────────────────

    [Fact]
    public void InterceptToolCall_ExceedsBudget_Blocked()
    {
        var gateway = CreateGateway(maxCalls: 3);

        for (int i = 0; i < 3; i++)
        {
            var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "tool", new());
            Assert.True(allowed);
        }

        var (blockedAllowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "tool", new());
        Assert.False(blockedAllowed);
        Assert.Contains("exceeded call budget", reason);
    }

    [Fact]
    public void InterceptToolCall_DifferentAgents_IndependentBudgets()
    {
        var gateway = CreateGateway(maxCalls: 1);

        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.False(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);

        // Different agent still has budget
        Assert.True(gateway.InterceptToolCall("did:mesh:a2", "tool", new()).Allowed);
    }

    [Fact]
    public void GetAgentCallCount_ReturnsAccurateCount()
    {
        var gateway = CreateGateway();
        gateway.InterceptToolCall("did:mesh:a1", "tool", new());
        gateway.InterceptToolCall("did:mesh:a1", "tool", new());

        Assert.Equal(2, gateway.GetAgentCallCount("did:mesh:a1"));
        Assert.Equal(0, gateway.GetAgentCallCount("did:mesh:unknown"));
    }

    [Fact]
    public void ResetAgentBudget_RestoresCallCapacity()
    {
        var gateway = CreateGateway(maxCalls: 1);

        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.False(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);

        gateway.ResetAgentBudget("did:mesh:a1");
        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
    }

    [Fact]
    public void ResetAllBudgets_RestoresAllAgents()
    {
        var gateway = CreateGateway(maxCalls: 1);

        gateway.InterceptToolCall("did:mesh:a1", "tool", new());
        gateway.InterceptToolCall("did:mesh:a2", "tool", new());

        gateway.ResetAllBudgets();

        Assert.True(gateway.InterceptToolCall("did:mesh:a1", "tool", new()).Allowed);
        Assert.True(gateway.InterceptToolCall("did:mesh:a2", "tool", new()).Allowed);
    }

    // ── Stage 5: Human approval ──────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_SensitiveTool_NoCallback_Pending()
    {
        var gateway = CreateGateway(sensitiveTools: new[] { "deploy" });

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "deploy", new());

        Assert.False(allowed);
        Assert.Contains("Awaiting human approval", reason);
    }

    [Fact]
    public void InterceptToolCall_SensitiveTool_Approved()
    {
        var gateway = CreateGateway(
            sensitiveTools: new[] { "deploy" },
            approvalCallback: (_, _, _) => ApprovalStatus.Approved);

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "deploy", new());

        Assert.True(allowed);
        Assert.Contains("Approved by human", reason);
    }

    [Fact]
    public void InterceptToolCall_SensitiveTool_Denied()
    {
        var gateway = CreateGateway(
            sensitiveTools: new[] { "deploy" },
            approvalCallback: (_, _, _) => ApprovalStatus.Denied);

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "deploy", new());

        Assert.False(allowed);
        Assert.Contains("denied", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InterceptToolCall_RequireAllApproval_AppliesToAllTools()
    {
        var gateway = CreateGateway(
            requireHumanApproval: true,
            approvalCallback: (_, _, _) => ApprovalStatus.Approved);

        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "any_tool", new());

        Assert.True(allowed);
    }

    [Fact]
    public void InterceptToolCall_ApprovalCallbackThrows_FailClosed()
    {
        var gateway = CreateGateway(
            sensitiveTools: new[] { "deploy" },
            approvalCallback: (_, _, _) => throw new Exception("callback error"));

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "deploy", new());

        Assert.False(allowed);
        Assert.Contains("fail-closed", reason);
    }

    // ── Fail-closed behavior ─────────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_NullArgs_DoesNotThrow()
    {
        var gateway = CreateGateway();
        var (allowed, _) = gateway.InterceptToolCall("did:mesh:a1", "tool", null!);
        Assert.True(allowed);
    }

    // ── Audit log ────────────────────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_RecordsAuditEntry()
    {
        var gateway = CreateGateway();
        gateway.InterceptToolCall("did:mesh:a1", "read_file", new());

        Assert.Single(gateway.AuditLog);
        Assert.Equal("did:mesh:a1", gateway.AuditLog[0].AgentId);
        Assert.Equal("read_file", gateway.AuditLog[0].ToolName);
        Assert.True(gateway.AuditLog[0].Allowed);
    }

    [Fact]
    public void InterceptToolCall_BlockedCall_AuditShowsDenied()
    {
        var gateway = CreateGateway(deniedTools: new[] { "evil" });
        gateway.InterceptToolCall("did:mesh:a1", "evil", new());

        Assert.Single(gateway.AuditLog);
        Assert.False(gateway.AuditLog[0].Allowed);
    }

    [Fact]
    public void InterceptToolCall_AuditParametersAreRedactedByDefault()
    {
        var gateway = CreateGateway();
        gateway.InterceptToolCall("did:mesh:a1", "read_file", new Dictionary<string, object>
        {
            ["apiKey"] = "sk-live_abc123def456ghi789"
        });

        Assert.Single(gateway.AuditLog);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, gateway.AuditLog[0].Parameters["apiKey"].ToString());
    }

    [Fact]
    public void InterceptToolCall_UsesInjectedTimeProviderForAuditTimestamp()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T12:00:00Z"));
        var gateway = CreateGateway(timeProvider: timeProvider);

        gateway.InterceptToolCall("did:mesh:a1", "read_file", new());

        Assert.Single(gateway.AuditLog);
        Assert.Equal(timeProvider.GetUtcNow(), gateway.AuditLog[0].Timestamp);
    }

    // ── Policy integration ───────────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_PolicyDenies_Blocked()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: deny-writes
default_action: deny
rules: []
";
        var kernel = CreateKernel(yaml);
        var gateway = new McpGateway(kernel);

        var (allowed, reason) = gateway.InterceptToolCall("did:mesh:a1", "file_write", new());

        Assert.False(allowed);
    }

    // ── Argument validation ──────────────────────────────────────────────

    [Fact]
    public void InterceptToolCall_EmptyAgentId_Throws()
    {
        var gateway = CreateGateway();
        Assert.ThrowsAny<ArgumentException>(() =>
            gateway.InterceptToolCall("", "tool", new()));
    }

    [Fact]
    public void InterceptToolCall_EmptyToolName_Throws()
    {
        var gateway = CreateGateway();
        Assert.ThrowsAny<ArgumentException>(() =>
            gateway.InterceptToolCall("did:mesh:a1", "", new()));
    }
}
